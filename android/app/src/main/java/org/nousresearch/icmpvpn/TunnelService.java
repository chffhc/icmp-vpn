package org.nousresearch.icmpvpn;

import android.app.*;
import android.content.Intent;
import android.net.*;
import android.os.*;
import android.system.*;
import java.io.FileDescriptor;
import java.net.InetAddress;
import java.security.GeneralSecurityException;
import java.util.ArrayDeque;
import java.util.Arrays;

/** One bounded nonblocking I/O worker; only its ping socket is exempt from the VPN. */
public final class TunnelService extends VpnService {
    public static final String START="org.nousresearch.icmpvpn.START", STOP="org.nousresearch.icmpvpn.STOP";
    static final String LEASE="profile_launch_lease";
    public static volatile String status="Stopped. Enable Android VPN lockdown to prevent direct fallback.";
    private static final int NOTIFICATION=1, QUEUE_LIMIT=256;
    private final Handler main=new Handler(Looper.getMainLooper());
    private volatile boolean running;
    private volatile boolean networkLost;
    private static final class TunnelHandle { ParcelFileDescriptor tun; }
    private volatile String stopReason="Stopped by user";
    private static final class TunnelFailure extends Exception {
        TunnelFailure(String safeMessage) { super(safeMessage); }
    }
    private Thread worker;
    private ConnectivityManager connectivity;
    private ConnectivityManager.NetworkCallback networkCallback;

    @Override public int onStartCommand(Intent intent,int flags,int startId) {
        if(intent!=null && STOP.equals(intent.getAction())) {
            requestStop("Stopped by user");
            if(worker==null) { SessionGate.finished();stopSelf(); }
            return START_NOT_STICKY;
        }
        if(worker!=null) return START_NOT_STICKY;
        if(intent!=null && intent.getAction()!=null && !START.equals(intent.getAction()) && !VpnService.SERVICE_INTERFACE.equals(intent.getAction())) { stopSelf();return START_NOT_STICKY; }
        Profile snapshot;
        try {
            synchronized(SessionGate.class) {
                String lease=intent==null?null:intent.getStringExtra(LEASE);
                if(lease==null) {
                    // System/compatibility starts freeze selection once, just like UI starts.
                    if(SessionGate.busy()) return START_NOT_STICKY;
                    lease=ProfileStore.reserveSelected(this);SessionGate.launch(lease);
                }
                snapshot=SessionGate.accept(lease);
            }
            if(snapshot==null) { stopSelf();return START_NOT_STICKY; }
        } catch(Exception invalid) {
            status="Configuration/Keystore unavailable. Existing profiles were not reset.";
            stopSelf();return START_NOT_STICKY;
        }
        try { notification("Connecting — IPv4 only; IPv6 blocked"); }
        catch(RuntimeException denied) {
            status="Foreground VPN start denied. Grant VPN consent and start from the app. Direct fallback is possible; enable Android VPN lockdown.";
            SessionGate.finished();stopSelf();return START_NOT_STICKY;
        }
        running=true;stopReason="Stopped by user";
        status="Starting VPN — "+snapshot.name+" / "+snapshot.server;
        worker=new Thread(() -> runTunnel(snapshot),"icmp-vpn-io");worker.start();return START_NOT_STICKY;
    }
    private void notification(String message) {
        NotificationManager nm=getSystemService(NotificationManager.class);
        nm.createNotificationChannel(new NotificationChannel("vpn","ICMP VPN",NotificationManager.IMPORTANCE_LOW));
        PendingIntent open=PendingIntent.getActivity(this,0,new Intent(this,MainActivity.class),PendingIntent.FLAG_IMMUTABLE|PendingIntent.FLAG_UPDATE_CURRENT);
        PendingIntent stop=PendingIntent.getService(this,1,new Intent(this,TunnelService.class).setAction(STOP),PendingIntent.FLAG_IMMUTABLE|PendingIntent.FLAG_UPDATE_CURRENT);
        Notification n=new Notification.Builder(this,"vpn").setContentTitle("ICMP VPN").setContentText(message)
            .setSmallIcon(android.R.drawable.stat_sys_warning).setContentIntent(open).setOngoing(true)
            .addAction(new Notification.Action.Builder(null,"Stop",stop).build()).build();
        if(Build.VERSION.SDK_INT>=34) startForeground(NOTIFICATION,n,android.content.pm.ServiceInfo.FOREGROUND_SERVICE_TYPE_SYSTEM_EXEMPTED);
        else startForeground(NOTIFICATION,n);
    }
    private void requestStop(String reason) { if(running) stopReason=reason;running=false;if(worker!=null) SessionGate.stopping(); }
    @Override public void onRevoke() { requestStop("VPN consent revoked");super.onRevoke(); }
    @Override public void onDestroy() { requestStop("Service destroyed");super.onDestroy(); }
    private Network physicalNetwork() throws Exception {
        connectivity=getSystemService(ConnectivityManager.class);
        Network active=connectivity.getActiveNetwork();
        if(isPhysical(active)) return active;
        for(Network n:connectivity.getAllNetworks()) if(isPhysical(n)) return n;
        throw new TunnelFailure("No underlying Internet network");
    }
    private boolean isPhysical(Network n) {
        NetworkCapabilities c=n==null?null:connectivity.getNetworkCapabilities(n);
        return c!=null && c.hasCapability(NetworkCapabilities.NET_CAPABILITY_INTERNET) && c.hasCapability(NetworkCapabilities.NET_CAPABILITY_NOT_VPN);
    }
    private void watch(Network selected) {
        networkCallback=new ConnectivityManager.NetworkCallback() {
            @Override public void onLost(Network network) { if(networkCallback==this && selected.equals(network)) networkLost=true; }
        };
        connectivity.registerNetworkCallback(new NetworkRequest.Builder().addCapability(NetworkCapabilities.NET_CAPABILITY_INTERNET)
            .addCapability(NetworkCapabilities.NET_CAPABILITY_NOT_VPN).build(),networkCallback,main);
    }
    private static boolean wouldBlock(ErrnoException e) { return e.errno==OsConstants.EAGAIN || e.errno==OsConstants.EINTR; }
    private void runTunnel(Profile snapshot) {
        TunnelHandle handle=new TunnelHandle();
        RetryPolicy retries=new RetryPolicy();
        try {
            while(running) {
                boolean retry=runAttempt(handle,retries,snapshot);
                if(!running || !retry) break;
                long delay=retries.nextDelay();
                status="Reconnecting in "+(delay/1000)+" s. Existing VPN capture retained; traffic is not forwarded until authentication.";
                long until=SystemClock.elapsedRealtime()+delay;
                while(running && SystemClock.elapsedRealtime()<until) {
                    // Drain/drop captured packets during backoff so stale application traffic
                    // is not replayed in a new session. Keep TUN open, IPv6 blocked as before.
                    if(handle.tun!=null) {
                        byte[] drain=new byte[65536];
                        for(int i=0;i<32;i++) try { if(Os.read(handle.tun.getFileDescriptor(),drain,0,drain.length)<=0) break; }
                        catch(Exception ignored) { break; }
                    }
                    try { Thread.sleep(100); } catch(InterruptedException ignored) { }
                }
            }
        } finally {
            running=false;
            if(handle.tun!=null) try { handle.tun.close(); } catch(Exception ignored) { }
            status += "\nVPN stopped. Use Android lockdown to prevent direct fallback after stop/process death.";
            main.post(() -> { worker=null;stopForeground(STOP_FOREGROUND_REMOVE);SessionGate.finished();stopSelf(); });
        }
    }
    private boolean runAttempt(TunnelHandle handle,RetryPolicy retries,Profile snapshot) {
        FileDescriptor socket=null;ParcelFileDescriptor tun=handle.tun;
        Protocol.Sequence sequence=new Protocol.Sequence();
        long session=0;int echoSequence=0;
        boolean retry=false;
        networkLost=false;
        byte[] psk=null,txKey=null,rxKey=null;
        long sent=0,received=0,up=0,down=0,rejected=0,ipv6=0,dropped=0;
        String outcome=null,stage="configuration";
        ArrayDeque<byte[]> outgoing=new ArrayDeque<>(QUEUE_LIMIT);
        try {
            InetAddress server=Config.ipv4(snapshot.server);
            String dns=snapshot.dns;Config.ipv4(dns);
            stage="keystore";psk=KeyStoreConfig.decrypt(snapshot);session=Protocol.freshSession();txKey=Protocol.derive(psk,0,session);rxKey=Protocol.derive(psk,1,session);
            Arrays.fill(psk,(byte)0);psk=null;
            stage="underlying network";Network network=physicalNetwork();watch(network);
            // Linux SOCK_NONBLOCK equals O_NONBLOCK. The former Android field is public only from API 29;
            // O_NONBLOCK is public on all supported APIs and avoids reflection/hidden fcntl APIs.
            stage="ping socket";socket=Os.socket(OsConstants.AF_INET,OsConstants.SOCK_DGRAM|OsConstants.O_NONBLOCK,OsConstants.IPPROTO_ICMP);
            // protect(int) works with a duplicate of the same socket; never use hidden FD APIs.
            try(ParcelFileDescriptor duplicate=ParcelFileDescriptor.dup(socket)) {
                if(!protect(duplicate.getFd())) throw new TunnelFailure("VPN socket protection failed");
            }
            stage="socket binding";network.bindSocket(socket);
            // API 26-28 use nonblocking sockets + bounded poll; timeval became public in API 29.
            if(Build.VERSION.SDK_INT>=29) {
                Os.setsockoptTimeval(socket,OsConstants.SOL_SOCKET,OsConstants.SO_RCVTIMEO,StructTimeval.fromMillis(1000));
                Os.setsockoptTimeval(socket,OsConstants.SOL_SOCKET,OsConstants.SO_SNDTIMEO,StructTimeval.fromMillis(1000));
            }
            // High-BDP replies arrive in bursts; buffer remains bounded. Kernel echo replies
            // are ignored, never counted as authenticated tunnel progress.
            try { Os.setsockoptInt(socket,OsConstants.SOL_SOCKET,OsConstants.SO_RCVBUF,1<<20); } catch(ErrnoException ignored) { }
            stage="socket connect";Os.connect(socket,server,0);
            if(!running) throw new TunnelFailure("Start cancelled");
            // Linux refuses an IPv6 TUN address below MTU 1280. Protocol IPv4 remains capped at 1200;
            // local ICMP fragmentation-needed feedback handles oversized IPv4 without fragmentation.
            // Capture before HELLO; no server data reaches TUN before authenticated configuration.
            stage="TUN establishment";
            if(tun==null) tun=new Builder().setSession("ICMP IPv4 VPN").setMtu(1280)
                .addAddress("10.77.0.2",32).addRoute("0.0.0.0",0).addDnsServer(dns)
                .addAddress("fd77:77::2",128).addRoute("::",0)
                .setUnderlyingNetworks(new Network[]{network}).setBlocking(false).establish();
            if(tun==null) throw new TunnelFailure("VPN consent missing");
            handle.tun=tun;
            setUnderlyingNetworks(new Network[]{network});
            stage="tunnel I/O";FileDescriptor tunFd=tun.getFileDescriptor();
            StructPollfd outer=new StructPollfd();outer.fd=socket;outer.events=(short)OsConstants.POLLIN;
            StructPollfd inner=new StructPollfd();inner.fd=tunFd;inner.events=(short)OsConstants.POLLIN;
            StructPollfd[] polls={outer,inner};
            Protocol.Replay replay=new Protocol.Replay();
            byte[] socketBuffer=new byte[2048],tunBuffer=new byte[65536];
            boolean connected=false;long began=SystemClock.elapsedRealtime(),lastAuth=began,nextSend=began,nextStats=began,nextReap=began;
            FlowControl flow=new FlowControl();long sendBlockedUntil=0;
            while(running) {
                long now=SystemClock.elapsedRealtime();
                if(networkLost) throw new TunnelFailure("Underlying network lost");
                if(retries.timedOut(connected,now,began,lastAuth)) throw new TunnelFailure(connected?"Authenticated tunnel response timeout":"Authenticated HELLO timeout (ICMP filtered or key mismatch)");
                // Before HELLO: one request per 20 ms. After: adaptive window of outstanding
                // requests (FlowControl), because each reply returns at most one packet.
                // Bounded per iteration so reads are never starved.
                for(int burst=0;burst<16 && now>=sendBlockedUntil;burst++) {
                    if(connected?!flow.shouldSend(now,!outgoing.isEmpty()):now<nextSend) break;
                    byte[] packet=connected?outgoing.pollFirst():null;
                    int kind=connected?(packet==null?Protocol.POLL:Protocol.IP):Protocol.HELLO;
                    int echoSeq=++echoSequence&65535;
                    byte[] wire=Protocol.echo(Protocol.encode(txKey,session,sequence.take(),kind,packet==null?new byte[0]:packet),echoSeq);
                    try { int n=Os.write(socket,wire,0,wire.length);if(n!=wire.length) throw new TunnelFailure("Short ICMP datagram");sent++;if(packet!=null) up++;flow.onSent(echoSeq,now); }
                    // Full socket buffer: back off 2 ms instead of spinning on a sendable window.
                    catch(ErrnoException e) { if(wouldBlock(e)) { dropped++;sendBlockedUntil=now+2;break; } else throw e; }
                    nextSend=now+100; // HELLO retry is 10 pps, not bulk traffic.
                }
                if(connected && now>=nextReap) { flow.reap(now);nextReap=now+50; }
                int timeout=connected?flow.pollTimeout(SystemClock.elapsedRealtime(),!outgoing.isEmpty())
                    :(int)Math.max(0,Math.min(20,nextSend-SystemClock.elapsedRealtime()));
                if(sendBlockedUntil>now) timeout=Math.max(timeout,(int)Math.min(2,sendBlockedUntil-now));
                try { Os.poll(polls,timeout); } catch(ErrnoException e) { if(wouldBlock(e)) continue;throw e; }
                if((outer.revents&(OsConstants.POLLERR|OsConstants.POLLHUP|OsConstants.POLLNVAL))!=0 || (inner.revents&(OsConstants.POLLERR|OsConstants.POLLHUP|OsConstants.POLLNVAL))!=0) throw new TunnelFailure("Socket/TUN poll failure");
                if((outer.revents&OsConstants.POLLIN)!=0) {
                    for(int i=0;i<32;i++) {
                        int n;try { n=Os.read(socket,socketBuffer,0,socketBuffer.length); } catch(ErrnoException e) { if(wouldBlock(e)) break;throw e; }
                        int replySeq=n>=8?((socketBuffer[6]&255)<<8)|(socketBuffer[7]&255):-1; // server mirrors request echo sequence
                        Protocol.Frame frame;
                        try { frame=Protocol.decode(rxKey,session,1,Protocol.replyPayload(socketBuffer,n),replay,!connected); }
                        catch(GeneralSecurityException e) { rejected++;continue; }
                        received++;lastAuth=SystemClock.elapsedRealtime();retries.authenticated();
                        if(replySeq>=0) flow.onReply(replySeq,frame.kind==Protocol.IP,lastAuth); // authenticated replies only
                        if(frame.kind==Protocol.CLOSE) throw new TunnelFailure("Server closed session");
                        if(!connected) {
                            if(frame.kind!=Protocol.HELLO) { rejected++;continue; }
                            connected=true;main.post(() -> { if(running) notification("Connected — IPv4 tunneled; IPv6 blocked"); });
                        }
                        if(frame.kind==Protocol.IP) {
                            byte[] delivered=MtuFeedback.clampTcpMss(frame.plain);
                            try { int written=Os.write(tunFd,delivered,0,delivered.length);if(written!=frame.plain.length) throw new TunnelFailure("Short TUN write");down++; }
                            catch(ErrnoException e) { if(wouldBlock(e)) dropped++;else throw e; }
                        }
                    }
                }
                if((inner.revents&OsConstants.POLLIN)!=0) {
                    for(int i=0;i<32;i++) {
                        int n;try { n=Os.read(tunFd,tunBuffer,0,tunBuffer.length); } catch(ErrnoException e) { if(wouldBlock(e)) break;throw e; }
                        if(n<=0) throw new TunnelFailure("TUN closed");
                        if((tunBuffer[0]&240)==96) { ipv6++;continue; }
                        byte[] packet=Arrays.copyOf(tunBuffer,n);
                        byte[] feedback=MtuFeedback.forOversize(packet);
                        if(feedback!=null) {
                            try { Os.write(tunFd,feedback,0,feedback.length); } catch(ErrnoException e) { if(!wouldBlock(e)) throw e; }
                            dropped++;continue;
                        }
                        if(!connected || !Protocol.validIpv4(packet,true)) { dropped++;continue; }
                        if(outgoing.size()>=QUEUE_LIMIT) { outgoing.removeFirst();dropped++; }
                        outgoing.addLast(MtuFeedback.clampTcpMss(packet));
                    }
                }
                now=SystemClock.elapsedRealtime();
                if(now>=nextStats) {
                    status=(connected?"Connected (authenticated)":"Connecting (awaiting authenticated HELLO)")+"\nEcho tx/rx "+sent+"/"+received+"; IPv4 up/down "+up+"/"+down+"\nInterface MTU 1280 / wire IPv4 ceiling 1200; rejected "+rejected+"; IPv6 blocked "+ipv6+"; dropped "+dropped+"; queue "+outgoing.size()
                        +"\nWindow "+flow.window()+", in flight "+flow.inflight()+", RTT "+flow.srtt()+" ms, lost "+flow.lost();nextStats=now+500;
                }
            }
            outcome=stopReason;
        } catch(Exception e) {
            // Never log keys, plaintext packets, configuration exception payloads or stack traces.
            outcome=running?"Tunnel failed at "+stage+": "+(e instanceof TunnelFailure?e.getMessage():e.getClass().getSimpleName())+(stage.equals("TUN establishment") && e instanceof IllegalArgumentException?" ("+e.getMessage()+")":"")+ (e instanceof ErrnoException?" errno="+((ErrnoException)e).errno:"")+". Check ICMP availability, key, and network.":stopReason;
            retry=running && !(stage.equals("configuration") || stage.equals("keystore") || stage.equals("TUN establishment"));
        } finally {
            outgoing.clear();
            // Fresh SID and direction keys on every attempt. Try to retire the old server
            // slot; if CLOSE is lost, server's 120s idle expiry applies (no takeover/ledger reset).
            if(socket!=null && txKey!=null) try {
                byte[] close=Protocol.echo(Protocol.encode(txKey,session,sequence.take(),Protocol.CLOSE,new byte[0]),++echoSequence);
                Os.write(socket,close,0,close.length);
            } catch(Exception ignored) { }
            if(socket!=null) try { Os.close(socket); } catch(Exception ignored) { }
            if(psk!=null) Arrays.fill(psk,(byte)0);if(txKey!=null) Arrays.fill(txKey,(byte)0);if(rxKey!=null) Arrays.fill(rxKey,(byte)0);
            if(networkCallback!=null) { try { connectivity.unregisterNetworkCallback(networkCallback); } catch(Exception ignored) { } networkCallback=null; }
            status=(outcome==null?"Tunnel stopped":outcome)+"\nFinal echo tx/rx "+sent+"/"+received+", IPv4 up/down "+up+"/"+down+", rejected "+rejected+", IPv6 blocked "+ipv6+", dropped "+dropped+"\nDirect fallback is possible. Enable Always-on VPN + Block connections without VPN for fail-closed behavior.";
        }
        return retry;
    }
}
