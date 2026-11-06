package org.nousresearch.icmpvpn;

import android.test.InstrumentationTestCase;
import android.content.Context;
import android.content.Intent;
import android.net.VpnService;
import android.os.SystemClock;
import android.app.NotificationManager;
import java.net.DatagramPacket;
import java.net.DatagramSocket;
import java.net.InetAddress;
import java.util.Arrays;

/** Requires consent pre-granted ONLY on the disposable test emulator. No authenticated server. */
@SuppressWarnings("deprecation")
public final class VpnServiceSmokeTest extends InstrumentationTestCase {
    private void awaitStopped() {
        long until=SystemClock.elapsedRealtime()+4000;
        while(SessionGate.busy() && SystemClock.elapsedRealtime()<until) SystemClock.sleep(20);
        assertFalse("VPN must stop before clearing configuration",SessionGate.busy());
    }
    public void testUnauthenticatedHelloTimeoutRetainsVpnAndRetries() throws Exception {
        Context c=getInstrumentation().getTargetContext();assertNull("Pre-grant emulator VPN consent",VpnService.prepare(c));
        byte[] key=new byte[32];new java.security.SecureRandom().nextBytes(key);
        try {
            KeyStoreConfig.save(c,"10.0.2.2","1.1.1.1",key);
            c.startActivity(new Intent(c,MainActivity.class).addFlags(Intent.FLAG_ACTIVITY_NEW_TASK));
            c.startForegroundService(new Intent(c,TunnelService.class).setAction(TunnelService.START));
            long until=SystemClock.elapsedRealtime()+3000;
            while(!TunnelService.status.startsWith("Connecting (awaiting") && SystemClock.elapsedRealtime()<until) SystemClock.sleep(20);
            assertTrue(TunnelService.status,TunnelService.status.startsWith("Connecting (awaiting"));
            until=SystemClock.elapsedRealtime()+23000;
            while(!TunnelService.status.startsWith("Reconnecting") && SystemClock.elapsedRealtime()<until) {
                assertFalse("Must not trust normal echo replies",TunnelService.status.startsWith("Connected"));SystemClock.sleep(20);
            }
            assertTrue(TunnelService.status,TunnelService.status.startsWith("Reconnecting"));
            assertTrue("Foreground must survive retry",c.getSystemService(NotificationManager.class).getActiveNotifications().length>0);
            android.net.ConnectivityManager cm=c.getSystemService(android.net.ConnectivityManager.class);
            android.net.NetworkCapabilities caps=cm.getNetworkCapabilities(cm.getActiveNetwork());
            assertNotNull(caps);assertTrue("TUN must not close during retry",caps.hasTransport(android.net.NetworkCapabilities.TRANSPORT_VPN));
            // A captured datagram must not reach direct fallback while reconnecting.
            try(DatagramSocket udp=new DatagramSocket()) {
                udp.setSoTimeout(300);byte[] m=new byte[]{1};
                udp.send(new DatagramPacket(m,m.length,InetAddress.getByAddress(new byte[]{(byte)192,0,2,2}),5353));
            }
            until=SystemClock.elapsedRealtime()+4000;
            while(!TunnelService.status.startsWith("Connecting (awaiting") && SystemClock.elapsedRealtime()<until) SystemClock.sleep(20);
            assertTrue("Automatic second attempt missing: "+TunnelService.status,TunnelService.status.startsWith("Connecting (awaiting"));
        } finally {
            c.startService(new Intent(c,TunnelService.class).setAction(TunnelService.STOP));awaitStopped();Arrays.fill(key,(byte)0);KeyStoreConfig.prefs(c).edit().clear().commit();
        }
    }
    public void testConsentedForegroundTunCaptureAndStop() throws Exception {
        Context c=getInstrumentation().getTargetContext();
        assertNull("Grant emulator ACTIVATE_VPN app-op before this consented smoke test",VpnService.prepare(c));
        byte[] key=new byte[32];new java.security.SecureRandom().nextBytes(key);
        try {
            KeyStoreConfig.save(c,"10.0.2.2","1.1.1.1",key);
            Intent ui=new Intent(c,MainActivity.class).addFlags(Intent.FLAG_ACTIVITY_NEW_TASK);
            c.startActivity(ui);
            c.startForegroundService(new Intent(c,TunnelService.class).setAction(TunnelService.START));
            long until=SystemClock.elapsedRealtime()+4000;
            while(!TunnelService.status.startsWith("Connecting (awaiting") && SystemClock.elapsedRealtime()<until) SystemClock.sleep(20);
            assertTrue(TunnelService.status,TunnelService.status.startsWith("Connecting (awaiting"));
            assertTrue("Foreground notification missing",c.getSystemService(NotificationManager.class).getActiveNotifications().length>0);
            // Own app traffic must enter TUN too: we do not exclude this application's UID.
            try(DatagramSocket udp=new DatagramSocket()) {
                byte[] message=new byte[]{1,2,3};udp.send(new DatagramPacket(message,message.length,InetAddress.getByAddress(new byte[]{(byte)192,0,2,2}),5353));
            }
            until=SystemClock.elapsedRealtime()+1500;
            while(TunnelService.status.contains("dropped 0;") && SystemClock.elapsedRealtime()<until) SystemClock.sleep(20);
            assertTrue(TunnelService.status,TunnelService.status.startsWith("Connecting (awaiting"));
            assertFalse(TunnelService.status,TunnelService.status.contains("dropped 0;"));
            assertFalse("Never announce connected from unencrypted kernel echoes",TunnelService.status.startsWith("Connected"));
            try(DatagramSocket udp6=new DatagramSocket()) {
                byte[] message=new byte[]{4,5,6};udp6.send(new DatagramPacket(message,message.length,InetAddress.getByName("2001:db8::1"),5353));
            }
            until=SystemClock.elapsedRealtime()+1000;
            while(TunnelService.status.contains("IPv6 blocked 0;") && SystemClock.elapsedRealtime()<until) SystemClock.sleep(20);
            assertTrue(TunnelService.status,TunnelService.status.startsWith("Connecting (awaiting"));
            assertFalse("IPv6 must enter TUN and be dropped: "+TunnelService.status,TunnelService.status.contains("IPv6 blocked 0;"));
        } finally {
            c.startService(new Intent(c,TunnelService.class).setAction(TunnelService.STOP));
            long until=SystemClock.elapsedRealtime()+3000;
            while(!TunnelService.status.contains("Direct fallback is possible") && SystemClock.elapsedRealtime()<until) SystemClock.sleep(20);
            awaitStopped();Arrays.fill(key,(byte)0);KeyStoreConfig.prefs(c).edit().clear().commit();
        }
        assertTrue(TunnelService.status,TunnelService.status.contains("Direct fallback is possible"));
        long until=SystemClock.elapsedRealtime()+1000;
        while(c.getSystemService(NotificationManager.class).getActiveNotifications().length>0 && SystemClock.elapsedRealtime()<until) SystemClock.sleep(20);
        assertEquals(0,c.getSystemService(NotificationManager.class).getActiveNotifications().length);
        for(Thread thread:Thread.getAllStackTraces().keySet()) assertFalse("Worker not stopped",thread.isAlive() && thread.getName().equals("icmp-vpn-io"));
    }
}
