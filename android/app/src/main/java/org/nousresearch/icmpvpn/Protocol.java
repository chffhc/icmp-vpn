package org.nousresearch.icmpvpn;

import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.SecureRandom;
import java.util.Arrays;
import javax.crypto.Cipher;
import javax.crypto.Mac;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;

/** Pure Java fixed IVP1 wire codec. No Android dependencies. */
public final class Protocol {
    public static final int POLL=0, IP=1, HELLO=2, CLOSE=3, MTU=1200;
    public static final byte[] HELLO_REPLY="10.77.0.2|1200".getBytes(StandardCharsets.US_ASCII);
    private static final int MAGIC=0x49565031;
    private Protocol() {}
    public static byte[] parseKey(String text) {
        if (text == null || !text.matches("[0-9a-fA-F]{64}")) throw new IllegalArgumentException("PSK must be exactly 64 hex characters");
        byte[] key=new byte[32];
        for(int i=0;i<32;i++) key[i]=(byte)Integer.parseInt(text.substring(i*2,i*2+2),16);
        return key;
    }
    public static long freshSession() {
        SecureRandom rng=new SecureRandom(); long id;
        do { id=rng.nextLong(); } while(id==0);
        return id;
    }
    public static byte[] derive(byte[] psk,int direction,long session) throws GeneralSecurityException {
        if(psk.length!=32 || direction<0 || direction>1 || session==0) throw new IllegalArgumentException("Invalid key parameters");
        Mac mac=Mac.getInstance("HmacSHA256"); mac.init(new SecretKeySpec(psk,"HmacSHA256"));
        mac.update("icmp-vpn-v1/".getBytes(StandardCharsets.US_ASCII)); mac.update((byte)direction);
        return mac.doFinal(ByteBuffer.allocate(8).putLong(session).array());
    }
    private static Cipher cipher(int mode,byte[] key,long sequence) throws GeneralSecurityException {
        Cipher c=Cipher.getInstance("AES/GCM/NoPadding");
        c.init(mode,new SecretKeySpec(key,"AES"),new GCMParameterSpec(128,ByteBuffer.allocate(12).putInt(0).putLong(sequence).array()));
        return c;
    }
    public static byte[] encode(byte[] key,long session,long sequence,int kind,byte[] plain) throws GeneralSecurityException {
        if(session==0 || sequence==0 || plain.length>MTU || kind<0 || kind>3 || ((kind==POLL || kind==CLOSE) && plain.length!=0)) throw new IllegalArgumentException("Invalid frame");
        byte[] header=ByteBuffer.allocate(24).putInt(MAGIC).put((byte)1).put((byte)kind).putLong(session).putLong(sequence).putShort((short)plain.length).array();
        Cipher c=cipher(Cipher.ENCRYPT_MODE,key,sequence); c.updateAAD(header);
        byte[] encrypted=c.doFinal(plain); byte[] out=Arrays.copyOf(header,24+encrypted.length);
        System.arraycopy(encrypted,0,out,24,encrypted.length); return out;
    }
    public static final class Frame {
        public final int kind; public final long sequence; public final byte[] plain;
        Frame(int k,long s,byte[] p) { kind=k;sequence=s;plain=p; }
    }
    /** Authentication and all semantic checks precede replay mutation. */
    public static Frame decode(byte[] key,long session,int direction,byte[] frame,Replay replay) throws GeneralSecurityException {
        return decode(key,session,direction,frame,replay,false);
    }
    public static Frame decode(byte[] key,long session,int direction,byte[] frame,Replay replay,boolean helloRequired) throws GeneralSecurityException {
        if(direction<0 || direction>1 || frame.length<40 || frame.length>1240) throw new GeneralSecurityException("Frame length/direction");
        ByteBuffer b=ByteBuffer.wrap(frame);
        if(b.getInt()!=MAGIC || b.get()!=1) throw new GeneralSecurityException("Frame magic/version");
        int kind=b.get()&255; long sid=b.getLong(), seq=b.getLong(); int len=b.getShort()&65535;
        if(kind>3 || sid==0 || sid!=session || seq==0 || len>MTU || frame.length!=24+len+16) throw new GeneralSecurityException("Frame header");
        Cipher c=cipher(Cipher.DECRYPT_MODE,key,seq); c.updateAAD(frame,0,24);
        byte[] p=c.doFinal(frame,24,frame.length-24);
        if((kind==POLL || kind==CLOSE) && p.length!=0) throw new GeneralSecurityException("Idle/close payload");
        if(kind==HELLO && !(direction==0 ? p.length==0 : Arrays.equals(p,HELLO_REPLY))) throw new GeneralSecurityException("HELLO configuration mismatch");
        if(kind==IP && !validIpv4(p,direction==0)) throw new GeneralSecurityException("Invalid inner IPv4");
        if(helloRequired && kind!=HELLO) throw new GeneralSecurityException("HELLO required before data");
        if(!replay.accept(seq)) throw new GeneralSecurityException("Replay/stale");
        return new Frame(kind,seq,p);
    }
    public static boolean validIpv4(byte[] p,boolean outbound) { return validIpv4(p,outbound,MTU); }
    static boolean validIpv4(byte[] p,boolean outbound,int maxLength) {
        if(p.length<20 || p.length>maxLength || (p[0]&240)!=64) return false;
        int ihl=(p[0]&15)*4, total=((p[2]&255)<<8)|(p[3]&255), fragment=((p[6]&255)<<8)|(p[7]&255);
        if(ihl<20 || ihl>p.length || total!=p.length || (fragment&0xbfff)!=0) return false;
        int i=outbound?12:16;
        return p[i]==10 && p[i+1]==77 && p[i+2]==0 && p[i+3]==2;
    }
    public static final class Replay {
        public static final int WINDOW=32768;
        private long highest=0; private final boolean[] seen=new boolean[WINDOW];
        public boolean accept(long seq) {
            if(seq==0) return false;
            if(highest==0 || Long.compareUnsigned(seq,highest)>0) {
                long delta=seq-highest;
                if(highest==0 || Long.compareUnsigned(delta,WINDOW)>=0) Arrays.fill(seen,false);
                else for(int i=1;i<=(int)delta;i++) seen[(int)(highest+i)&(WINDOW-1)]=false;
                highest=seq;
            } else if(Long.compareUnsigned(highest-seq,WINDOW)>=0) return false;
            int slot=(int)seq&(WINDOW-1); if(seen[slot]) return false; seen[slot]=true; return true;
        }
    }
    public static final class Sequence {
        private long next=1;
        public long take() {
            if(next==0) throw new IllegalStateException("Sequence exhausted; reconnect required");
            return next++;
        }
    }
    public static byte[] echo(byte[] frame,int sequence) {
        byte[] d=new byte[8+frame.length]; d[0]=8; d[6]=(byte)(sequence>>>8); d[7]=(byte)sequence;
        System.arraycopy(frame,0,d,8,frame.length); int sum=checksum(d); d[2]=(byte)(sum>>>8); d[3]=(byte)sum; return d;
    }
    public static byte[] replyPayload(byte[] d,int length) throws GeneralSecurityException {
        if(length<48 || length>1248 || (d[0]&255)!=0 || d[1]!=0) throw new GeneralSecurityException("Not an echo reply");
        byte[] exact=Arrays.copyOf(d,length);
        if(checksum(exact)!=0) throw new GeneralSecurityException("ICMP checksum");
        return Arrays.copyOfRange(exact,8,length);
    }
    public static int checksum(byte[] bytes) {
        int sum=0; for(int i=0;i<bytes.length;i+=2) sum+=((bytes[i]&255)<<8)|(i+1<bytes.length?(bytes[i+1]&255):0);
        while((sum>>>16)!=0) sum=(sum&65535)+(sum>>>16); return (~sum)&65535;
    }
}
