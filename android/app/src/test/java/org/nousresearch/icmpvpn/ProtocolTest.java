package org.nousresearch.icmpvpn;
import org.junit.Test;
import static org.junit.Assert.*;
import java.util.*;
import java.security.GeneralSecurityException;
import java.nio.ByteBuffer;
import javax.crypto.Cipher;
import javax.crypto.spec.*;

public class ProtocolTest {
    private static final byte[] PSK=Protocol.parseKey("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f");
    private static final long SID=0x0102030405060708L;
    static byte[] hex(String s) { byte[] b=new byte[s.length()/2]; for(int i=0;i<b.length;i++) b[i]=(byte)Integer.parseInt(s.substring(2*i,2*i+2),16); return b; }
    @Test public void independentPythonWireVectors() throws Exception {
        Properties p=new Properties(); try(var in=getClass().getResourceAsStream("/vectors.properties")) { assertNotNull(in); p.load(in); }
        byte[] psk=Protocol.parseKey(p.getProperty("psk_hex")); int count=Integer.parseInt(p.getProperty("count")); assertEquals(4,count);
        for(int i=0;i<count;i++) {
            String prefix=i+"."; int dir=Integer.parseInt(p.getProperty(prefix+"direction")), kind=Integer.parseInt(p.getProperty(prefix+"kind"));
            long sid=Long.parseUnsignedLong(p.getProperty(prefix+"session_id_hex"),16), seq=Long.parseUnsignedLong(p.getProperty(prefix+"sequence"));
            byte[] key=Protocol.derive(psk,dir,sid), plain=hex(p.getProperty(prefix+"plaintext_hex")), frame=hex(p.getProperty(prefix+"frame_hex"));
            assertArrayEquals(hex(p.getProperty(prefix+"key_hex")),key);
            assertArrayEquals(frame,Protocol.encode(key,sid,seq,kind,plain));
            assertArrayEquals(plain,Protocol.decode(key,sid,dir,frame,new Protocol.Replay()).plain);
        }
    }
    private static void rejected(byte[] key,long sid,int dir,byte[] wire,Protocol.Replay replay) throws Exception {
        try { Protocol.decode(key,sid,dir,wire,replay); fail("Accepted invalid frame"); } catch(GeneralSecurityException expected) { }
    }
    @Test public void tamperingReflectionAndWrongSessionRejected() throws Exception {
        byte[] tx=Protocol.derive(PSK,0,SID), rx=Protocol.derive(PSK,1,SID);
        byte[] wire=Protocol.encode(tx,SID,1,Protocol.HELLO,new byte[0]);
        rejected(rx,SID,1,wire,new Protocol.Replay()); rejected(tx,SID+1,0,wire,new Protocol.Replay());
        for(int i=0;i<wire.length;i++) { byte[] bad=wire.clone(); bad[i]^=1; rejected(tx,SID,0,bad,new Protocol.Replay()); }
    }
    @Test public void authFailuresDoNotPoisonReplay() throws Exception {
        byte[] key=Protocol.derive(PSK,1,SID), wire=Protocol.encode(key,SID,1,Protocol.POLL,new byte[0]);
        Protocol.Replay replay=new Protocol.Replay(); byte[] bad=wire.clone(); bad[bad.length-1]^=1;
        rejected(key,SID,1,bad,replay); Protocol.decode(key,SID,1,wire,replay); rejected(key,SID,1,wire,replay);
    }
    @Test public void semanticFailuresDoNotPoisonReplay() throws Exception {
        byte[] key=Protocol.derive(PSK,1,SID); Protocol.Replay replay=new Protocol.Replay();
        rejected(key,SID,1,Protocol.encode(key,SID,1,Protocol.HELLO,new byte[]{1}),replay);
        rejected(key,SID,1,Protocol.encode(key,SID,1,Protocol.IP,new byte[]{0x60}),replay);
        Protocol.decode(key,SID,1,Protocol.encode(key,SID,1,Protocol.POLL,new byte[0]),replay);
    }
    @Test public void replayReorderWindowAndUnsignedSequences() {
        Protocol.Replay r=new Protocol.Replay(); long n=Protocol.Replay.WINDOW;
        assertTrue(r.accept(n+44)); assertTrue(r.accept(45)); assertFalse(r.accept(44)); assertFalse(r.accept(45));
        assertTrue(r.accept(n+45)); assertFalse(r.accept(45)); assertTrue(r.accept(46)); assertFalse(r.accept(0));
        r=new Protocol.Replay(); assertTrue(r.accept(Long.MAX_VALUE)); assertTrue(r.accept(Long.MIN_VALUE)); assertTrue(r.accept(-1)); assertFalse(r.accept(-1)); assertTrue(r.accept(-2)); assertFalse(r.accept(1));
    }
    @Test public void strictLengthsAndHeaders() throws Exception {
        byte[] key=Protocol.derive(PSK,1,SID), wire=Protocol.encode(key,SID,1,0,new byte[0]);
        for(int n=0;n<wire.length;n++) rejected(key,SID,1,Arrays.copyOf(wire,n),new Protocol.Replay());
        rejected(key,SID,1,Arrays.copyOf(wire,wire.length+1),new Protocol.Replay());
        for(int pos:new int[]{0,4,5,6,14,22}) { byte[] b=wire.clone(); b[pos]=(byte)255; rejected(key,SID,1,b,new Protocol.Replay()); }
    }
    @Test public void authenticatedMalformedHeaderAndPayloadRejected() throws Exception {
        byte[] key=Protocol.derive(PSK,1,SID);
        // Sign deliberately malformed headers to distinguish semantics from failed authentication.
        for(int kind:new int[]{0,3,4}) {
            byte[] h=ByteBuffer.allocate(24).putInt(0x49565031).put((byte)1).put((byte)kind).putLong(SID).putLong(1).putShort((short)1).array();
            Cipher c=Cipher.getInstance("AES/GCM/NoPadding"); c.init(Cipher.ENCRYPT_MODE,new SecretKeySpec(key,"AES"),new GCMParameterSpec(128,ByteBuffer.allocate(12).putInt(0).putLong(1).array())); c.updateAAD(h);
            byte[] ct=c.doFinal(new byte[]{1}), wire=Arrays.copyOf(h,24+ct.length); System.arraycopy(ct,0,wire,24,ct.length);
            Protocol.Replay replay=new Protocol.Replay(); rejected(key,SID,1,wire,replay); assertTrue(replay.accept(1));
        }
    }
    @Test public void ipv4BoundariesAndFragments() {
        byte[] p=hex("450000140001000040010000010101010a4d0002"); assertTrue(Protocol.validIpv4(p,false)); assertFalse(Protocol.validIpv4(p,true));
        for(int pos:new int[]{0,2,3,6,7,16,19}) { byte[] b=p.clone(); b[pos]^=1; assertFalse("position "+pos,Protocol.validIpv4(b,false)); }
        p[6]=0x40; assertTrue(Protocol.validIpv4(p,false)); p[6]=0x20; assertFalse(Protocol.validIpv4(p,false));
        assertFalse(Protocol.validIpv4(new byte[0],false)); assertFalse(Protocol.validIpv4(new byte[]{0x60},false));
    }
    @Test public void maximumFrameAndIcmpChecksum() throws Exception {
        byte[] p=new byte[1200]; p[0]=0x45; p[2]=4; p[3]=(byte)176; p[16]=10;p[17]=77;p[19]=2;
        byte[] key=Protocol.derive(PSK,1,SID), frame=Protocol.encode(key,SID,1,1,p), d=Protocol.echo(frame,65535); assertEquals(1248,d.length); assertEquals(0,Protocol.checksum(d));
        d[0]=0;d[2]=0;d[3]=0; int cs=Protocol.checksum(d);d[2]=(byte)(cs>>>8);d[3]=(byte)cs;
        assertArrayEquals(frame,Protocol.replyPayload(d,d.length)); assertArrayEquals(p,Protocol.decode(key,SID,1,frame,new Protocol.Replay()).plain);
        d[8]^=1; try { Protocol.replyPayload(d,d.length); fail(); } catch(GeneralSecurityException expected) { }
    }
    @Test public void pskAndSessionValidation() {
        for(String s:new String[]{"", "00", "x".repeat(64), " "+"0".repeat(64), "0".repeat(64)+" "}) { try { Protocol.parseKey(s);fail(); } catch(IllegalArgumentException expected) { } }
        assertEquals(32,Protocol.parseKey("A".repeat(64)).length); for(int i=0;i<100;i++) assertNotEquals(0,Protocol.freshSession());
    }
    @Test public void preHandshakeDataDoesNotConsumeReplay() throws Exception {
        byte[] key=Protocol.derive(PSK,1,SID);Protocol.Replay replay=new Protocol.Replay();
        try { Protocol.decode(key,SID,1,Protocol.encode(key,SID,1,Protocol.POLL,new byte[0]),replay,true);fail(); } catch(GeneralSecurityException expected) { }
        Protocol.decode(key,SID,1,Protocol.encode(key,SID,1,Protocol.HELLO,Protocol.HELLO_REPLY),replay,true);
    }
    @Test public void sequenceWrapIsFatal() throws Exception {
        Protocol.Sequence sequence=new Protocol.Sequence();java.lang.reflect.Field next=Protocol.Sequence.class.getDeclaredField("next");next.setAccessible(true);next.setLong(sequence,-1);
        assertEquals(-1,sequence.take());try { sequence.take();fail(); } catch(IllegalStateException expected) { }
    }
    @Test public void literalIpv4Only() {
        assertEquals("192.0.2.1",Config.ipv4("192.0.2.1").getHostAddress());
        for(String host:new String[]{"example.com","1.1.1.999","1.1.1","01.1.1.1","127.0.0.1","0.0.0.0","224.1.1.1","::1"," 1.1.1.1","1.1.1.1 "}) {
            try { Config.ipv4(host);fail(host); } catch(IllegalArgumentException expected) { }
        }
    }
    @Test public void expandedReplayRingMatchesReferenceUnderReordering() {
        Protocol.Replay r=new Protocol.Replay(); Set<Long> reference=new HashSet<>();
        Random random=new Random(7); long highest=0;
        for(int i=0;i<100000;i++) {
            long seq=Math.max(1,highest + random.nextInt(101)-70);
            if(i%37==0) seq=highest+40000;
            boolean expected=seq>0 && seq>highest-Protocol.Replay.WINDOW && !reference.contains(seq);
            assertEquals("sequence "+seq,expected,r.accept(seq));
            if(expected) {
                highest=Math.max(highest,seq); final long floor=highest-Protocol.Replay.WINDOW;
                reference.removeIf(n -> n<=floor);reference.add(seq);
            }
        }
    }
    @Test public void sequenceStartsAtOne() { Protocol.Sequence s=new Protocol.Sequence();assertEquals(1,s.take());assertEquals(2,s.take()); }
}
