package org.nousresearch.icmpvpn;
import org.junit.Test;
import static org.junit.Assert.*;
import java.util.Arrays;
public class MtuFeedbackTest {
    private byte[] packet(int length) {
        byte[] p=new byte[length];p[0]=0x45;p[2]=(byte)(length>>>8);p[3]=(byte)length;p[6]=0x40;p[8]=64;p[9]=17;p[12]=10;p[13]=77;p[15]=2;p[16]=1;p[17]=1;p[18]=1;p[19]=1;return p;
    }
    @Test public void correctFragmentationNeededAndQuote() {
        byte[] p=packet(1280),r=MtuFeedback.forOversize(p);assertNotNull(r);assertEquals(56,r.length);assertTrue(Protocol.validIpv4(r,false));
        assertEquals(0,Protocol.checksum(Arrays.copyOf(r,20)));assertEquals(0,Protocol.checksum(Arrays.copyOfRange(r,20,r.length)));
        assertEquals(3,r[20]);assertEquals(4,r[21]);assertEquals(1200,((r[26]&255)<<8)|(r[27]&255));assertArrayEquals(Arrays.copyOf(p,28),Arrays.copyOfRange(r,28,r.length));
    }
    @Test public void noFeedbackForSmallMalformedIpv6OrFragments() {
        assertNull(MtuFeedback.forOversize(packet(1200)));byte[] p=packet(1280);p[0]=0x60;assertNull(MtuFeedback.forOversize(p));
        p=packet(1280);p[6]=0x20;assertNull(MtuFeedback.forOversize(p));p=packet(1280);p[3]=1;assertNull(MtuFeedback.forOversize(p));
    }
    @Test public void tcpSynMssClampRecomputesPseudoheaderChecksum() {
        byte[] p=packet(44);p[9]=6;p[32]=0x60;p[33]=2;p[40]=2;p[41]=4;p[42]=5;p[43]=(byte)180;
        byte[] r=MtuFeedback.clampTcpMss(p);assertEquals(1160,((r[42]&255)<<8)|(r[43]&255));assertEquals(1460,((p[42]&255)<<8)|(p[43]&255));
        byte[] sum=new byte[36];System.arraycopy(r,12,sum,0,8);sum[9]=6;sum[11]=24;System.arraycopy(r,20,sum,12,24);assertEquals(0,Protocol.checksum(sum));
        assertSame(r,MtuFeedback.clampTcpMss(r));p[33]=16;assertSame(p,MtuFeedback.clampTcpMss(p));
    }
    @Test public void neverErrorOnIcmpErrors() {
        for(int type:new int[]{3,4,5,11,12}) { byte[] p=packet(1280);p[9]=1;p[20]=(byte)type;assertNull(MtuFeedback.forOversize(p)); }
        byte[] p=packet(1280);p[9]=1;p[20]=8;assertNotNull(MtuFeedback.forOversize(p));
    }
}
