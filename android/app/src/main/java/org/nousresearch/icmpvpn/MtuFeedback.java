package org.nousresearch.icmpvpn;
import java.util.Arrays;
/** IPv6 requires interface MTU >=1280. Advise IPv4 senders of the 1200-byte wire ceiling. */
final class MtuFeedback {
    private MtuFeedback() {}
    static byte[] clampTcpMss(byte[] packet) {
        int ihl=(packet[0]&15)*4;
        if((packet[9]&255)!=6 || packet.length<ihl+20 || (packet[ihl+13]&2)==0) return packet;
        int end=ihl+((packet[ihl+12]&240)>>>2);
        if(end<ihl+20 || end>packet.length) return packet;
        byte[] result=null;
        for(int pos=ihl+20;pos<end;) {
            int kind=packet[pos]&255;if(kind==0) break;if(kind==1) {pos++;continue;}
            if(pos+1>=end) break;int len=packet[pos+1]&255;if(len<2 || pos+len>end) break;
            if(kind==2 && len==4 && (((packet[pos+2]&255)<<8)|(packet[pos+3]&255))>1160) {
                if(result==null) result=packet.clone();result[pos+2]=4;result[pos+3]=(byte)136;
            }
            pos+=len;
        }
        if(result==null) return packet;
        int length=result.length-ihl;byte[] checksum=new byte[12+length];
        System.arraycopy(result,12,checksum,0,8);checksum[9]=6;checksum[10]=(byte)(length>>>8);checksum[11]=(byte)length;
        result[ihl+16]=0;result[ihl+17]=0;System.arraycopy(result,ihl,checksum,12,length);
        int sum=Protocol.checksum(checksum);result[ihl+16]=(byte)(sum>>>8);result[ihl+17]=(byte)sum;return result;
    }
    static byte[] forOversize(byte[] original) {
        if(original.length<=Protocol.MTU || !Protocol.validIpv4(original,true,65535)) return null;
        int ihl=(original[0]&15)*4;
        if((original[9]&255)==1 && original.length>ihl) {
            int type=original[ihl]&255;
            if(type==3 || type==4 || type==5 || type==11 || type==12) return null; // Never error on an ICMP error.
        }
        int quote=Math.min(original.length,ihl+8), total=28+quote;
        byte[] reply=new byte[total];reply[0]=0x45;reply[2]=(byte)(total>>>8);reply[3]=(byte)total;
        reply[8]=64;reply[9]=1;reply[12]=10;reply[13]=77;reply[15]=1;reply[16]=10;reply[17]=77;reply[19]=2;
        reply[20]=3;reply[21]=4;reply[26]=(byte)(Protocol.MTU>>>8);reply[27]=(byte)Protocol.MTU;
        System.arraycopy(original,0,reply,28,quote);
        int ip=Protocol.checksum(Arrays.copyOf(reply,20));reply[10]=(byte)(ip>>>8);reply[11]=(byte)ip;
        int icmp=Protocol.checksum(Arrays.copyOfRange(reply,20,total));reply[22]=(byte)(icmp>>>8);reply[23]=(byte)icmp;
        return reply;
    }
}
