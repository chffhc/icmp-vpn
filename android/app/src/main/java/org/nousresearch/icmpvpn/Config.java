package org.nousresearch.icmpvpn;
import java.net.InetAddress;
import java.net.UnknownHostException;
final class Config {
    private Config() {}
    static InetAddress ipv4(String text) {
        if(text==null || !text.matches("(0|[1-9][0-9]{0,2})(\\.(0|[1-9][0-9]{0,2})){3}")) throw new IllegalArgumentException("Use a literal IPv4 address (no hostname)");
        String[] parts=text.split("\\."); byte[] bytes=new byte[4];
        for(int i=0;i<4;i++) { int n=Integer.parseInt(parts[i]); if(n>255) throw new IllegalArgumentException("IPv4 octet exceeds 255"); bytes[i]=(byte)n; }
        if((bytes[0]&255)==0 || (bytes[0]&255)==127 || (bytes[0]&255)>=224) throw new IllegalArgumentException("Use a unicast, non-loopback IPv4 address");
        try { return InetAddress.getByAddress(bytes); } catch(UnknownHostException impossible) { throw new IllegalArgumentException("Invalid IPv4",impossible); }
    }
}
