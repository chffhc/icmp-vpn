import java.io.BufferedReader;
import java.io.InputStreamReader;
import org.nousresearch.icmpvpn.FlowControl;

/** Executes the exact Android controller for host-native WAN probes, not Android I/O. */
public final class FlowControlHarness {
    public static void main(String[] args) throws Exception {
        FlowControl f = new FlowControl();
        BufferedReader in = new BufferedReader(new InputStreamReader(System.in));
        String line;
        while ((line = in.readLine()) != null) {
            String[] p = line.split(" ");
            long now = Long.parseLong(p[1]);
            switch (p[0]) {
                case "S": f.onSent(Integer.parseInt(p[2]), now); break;
                case "R": f.onReply(Integer.parseInt(p[2]), Boolean.parseBoolean(p[3]), now); break;
                case "E": f.reap(now); break;
                case "Q": break;
                default: throw new IllegalArgumentException("unknown command");
            }
            boolean upload = p[0].equals("Q") && Boolean.parseBoolean(p[2]);
            System.out.println(f.shouldSend(now, upload) + " " + f.pollTimeout(now, upload)
                + " " + f.inflight() + " " + f.window() + " " + f.srtt() + " " + f.lost());
            System.out.flush();
        }
    }
}
