package org.nousresearch.icmpvpn;

import static org.junit.Assert.*;
import java.util.Comparator;
import java.util.PriorityQueue;
import org.junit.Test;

/** Runs the shipping Java controller with a deterministic millisecond clock; no Android I/O. */
public class FlowControlHighLatencyTest {
    private static final class Reply {
        final int seq;
        final long at;
        final boolean data;
        Reply(int seq, long at, boolean data) { this.seq = seq; this.at = at; this.data = data; }
    }

    private static final class Metrics {
        final FlowControl flow = new FlowControl();
        int sent, delivered, dataDelivered, maxInflight, steadySent, steadyDataDelivered, reordered;
        long rampAt = -1;
    }

    private Metrics simulate(int rtt, boolean upload, boolean jitter, int dropEvery) {
        Metrics m = new Metrics();
        PriorityQueue<Reply> replies = new PriorityQueue<>(Comparator
                .comparingLong((Reply r) -> r.at).thenComparingInt(r -> r.seq));
        int lastDelivered = 0;
        long end = 30000;
        for (long now = 0; now < end; now++) {
            while (!replies.isEmpty() && replies.peek().at <= now) {
                Reply r = replies.remove();
                if (r.seq < lastDelivered) m.reordered++;
                lastDelivered = Math.max(lastDelivered, r.seq);
                m.flow.onReply(r.seq, r.data, now);
                m.delivered++;
                if (r.data) {
                    m.dataDelivered++;
                    if (now >= 20000) m.steadyDataDelivered++;
                }
            }
            if (now % 50 == 0) m.flow.reap(now);
            int sameMillisecond = 0;
            while (m.flow.shouldSend(now, upload)) {
                int seq = ++m.sent;
                m.flow.onSent(seq, now);
                if (now >= 20000) m.steadySent++;
                assertTrue("adaptive window bypass", m.flow.inflight() <= m.flow.window());
                assertTrue("hard window bypass", m.flow.inflight() <= FlowControl.MAX_WINDOW);
                assertTrue("pacing burst", ++sameMillisecond <= FlowControl.BURST);
                if (dropEvery == 0 || seq % dropEvery != 0) {
                    int delta = jitter ? (seq % 5 - 2) * (rtt / 10) : 0;
                    // Pure uploads receive only empty ACKs; downstream traffic receives
                    // interleaved empties that must not cancel the data-pickup burst.
                    replies.add(new Reply(seq, now + rtt + delta, !upload && seq % 7 != 0));
                }
                m.maxInflight = Math.max(m.maxInflight, m.flow.inflight());
                if (m.rampAt < 0 && m.flow.inflight() >= rtt * 3 * 0.9) m.rampAt = now;
            }
        }
        System.out.printf("FLOW rtt=%d upload=%s jitter=%s dropEvery=%d sent=%d delivered=%d "
                + "steadyEchoPps=%.1f steadyDataPps=%.1f maxInflight=%d window=%d srtt=%d lost=%d rampMs=%d reordered=%d%n",
                rtt, upload, jitter, dropEvery, m.sent, m.delivered, m.steadySent / 10.0,
                m.steadyDataDelivered / 10.0, m.maxInflight, m.flow.window(), m.flow.srtt(), m.flow.lost(), m.rampAt, m.reordered);
        // Stop the traffic source, deliver every remaining scheduled reply, then expire
        // only deliberately dropped requests. This proves exact loss accounting, not
        // just an aggregate loss ratio that could hide false positives.
        while (!replies.isEmpty()) {
            Reply r = replies.remove();
            m.flow.onReply(r.seq, r.data, r.at);
            m.delivered++;
            if (r.data) m.dataDelivered++;
        }
        m.flow.reap(end + FlowControl.MAX_LOSS_MS + 1);
        int dropped = dropEvery == 0 ? 0 : m.sent / dropEvery;
        assertEquals("exact configured drops, no false losses", dropped, m.flow.lost());
        assertEquals("every echo accounted for", m.sent, m.delivered + dropped);
        assertEquals("no leaked outstanding slots", 0, m.flow.inflight());
        return m;
    }

    @Test public void highLatencyUploadAndDownloadReachPacedBdpWithoutSixRttStartup() {
        for (int rtt : new int[] {500, 1000, 2000}) {
            for (boolean upload : new boolean[] {false, true}) {
                Metrics m = simulate(rtt, upload, false, 0);
                assertEquals("no false loss at " + rtt, 0, m.flow.lost());
                assertTrue("steady pacing at " + rtt, m.steadySent >= 29000);
                assertTrue("sustained cap", m.steadySent <= 30008);
                assertTrue("startup should fill BDP in <= 3 RTT", m.rampAt >= 0 && m.rampAt <= 3L * rtt);
                assertTrue("modest BDP headroom", m.flow.window() <= Math.ceil(rtt * 3.3) + FlowControl.BURST);
            }
        }
    }

    @Test public void highLatencyJitterReorderingAndMixedEmptyRepliesAreNotLoss() {
        for (int rtt : new int[] {500, 1000, 2000}) {
            Metrics m = simulate(rtt, false, true, 0);
            assertEquals("jitter must not be loss", 0, m.flow.lost());
            assertTrue("actually exercised reordering", m.reordered > 0);
            assertTrue("useful throughput under +/-20% jitter", m.steadySent >= 24000);
        }
    }

    @Test public void lossIsDetectedAndBothDirectionsRemainBounded() {
        for (boolean upload : new boolean[] {false, true}) {
            Metrics m = simulate(2000, upload, true, 100);
            assertTrue("actual loss must be detected", m.flow.lost() > 0);
            assertTrue("not every request is classified lost", m.flow.lost() < m.sent / 20);
            assertTrue("loss recovery remains useful at 2s RTT", m.steadySent >= 15000);
            if (upload) assertEquals("pure upload uses only empty ACKs", 0, m.dataDelivered);
            else assertTrue("unique downstream data survives mixed empties and loss", m.steadyDataDelivered >= 12000);
            assertTrue(m.flow.window() >= FlowControl.MIN_WINDOW);
        }
    }

    @Test public void coldStartWaitsAtLeastFourSecondsForFirstMeasurement() {
        FlowControl f = new FlowControl();
        f.onSent(1, 0);
        f.reap(3999);
        assertEquals(1, f.inflight());
        assertEquals(0, f.lost());
        f.reap(4000);
        assertEquals(1, f.inflight());
        f.reap(4001);
        assertEquals(0, f.inflight());
        assertEquals(1, f.lost());
        FlowControl measured = new FlowControl();
        measured.onSent(1, 0);
        measured.onReply(1, false, 2000);
        assertEquals("timestamp zero has no sentinel bias", 2000, measured.srtt());
        assertTrue("first measured BDP floor", measured.window() >= 6000);
    }

    @Test public void measuredTwoSecondRttUsesAtLeastEightSecondLossTimer() {
        FlowControl f = new FlowControl();
        f.onSent(1, 0);
        f.onReply(1, true, 2000);
        f.onSent(2, 2000);
        f.reap(10000);
        assertEquals(1, f.inflight());
        assertEquals(0, f.lost());
        f.reap(10001);
        assertEquals(0, f.inflight());
        assertEquals(1, f.lost());
    }

    @Test public void emptyRepliesKeepRecentBurstForTwoRttThenReturnToIdle() {
        FlowControl f = new FlowControl();
        f.onSent(1, 0);
        f.onReply(1, true, 2000);
        f.onSent(2, 2000);
        f.onReply(2, false, 4000);
        f.onSent(3, 4000);
        assertTrue("empty must not instantly cancel recent data", f.shouldSend(4001, false));
        f.onSent(4, 5999);
        assertTrue("at least two full RTT since data", f.shouldSend(6000, false));
        f.onSent(5, 6100);
        assertFalse("bounded hysteresis expires", f.shouldSend(6101, false));
        assertEquals(19, f.pollTimeout(6101, false));
        assertTrue(f.shouldSend(6120, false));
    }

    @Test public void uploadsCannotBypassReducedAdaptiveWindow() {
        FlowControl f = new FlowControl();
        f.onSent(1, 0);
        f.onReply(1, false, 2000);
        int before = f.window();
        f.onSent(2, 2000);
        f.reap(10001);
        assertEquals(before / 2, f.window());
        int seq = 2;
        for (long now = 10002; f.inflight() < f.window(); now++) {
            while (f.shouldSend(now, true)) f.onSent(++seq, now);
        }
        assertEquals(f.window(), f.inflight());
        assertFalse(f.shouldSend(12000, true));
        assertEquals(FlowControl.IDLE_POLL_MS, f.pollTimeout(12000, true));
    }

    @Test public void sequenceWrapAndSlotAliasesDoNotMutateUnmatchedOutstandingRequests() {
        FlowControl f = new FlowControl();
        for (int seq = 65530; seq < 65550; seq++) {
            f.onSent(seq, seq);
            int inflight = f.inflight();
            int window = f.window();
            long srtt = f.srtt();
            f.onReply(seq + FlowControl.SLOTS, true, seq + 2000);
            assertEquals(inflight, f.inflight());
            assertEquals(window, f.window());
            assertEquals(srtt, f.srtt());
            f.onReply(seq & 65535, false, seq + 2000);
            assertEquals(0, f.inflight());
            long smoothed = f.srtt();
            f.onReply(seq, true, seq + 9000);
            assertEquals(smoothed, f.srtt());
            assertEquals(0, f.lost());
        }
    }

    @Test public void emptyRttUpdateExtendsHysteresisWithoutRefreshingLastDataTime() {
        FlowControl f = new FlowControl();
        f.onSent(1, 0);
        f.onSent(2, 0);
        f.onReply(1, true, 500);
        f.onReply(2, false, 1400);
        assertEquals(613, f.srtt());
        f.onSent(3, 1599);
        assertTrue("empty RTT update preserves two current RTTs", f.shouldSend(1600, false));
        f.onSent(4, 1746);
        assertFalse("empty ACK did not refresh last data time", f.shouldSend(1747, false));
        assertTrue(f.shouldSend(1766, false));
    }

    @Test public void rttVarianceExtendsTimerBeyondFourSecondFloor() {
        FlowControl f = new FlowControl();
        f.onSent(1, 0);
        f.onReply(1, false, 1);
        f.onSent(2, 1);
        f.reap(3500);
        assertEquals(1, f.inflight());
        f.onReply(2, false, 3501);
        f.onSent(3, 3501);
        f.reap(7000);
        assertEquals(1, f.inflight());
        f.onReply(3, false, 7001);
        f.onSent(4, 7001);
        f.reap(13501); // 6500ms old: SRTT+4*RTTVAR exceeds this despite low SRTT.
        assertEquals(1, f.inflight());
        assertEquals(0, f.lost());
        f.reap(14501);
        assertEquals(0, f.inflight());
        assertEquals(1, f.lost());
    }

    @Test public void lossTimerHasFifteenSecondUpperBound() {
        FlowControl f = new FlowControl();
        f.onSent(1, 0);
        f.onReply(1, false, 5000);
        f.onSent(2, 5000);
        f.reap(20000);
        assertEquals(1, f.inflight());
        f.reap(20001);
        assertEquals(0, f.inflight());
        assertEquals(1, f.lost());
    }

    @Test public void twoSecondIdlePathSettlesToFiftyPollsPerSecond() {
        FlowControl f = new FlowControl();
        PriorityQueue<Reply> replies = new PriorityQueue<>(Comparator.comparingLong(r -> r.at));
        int seq = 0, steady = 0;
        for (long now = 0; now < 15000; now++) {
            while (!replies.isEmpty() && replies.peek().at <= now) {
                Reply r = replies.remove();
                f.onReply(r.seq, false, now);
            }
            if (now % 50 == 0) f.reap(now);
            if (f.shouldSend(now, false)) {
                f.onSent(++seq, now);
                replies.add(new Reply(seq, now + 2000, false));
                if (now >= 5000) steady++;
                assertFalse("idle never emits two requests on one tick", f.shouldSend(now, false));
            }
        }
        assertEquals("10 seconds at one poll per20ms", 500, steady);
        assertEquals(2000, f.srtt());
        assertEquals(0, f.lost());
    }

    @Test public void noSampleDoesNotPermitUncontrolledHighRttUploadStartup() {
        FlowControl f = new FlowControl();
        int sent = 0;
        for (long now = 0; now < 2000; now++) {
            while (f.shouldSend(now, true)) f.onSent(++sent, now);
        }
        assertEquals(FlowControl.INITIAL_WINDOW, sent);
        assertEquals(0, f.srtt());
        assertEquals(FlowControl.INITIAL_WINDOW, f.window());
        assertEquals(FlowControl.IDLE_POLL_MS, f.pollTimeout(2000, true));
    }

    @Test public void prematchedButImpossibleEarlyReplyIsIgnored() {
        FlowControl f = new FlowControl();
        f.onSent(1, 1000);
        f.onReply(1, true, 999);
        assertEquals(1, f.inflight());
        assertEquals(0, f.srtt());
        assertEquals(FlowControl.INITIAL_WINDOW, f.window());
        f.onReply(1, false, 3000);
        assertEquals(0, f.inflight());
        assertEquals(2000, f.srtt());
    }

    @Test public void lowRttTargetDoesNotAccumulateHighLatencyBacklog() {
        Metrics m = simulate(10, true, false, 0);
        assertTrue(m.flow.window() <= 41);
        assertTrue(m.maxInflight <= 41);
        assertTrue(m.steadySent >= 29000);
        assertEquals(0, m.flow.lost());
    }
}
