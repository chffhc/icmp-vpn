package org.nousresearch.icmpvpn;

import static org.junit.Assert.*;
import org.junit.Test;

public class FlowControlTest {
    private static int target(long rtt) {
        return (int) Math.min(FlowControl.MAX_WINDOW,
                Math.max(FlowControl.INITIAL_WINDOW, Math.ceil(rtt * 3.3) + FlowControl.BURST));
    }

    @Test public void idleSendsOnePollPer20ms() {
        FlowControl f = new FlowControl();
        assertTrue(f.shouldSend(1000, false));
        f.onSent(1, 1000);
        assertFalse(f.shouldSend(1001, false));
        assertFalse(f.shouldSend(1019, false));
        assertTrue(f.shouldSend(1020, false));
        f.onReply(1, false, 1030);
        assertEquals(0, f.inflight());
        assertEquals("empty ACK measures RTT but does not enable burst", target(30), f.window());
        f.onSent(2, 1030);
        assertFalse(f.shouldSend(1031, false));
        assertTrue(f.shouldSend(1050, false));
    }

    @Test public void dataRepliesSetMeasuredWindowWithPacing() {
        FlowControl f = new FlowControl();
        f.onSent(1, 1000);
        f.onReply(1, true, 1030);
        assertEquals(target(30), f.window());
        int seq = 1;
        while (f.shouldSend(1030, false)) f.onSent(++seq, 1030);
        assertEquals("pacing bounds first measured-window burst", FlowControl.BURST, f.inflight());
        assertFalse(f.shouldSend(1030, false));
        for (long now = 1031; f.inflight() < f.window(); now++) {
            while (f.shouldSend(now, false)) f.onSent(++seq, now);
        }
        assertEquals(target(30), f.inflight());
        assertFalse("no idle escape from a full adaptive window", f.shouldSend(1100, false));
        assertFalse("upload cannot escape either", f.shouldSend(1100, true));
        assertTrue(f.window() < FlowControl.MAX_WINDOW);
    }

    @Test public void emptyReplyDoesNotInstantlyEndRecentBurst() {
        FlowControl f = new FlowControl();
        f.onSent(1, 1000);
        f.onReply(1, true, 1030);
        assertTrue(f.shouldSend(1030, false));
        f.onSent(2, 1030);
        f.onReply(2, false, 1040);
        assertTrue("interleaved empty ACK is not a queue drain signal", f.shouldSend(1041, false));
        f.onSent(3, 1109);
        assertTrue(f.shouldSend(1109, false));
        // At 1110 pickup mode ends; the last request still sets a 20ms idle interval.
        assertFalse(f.shouldSend(1110, false));
        assertFalse(f.shouldSend(1128, false));
        assertTrue(f.shouldSend(1129, false));
    }

    @Test public void tokenBucketLimitsBurstAndSustainedRate() {
        FlowControl f = new FlowControl();
        int sent = 0;
        while (f.shouldSend(1000, true)) f.onSent(++sent, 1000);
        assertEquals("same-millisecond burst", FlowControl.BURST, sent);
        assertEquals("full initial window is not just pacing", FlowControl.IDLE_POLL_MS, f.pollTimeout(1000, true));
        f.onReply(1, false, 1000);
        assertEquals("with window space, refill is <=1ms away", 1, f.pollTimeout(1000, true));
        FlowControl g = new FlowControl();
        int n = 0;
        for (long ms = 0; ms < 1000; ms++) {
            while (g.shouldSend(ms, true)) { g.onSent(++n, ms); g.onReply(n, false, ms); }
        }
        assertTrue("rate " + n, n <= FlowControl.MAX_RATE_PPS + FlowControl.BURST);
        assertTrue("rate " + n, n >= FlowControl.MAX_RATE_PPS - FlowControl.BURST);
    }

    @Test public void uploadsBypassIdleTimerButRespectAdaptiveCap() {
        FlowControl f = new FlowControl();
        for (int i = 1; i <= FlowControl.INITIAL_WINDOW; i++) {
            long now = 1000 + i;
            assertTrue(f.shouldSend(now, true));
            f.onSent(i, now);
        }
        assertEquals(f.window(), f.inflight());
        assertFalse(f.shouldSend(1100, true));
        assertEquals("full window must not busy-spin", FlowControl.IDLE_POLL_MS, f.pollTimeout(1100, true));
        assertEquals(FlowControl.IDLE_POLL_MS, f.pollTimeout(1100, false));
        f.onReply(1, false, 1031);
        assertEquals(target(30), f.window());
        assertTrue(f.shouldSend(1031, true));
    }

    @Test public void lossFreesSlotsAndHalvesWindowOncePerRtt() {
        FlowControl f = new FlowControl();
        long now = 1000;
        int seq = 0;
        for (int i = 0; i < 10; i++) { f.onSent(++seq, now); f.onReply(seq, true, now + 30); now += 30; }
        int halved = Math.max(FlowControl.MIN_WINDOW, f.window() / 2);
        for (int i = 0; i < 4; i++) f.onSent(++seq, now);
        for (int i = 0; i < 4; i++) f.onSent(++seq, now + 10);
        long limit = FlowControl.MIN_LOSS_MS;
        f.reap(now + limit - 1);
        assertEquals(8, f.inflight());
        f.reap(now + limit + 1);
        assertEquals(4, f.inflight());
        assertEquals(halved, f.window());
        f.reap(now + limit + 11);
        assertEquals(0, f.inflight());
        assertEquals(8, f.lost());
        assertEquals(halved, f.window());
        f.onSent(++seq, now + limit + 100);
        f.reap(now + 2 * limit + 200);
        assertEquals(Math.max(FlowControl.MIN_WINDOW, halved / 2), f.window());
    }

    @Test public void windowNeverBelowMinimum() {
        FlowControl f = new FlowControl();
        long now = 1000;
        for (int round = 0; round < 10; round++) {
            f.onSent(round + 1, now);
            now += 5000;
            f.reap(now);
        }
        assertEquals(FlowControl.MIN_WINDOW, f.window());
        assertEquals(0, f.inflight());
    }

    @Test public void unknownDuplicateAndWrappedRepliesAreSafe() {
        FlowControl f = new FlowControl();
        f.onReply(77, true, 1000);
        assertEquals(0, f.inflight());
        assertEquals("unknown reply does not grow window", FlowControl.INITIAL_WINDOW, f.window());
        f.onSent(65535, 1000);
        f.onSent(0, 1001);
        f.onReply(65535, false, 1010);
        int measuredWindow = f.window();
        long measuredRtt = f.srtt();
        f.onReply(65535, true, 1011);
        assertEquals(1, f.inflight());
        assertEquals(measuredWindow, f.window());
        assertEquals(measuredRtt, f.srtt());
        f.onReply(0, false, 1012);
        assertEquals(0, f.inflight());
    }

    @Test public void staleReplyCannotFreeReusedSlot() {
        FlowControl f = new FlowControl();
        f.onSent(5, 1000);
        f.onSent(5 + FlowControl.SLOTS, 1001);
        assertEquals(1, f.inflight());
        assertEquals(1, f.lost());
        int afterLoss = f.window();
        assertEquals(Math.max(FlowControl.MIN_WINDOW, FlowControl.INITIAL_WINDOW / 2), afterLoss);
        f.onReply(5, true, 1010);
        assertEquals(1, f.inflight());
        assertEquals("stale reply must not grow window", afterLoss, f.window());
        assertEquals(0, f.srtt());
        f.onReply(5 + FlowControl.SLOTS, false, 1011);
        assertEquals(0, f.inflight());
        assertEquals("first measurement after known loss cannot re-bootstrap", afterLoss + 1, f.window());
    }

    @Test public void slotOverwriteLossAlsoHalvesWindow() {
        FlowControl f = new FlowControl();
        f.onSent(1, 0);
        f.onReply(1, true, 3000);
        assertEquals("BDP cannot exceed hard cap", FlowControl.MAX_WINDOW, f.window());
        f.onSent(2, 3001);
        f.onSent(2 + FlowControl.SLOTS, 3002);
        assertEquals(1, f.lost());
        assertEquals(1, f.inflight());
        assertEquals(FlowControl.MAX_WINDOW / 2, f.window());
        f.onReply(2, true, 6001);
        assertEquals(1, f.inflight());
        assertEquals(FlowControl.MAX_WINDOW / 2, f.window());
    }

    @Test public void pollTimeoutIsZeroWhenSendableAndBoundedOtherwise() {
        FlowControl f = new FlowControl();
        assertEquals(0, f.pollTimeout(1000, false));
        f.onSent(1, 1000);
        assertEquals(FlowControl.IDLE_POLL_MS, f.pollTimeout(1000, false));
        assertEquals(5, f.pollTimeout(1015, false));
        assertEquals(0, f.pollTimeout(1015, true));
        assertEquals("tokens left: upload sendable now", 0, f.pollTimeout(1000, true));
    }
}
