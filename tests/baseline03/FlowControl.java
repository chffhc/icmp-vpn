package org.nousresearch.icmpvpn;

/**
 * Adaptive number of outstanding echo requests. Pure logic, no I/O, unit-tested.
 *
 * The server answers each authenticated request with at most ONE queued
 * downstream packet, so downstream throughput ~= outstanding requests / RTT.
 * The old client kept roughly one request outstanding (ping-pong), capping
 * downstream at ~1 packet per RTT. This keeps a window of requests in flight
 * while replies carry data, idles at one poll per 20 ms otherwise, and backs
 * off on loss (ICMP rate limiting/filtering) like TCP slow start + AIMD.
 *
 * Requests are matched to replies by the 16-bit ICMP echo sequence, which the
 * server mirrors. Only AUTHENTICATED replies may call onReply; the server
 * kernel's own plain echo replies never count.
 */
public final class FlowControl {
    public static final int MIN_WINDOW = 2, MAX_WINDOW = 256, INITIAL_WINDOW = 4;
    public static final int IDLE_POLL_MS = 20, SLOTS = 4096; // SLOTS divides 65536; >> MAX_WINDOW so slot reuse means real loss
    /** Token-bucket pacing: sustained request rate and largest same-millisecond burst. */
    public static final int MAX_RATE_PPS = 3000, BURST = 8;
    static final long MIN_LOSS_MS = 1000, MAX_LOSS_MS = 3000;

    private final long[] sentAt = new long[SLOTS]; // 0 = slot free
    private final int[] sentSequence = new int[SLOTS];
    private int inflight;
    private double window = INITIAL_WINDOW, ssthresh = MAX_WINDOW;
    private long srtt; // smoothed RTT in ms, 0 = no sample yet
    private double tokens = BURST;
    private long lastRefill;
    private long nextIdle, burstUntil, lastBackoff = Long.MIN_VALUE / 2;
    private long lost;

    /** May one more request be sent now? */
    public boolean shouldSend(long now, boolean haveUpload) {
        if (available(now) < 1 || inflight >= MAX_WINDOW) return false;          // hard cap, even for uploads
        if (haveUpload) return true;                        // uploads go out immediately
        if (now < burstUntil && inflight < (int) window) return true; // server queue likely non-empty
        return now >= nextIdle;                             // idle keepalive / pickup poll
    }

    /** Milliseconds the I/O loop may sleep in poll() before it must call shouldSend again. */
    public int pollTimeout(long now, boolean haveUpload) {
        if (shouldSend(now, haveUpload)) return 0;
        if (inflight >= MAX_WINDOW) return IDLE_POLL_MS; // no zero-timeout spin at hard cap
        if (haveUpload || (now < burstUntil && inflight < (int) window)) {
            return 1; // only the token bucket is holding us back: refills within 1 ms
        }
        long wait = Math.max(1, nextIdle - now);
        return (int) Math.min(IDLE_POLL_MS, wait);
    }

    public void onSent(int echoSequence, long now) {
        int slot = echoSequence & (SLOTS - 1);
        if (sentAt[slot] != 0) { inflight--; lost++; backoff(now); } // 1024 sends ago and never answered: a real loss
        sentAt[slot] = now == 0 ? 1 : now;
        sentSequence[slot] = echoSequence & 65535;
        inflight++;
        tokens = available(now) - 1; // at most MAX_RATE_PPS sustained, BURST per millisecond
        lastRefill = now;
        nextIdle = now + IDLE_POLL_MS;
    }

    /** Call only for an authenticated reply. carriedData = reply held a downstream IP packet. */
    public void onReply(int echoSequence, boolean carriedData, long now) {
        int slot = echoSequence & (SLOTS - 1);
        long sent = sentAt[slot];
        if (sent == 0 || sentSequence[slot] != (echoSequence & 65535)) return;
        {
            sentAt[slot] = 0;
            inflight--;
            long sample = Math.max(1, now - sent);
            srtt = srtt == 0 ? sample : (7 * srtt + sample) / 8;
        }
        if (carriedData) {
            window = Math.min(MAX_WINDOW, window < ssthresh ? window + 1 : window + 1.0 / window);
            burstUntil = now + Math.min(1000, Math.max(40, 2 * srtt + IDLE_POLL_MS));
        } else {
            burstUntil = 0; // server queue was empty when it answered
        }
    }

    /** Expire unanswered requests as lost; halve the window at most once per RTT. */
    public void reap(long now) {
        long limit = Math.min(MAX_LOSS_MS, Math.max(MIN_LOSS_MS, 4 * srtt));
        boolean anyLost = false;
        for (int i = 0; i < SLOTS; i++) {
            if (sentAt[i] != 0 && now - sentAt[i] > limit) { sentAt[i] = 0; inflight--; lost++; anyLost = true; }
        }
        if (anyLost) backoff(now);
    }

    private double available(long now) {
        return Math.min(BURST, tokens + Math.max(0, now - lastRefill) * (MAX_RATE_PPS / 1000.0));
    }

    /** Multiplicative decrease, at most once per RTT, shared by every loss-detection path. */
    private void backoff(long now) {
        if (now - lastBackoff <= Math.max(srtt, IDLE_POLL_MS)) return;
        ssthresh = Math.max(MIN_WINDOW, window / 2);
        window = ssthresh;
        lastBackoff = now;
    }

    public int inflight() { return inflight; }
    public int window() { return (int) window; }
    public long srtt() { return srtt; }
    public long lost() { return lost; }
}
