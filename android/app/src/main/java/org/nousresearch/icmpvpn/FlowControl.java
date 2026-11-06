package org.nousresearch.icmpvpn;

/**
 * Pure, single-threaded echo-request pacing and outstanding-request accounting.
 * One authenticated echo reply can return at most one downstream packet. The
 * measured bandwidth-delay product therefore bounds both upload and poll windows.
 * Call onSent only after a successful send, and onReply only after authentication
 * and protocol replay validation. Times are monotonic milliseconds, including zero.
 */
public final class FlowControl {
    public static final int MIN_WINDOW = 2, MAX_WINDOW = 8192, INITIAL_WINDOW = 8;
    public static final int IDLE_POLL_MS = 20, SLOTS = 32768;
    /** Unchanged token bucket: 3000 requests/s, at most eight on one clock tick. */
    public static final int MAX_RATE_PPS = 3000, BURST = 8;
    static final long MIN_LOSS_MS = 4000, MAX_LOSS_MS = 15000;
    private static final long MIN_BURST_MS = 40, MAX_BURST_MS = 6000;

    // Occupancy is separate from timestamps: a send at virtual/monotonic time zero is valid.
    // SLOTS divides 65536; full 16-bit equality rejects the other half-space slot alias.
    private final long[] sentAt = new long[SLOTS];
    private final int[] sentSequence = new int[SLOTS];
    private final boolean[] outstanding = new boolean[SLOTS];
    private int inflight;
    private double window = INITIAL_WINDOW, ssthresh = MAX_WINDOW;
    private double smoothedRtt, rttVariance;
    private boolean measured, backedOff;
    private double tokens = BURST;
    private long lastRefill;
    private long nextIdle, burstUntil, lastDataAt, lastBackoff = Long.MIN_VALUE / 2;
    private boolean seenData;
    private long lost;

    /** All requests, including uploads and idle polls, respect the adaptive window. */
    public boolean shouldSend(long now, boolean haveUpload) {
        if (inflight >= window() || available(now) < 1) return false;
        return haveUpload || now < burstUntil || now >= nextIdle;
    }

    /** Bounded non-spinning wait when a reply/window, rather than pacing, is needed. */
    public int pollTimeout(long now, boolean haveUpload) {
        if (shouldSend(now, haveUpload)) return 0;
        if (inflight >= window()) return IDLE_POLL_MS;
        if (haveUpload || now < burstUntil) return 1;
        return (int) Math.min(IDLE_POLL_MS, Math.max(1, nextIdle - now));
    }

    public void onSent(int echoSequence, long now) {
        int slot = echoSequence & (SLOTS - 1);
        if (outstanding[slot]) {
            inflight--;
            lost++;
            backoff(now);
        }
        outstanding[slot] = true;
        sentAt[slot] = now;
        sentSequence[slot] = echoSequence & 65535;
        inflight++;
        tokens = available(now) - 1;
        lastRefill = now;
        nextIdle = now + IDLE_POLL_MS;
    }

    /** Unknown, duplicate, half-space-alias and pre-send replies have no effects. */
    public void onReply(int echoSequence, boolean carriedData, long now) {
        int slot = echoSequence & (SLOTS - 1);
        if (!outstanding[slot] || sentSequence[slot] != (echoSequence & 65535)
                || now < sentAt[slot]) return;
        outstanding[slot] = false;
        inflight--;
        double sample = Math.max(1, now - sentAt[slot]);
        boolean firstMeasurement = !measured;
        if (firstMeasurement) {
            smoothedRtt = sample;
            rttVariance = sample / 2;
            measured = true;
        } else {
            rttVariance = 0.75 * rttVariance + 0.25 * Math.abs(smoothedRtt - sample);
            smoothedRtt = 0.875 * smoothedRtt + 0.125 * sample;
        }
        int target = targetWindow();
        if (firstMeasurement && !backedOff) {
            // An actual RTT sample permits a paced BDP, without six or more rounds
            // of exponential startup. No sample means only INITIAL_WINDOW requests.
            window = target;
        } else {
            // Empty replies acknowledge uploads too; they must participate in AIMD.
            // Additive recovery is RTT/BDP-scaled (up to 25% of target per RTT),
            // not one packet per multi-second RTT. Cap per-ACK growth at one so a
            // tiny post-loss window cannot jump by hundreds from a single reply.
            double increase = window < ssthresh ? 1
                    : Math.min(1, Math.max(1, target / 4.0) / window);
            window = Math.min(target, window + increase);
        }
        if (carriedData) {
            seenData = true;
            lastDataAt = now;
        }
        if (seenData) {
            // Empty replies can interleave or arrive out of order. They may update
            // RTT, but never refresh the data timestamp. Keep >=two measured RTTs
            // of hysteresis, capped at six seconds from the last actual data.
            long hold = Math.min(MAX_BURST_MS, Math.max(MIN_BURST_MS, 2 * srtt() + IDLE_POLL_MS));
            burstUntil = Math.max(burstUntil, lastDataAt + hold);
        }
    }

    /**
     * Expire unanswered requests; decrease once per RTT across all loss paths.
     * One bounded SLOTS scan per caller reap (20/s in TunnelService), no allocation.
     */
    public void reap(long now) {
        if (inflight == 0) return;
        long limit = lossTimeout();
        boolean anyLost = false;
        for (int slot = 0; slot < SLOTS; slot++) {
            if (outstanding[slot] && now - sentAt[slot] > limit) {
                outstanding[slot] = false;
                inflight--;
                lost++;
                anyLost = true;
            }
        }
        if (anyLost) backoff(now);
    }

    /** 10% headroom plus one pacing burst, not an RTT-independent deep queue. */
    private int targetWindow() {
        return (int) Math.min(MAX_WINDOW, Math.max(INITIAL_WINDOW,
                Math.ceil(MAX_RATE_PPS * smoothedRtt / 1000.0 * 110 / 100) + BURST));
    }

    private long lossTimeout() {
        // A 2s RTT gets >=8s; measured jitter may extend this, with a 15s bound.
        double adaptive = Math.max(4 * smoothedRtt, smoothedRtt + 4 * rttVariance + IDLE_POLL_MS);
        return (long) Math.min(MAX_LOSS_MS, Math.max(MIN_LOSS_MS, Math.ceil(adaptive)));
    }

    private double available(long now) {
        return Math.min(BURST, tokens + Math.max(0, now - lastRefill) * (MAX_RATE_PPS / 1000.0));
    }

    private void backoff(long now) {
        if (now - lastBackoff <= Math.max(srtt(), IDLE_POLL_MS)) return;
        ssthresh = Math.max(MIN_WINDOW, window / 2);
        window = ssthresh;
        backedOff = true;
        lastBackoff = now;
    }

    public int inflight() { return inflight; }
    public int window() { return Math.max(MIN_WINDOW, Math.min(MAX_WINDOW, (int) window)); }
    public long srtt() { return measured ? Math.max(1, Math.round(smoothedRtt)) : 0; }
    public long lost() { return lost; }
}
