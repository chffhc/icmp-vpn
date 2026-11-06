package org.nousresearch.icmpvpn;

/** Pure bounded connection policy for satellite paths; no Android dependencies. */
public final class RetryPolicy {
    public static final long HELLO_TIMEOUT_MS = 20000, RESPONSE_TIMEOUT_MS = 60000;
    private int failures;
    public boolean timedOut(boolean connected, long now, long began, long lastAuth) {
        return connected ? now-lastAuth>RESPONSE_TIMEOUT_MS : now-began>HELLO_TIMEOUT_MS;
    }
    public long nextDelay() {
        long delay = Math.min(30000, 2000L << Math.min(4, failures));
        failures = Math.min(4, failures+1);
        return delay;
    }
    public void authenticated() { failures=0; }
}
