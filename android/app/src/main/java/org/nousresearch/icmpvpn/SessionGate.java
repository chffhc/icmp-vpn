package org.nousresearch.icmpvpn;

import java.util.UUID;

/** Process-local launch lease: no secrets in Intents or saved instance state.
 * Process death invalidates consent/launch leases. Store mutations use this same monitor.
 */
final class SessionGate {
    enum State { IDLE, CONSENT, STARTING, ACTIVE, STOPPING }
    private static State state=State.IDLE;
    private static String token;
    private static Profile snapshot;
    static synchronized State state() { return state; }
    static synchronized boolean busy() { return state!=State.IDLE; }
    static synchronized void requireIdle() { if(busy()) throw new IllegalStateException("Stop VPN before changing profiles"); }
    static synchronized String reserve(Profile profile) {
        requireIdle();if(profile==null) throw new IllegalArgumentException("Select a profile");
        snapshot=profile;token=UUID.randomUUID().toString();state=State.CONSENT;return token;
    }
    static synchronized boolean launch(String lease) {
        if(state!=State.CONSENT || !matches(lease)) return false;state=State.STARTING;return true;
    }
    static synchronized Profile accept(String lease) {
        if(state!=State.STARTING || !matches(lease)) return null;state=State.ACTIVE;return snapshot;
    }
    static synchronized void cancelConsent(String lease) {
        if(state==State.CONSENT && matches(lease)) clear();
    }
    static synchronized void failedLaunch(String lease) {
        if(state==State.STARTING && matches(lease)) clear();
    }
    static synchronized void stopping() {
        // A queued START carrying an old token must never revive a cancelled launch.
        if(state!=State.IDLE) { state=State.STOPPING;token=null; }
    }
    static synchronized void finished() { clear(); }
    private static boolean matches(String lease) { return lease!=null && lease.equals(token); }
    private static void clear() { state=State.IDLE;token=null;snapshot=null; }
}
