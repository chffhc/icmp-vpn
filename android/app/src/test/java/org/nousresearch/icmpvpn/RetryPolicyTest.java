package org.nousresearch.icmpvpn;
import org.junit.Test;
import static org.junit.Assert.*;
public class RetryPolicyTest {
    @Test public void twoSecondRttHasAmpleHandshakeMargin() {
        RetryPolicy p=new RetryPolicy();
        assertFalse(p.timedOut(false,2100,100,100));
        assertFalse(p.timedOut(false,20100,100,100));
        assertTrue(p.timedOut(false,20101,100,100));
    }
    @Test public void satellitePauseAndBoundedRetry() {
        RetryPolicy p=new RetryPolicy();
        assertFalse(p.timedOut(true,45100,100,100));
        assertTrue(p.timedOut(true,60101,100,100));
        assertEquals(2000,p.nextDelay());assertEquals(4000,p.nextDelay());
        assertEquals(8000,p.nextDelay());assertEquals(16000,p.nextDelay());
        for(int i=0;i<10;i++) assertEquals(30000,p.nextDelay());
        p.authenticated();assertEquals(2000,p.nextDelay());
    }
}
