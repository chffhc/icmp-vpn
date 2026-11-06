package org.nousresearch.icmpvpn;

import org.junit.Test;
import org.junit.After;
import java.util.*;
import java.io.IOException;
import static org.junit.Assert.*;

public final class ProfileModelTest {
    private Profile profile(int number) { return new Profile(new UUID(0,number).toString(),"Server "+number,"192.0.2.1","1.1.1.1","iv","encrypted",2); }
    @After public void reset() { SessionGate.finished(); }
    @Test public void roundTripSelectionAndStableIds() throws Exception {
        Profile a=profile(1),b=profile(2);ProfileList list=new ProfileList(Arrays.asList(a,b),b.id);
        ProfileList loaded=ProfileList.decode(list.encode());assertEquals(b.id,loaded.selectedId);assertEquals(2,loaded.profiles.size());
        assertEquals(list.encode(),loaded.encode());assertEquals(a.name,loaded.get(a.id).name);
        Profile rename=new Profile(a.id,b.name,"192.0.2.8","8.8.8.8",a.iv,a.encrypted,2);
        loaded=loaded.save(rename,false);assertEquals(2,loaded.profiles.size());assertEquals(a.id,loaded.selectedId);assertEquals(b.id,loaded.profiles.get(1).id);
    }
    @Test public void deletingSelectionHasDeterministicFallback() {
        Profile a=profile(1),b=profile(2);ProfileList list=new ProfileList(Arrays.asList(a,b),b.id);
        list=list.delete(b.id);assertEquals(a.id,list.selectedId);list=list.delete(a.id);assertNull(list.selectedId);assertTrue(list.profiles.isEmpty());
    }
    @Test public void invalidModelsFailClosed() {
        Profile a=profile(1);
        assertThrows(IllegalArgumentException.class,() -> new ProfileList(Arrays.asList(a,a),a.id));
        assertThrows(IllegalArgumentException.class,() -> new ProfileList(Collections.singletonList(a),profile(2).id));
        assertThrows(IllegalArgumentException.class,() -> new ProfileList(Collections.emptyList(),a.id));
        assertThrows(IllegalArgumentException.class,() -> new ProfileList(Collections.singletonList(a),a.id).save(profile(2),false));
        assertThrows(IllegalArgumentException.class,() -> new ProfileList(Collections.singletonList(a),a.id).save(a,true));
    }
    @Test public void boundsAndLiteralValidation() {
        ArrayList<Profile> entries=new ArrayList<>();for(int i=0;i<64;i++) entries.add(profile(i));
        ProfileList list=new ProfileList(entries,entries.get(0).id);assertEquals(64,list.profiles.size());
        assertThrows(IllegalArgumentException.class,() -> list.save(profile(65),true));
        for(String name:new String[]{""," "," name","name\n","x".repeat(65)})
            assertThrows(IllegalArgumentException.class,() -> Profile.validateFields(name,"192.0.2.1","1.1.1.1"));
        for(String address:new String[]{"example.com","01.2.3.4","192.0.2.256","127.0.0.1","::1","192.0.2.1 "})
            assertThrows(IllegalArgumentException.class,() -> Profile.validateFields("name",address,"1.1.1.1"));
        Profile.validateFields("服务器","192.0.2.1","1.1.1.1");
    }
    @Test public void corruptSerializationIsNotAnEmptyList() throws Exception {
        assertThrows(IOException.class,() -> ProfileList.decode("broken"));
        assertThrows(IOException.class,() -> ProfileList.decode("x".repeat(65537)));
        byte[] bytes=Base64.getDecoder().decode(new ProfileList(Collections.emptyList(),null).encode());
        bytes[3]=2;assertThrows(IOException.class,() -> ProfileList.decode(Base64.getEncoder().encodeToString(bytes)));
        byte[] valid=Base64.getDecoder().decode(new ProfileList(Collections.emptyList(),null).encode());
        assertThrows(IOException.class,() -> ProfileList.decode(Base64.getEncoder().encodeToString(Arrays.copyOf(valid,valid.length+1))));
    }
    @Test public void snapshotsAreImmutableAndNotDisplayNameBased() {
        Profile a=profile(1);ArrayList<Profile> original=new ArrayList<>();original.add(a);
        ProfileList list=new ProfileList(original,a.id);original.clear();assertEquals(1,list.profiles.size());
        assertThrows(UnsupportedOperationException.class,() -> list.profiles.clear());
        String token=SessionGate.reserve(a);assertTrue(SessionGate.launch(token));assertSame(a,SessionGate.accept(token));assertNull(SessionGate.accept(token));
        assertThrows(IllegalStateException.class,SessionGate::requireIdle);SessionGate.stopping();assertTrue(SessionGate.busy());
        SessionGate.finished();assertFalse(SessionGate.busy());assertEquals("192.0.2.1",a.server);
    }
    @Test public void cancelledConsentAndQueuedStartsCannotRevive() {
        String old=SessionGate.reserve(profile(1));SessionGate.cancelConsent(old);
        String fresh=SessionGate.reserve(profile(2));assertFalse(SessionGate.launch(old));assertNull(SessionGate.accept(old));
        SessionGate.cancelConsent(old);assertEquals(SessionGate.State.CONSENT,SessionGate.state());
        assertTrue(SessionGate.launch(fresh));SessionGate.stopping();assertNull(SessionGate.accept(fresh));assertTrue(SessionGate.busy());
        SessionGate.finished();assertFalse(SessionGate.launch(fresh));
    }
    @Test public void failedLaunchReleasesOnlyMatchingLease() {
        String lease=SessionGate.reserve(profile(1));SessionGate.launch(lease);
        SessionGate.failedLaunch("stale");assertTrue(SessionGate.busy());SessionGate.failedLaunch(lease);assertFalse(SessionGate.busy());
    }
}
