package org.nousresearch.icmpvpn;

import android.app.Activity;
import android.os.Bundle;
import android.test.ActivityInstrumentationTestCase2;
import android.view.View;
import android.widget.*;
import java.lang.reflect.Field;
import java.lang.reflect.Method;
import java.util.Arrays;

@SuppressWarnings("deprecation")
public final class ProfileUiTest extends ActivityInstrumentationTestCase2<MainActivity> {
    public ProfileUiTest() { super(MainActivity.class); }
    @Override protected void setUp() throws Exception {
        super.setUp();assertFalse(SessionGate.busy());
        KeyStoreConfig.prefs(getInstrumentation().getTargetContext()).edit().clear().commit();
    }
    @Override protected void tearDown() throws Exception {
        SessionGate.finished();super.tearDown();
        KeyStoreConfig.prefs(getInstrumentation().getTargetContext()).edit().clear().commit();
    }
    private Object field(MainActivity activity,String name) throws Exception { Field f=MainActivity.class.getDeclaredField(name);f.setAccessible(true);return f.get(activity); }
    private void set(MainActivity activity,String name,Object value) throws Exception { Field f=MainActivity.class.getDeclaredField(name);f.setAccessible(true);f.set(activity,value); }
    private void refresh(MainActivity activity) throws Exception { Method m=MainActivity.class.getDeclaredMethod("refreshControls");m.setAccessible(true);m.invoke(activity); }
    private interface UiAction { void run() throws Exception; }
    private void ui(UiAction action) throws Throwable {
        final Throwable[] failure={null};getInstrumentation().runOnMainSync(() -> { try { action.run(); } catch(Throwable e) { failure[0]=e; } });
        getInstrumentation().waitForIdleSync();if(failure[0]!=null) throw failure[0];
    }
    public void testSaveNewBlankKeyIsolationAndBusyControls() throws Throwable {
        MainActivity activity=getActivity();String hex=new String(new char[32]).replace("\0","19");
        ui(() -> {
            ((EditText)field(activity,"name")).setText("配置 A");((EditText)field(activity,"server")).setText("192.0.2.1");
            ((EditText)field(activity,"psk")).setText(hex);((Button)field(activity,"save")).performClick();
        });
        Profile a=ProfileStore.read(activity).selected();assertNotNull(a);
        ui(() -> {
            EditText key=(EditText)field(activity,"psk");assertEquals(0,key.length());assertFalse(key.isSaveEnabled());
            assertEquals(View.IMPORTANT_FOR_AUTOFILL_NO_EXCLUDE_DESCENDANTS,key.getImportantForAutofill());
            ((Button)field(activity,"create")).performClick();assertEquals(0,key.length());
            assertEquals("1.1.1.1",((EditText)field(activity,"dns")).getText().toString());
            ((EditText)field(activity,"name")).setText("配置 B");((EditText)field(activity,"server")).setText("192.0.2.2");
            ((Button)field(activity,"save")).performClick();
        });
        assertEquals(1,ProfileStore.read(activity).profiles.size());assertEquals(a.id,ProfileStore.read(activity).selectedId);
        ui(() -> {
            ((EditText)field(activity,"psk")).setText(new String(new char[32]).replace("\0","72"));
            ((Button)field(activity,"save")).performClick();
        });
        Profile b=ProfileStore.read(activity).selected();assertFalse(a.id.equals(b.id));assertFalse(Arrays.equals(KeyStoreConfig.decrypt(a),KeyStoreConfig.decrypt(b)));
        String lease=ProfileStore.reserveSelected(activity);
        ui(() -> {
            refresh(activity);
            for(String control:new String[]{"profiles","name","server","dns","psk","create","save","delete","start"}) assertFalse(control,((View)field(activity,control)).isEnabled());
            assertTrue(((Button)field(activity,"stop")).isEnabled());
        });
        SessionGate.cancelConsent(lease);
    }
    public void testStaleConsentResultIgnoredAndSavedStateHasNoKey() throws Throwable {
        byte[] key=new byte[32];Arrays.fill(key,(byte)0x19);
        ProfileStore.save(getInstrumentation().getTargetContext(),null,"A","192.0.2.1","1.1.1.1",key);
        MainActivity activity=getActivity();String lease=ProfileStore.reserveSelected(activity);
        ui(() -> {
            set(activity,"consentLease",lease);set(activity,"pendingRequest",42);set(activity,"nextConsentRequest",43);
            ((EditText)field(activity,"psk")).setText(new String(new char[32]).replace("\0","72"));
            Bundle saved=new Bundle();activity.onSaveInstanceState(saved);assertEquals(43,saved.getInt("nextConsentRequest"));
            assertFalse(saved.toString().contains(new String(new char[32]).replace("\0","72")));
            activity.onActivityResult(41,Activity.RESULT_OK,null);assertEquals(SessionGate.State.CONSENT,SessionGate.state());
            activity.onActivityResult(42,Activity.RESULT_CANCELED,null);assertFalse(SessionGate.busy());
            activity.onActivityResult(42,Activity.RESULT_OK,null);assertFalse(SessionGate.busy());
        });
    }
}
