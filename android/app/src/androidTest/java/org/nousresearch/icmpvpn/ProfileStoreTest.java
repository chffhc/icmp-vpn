package org.nousresearch.icmpvpn;

import android.content.Context;
import android.content.SharedPreferences;
import android.test.InstrumentationTestCase;
import android.util.Base64;
import java.security.KeyStore;
import java.util.*;
import javax.crypto.Cipher;
import javax.crypto.SecretKey;

/** Disposable test app data only. Never run against an installation containing real profiles. */
@SuppressWarnings("deprecation")
public final class ProfileStoreTest extends InstrumentationTestCase {
    private Context context;
    private byte[] a,b;
    @Override protected void setUp() throws Exception {
        super.setUp();context=getInstrumentation().getTargetContext();
        assertFalse("Stop service before profile tests",SessionGate.busy());
        KeyStoreConfig.prefs(context).edit().clear().commit();
        a=new byte[32];b=new byte[32];Arrays.fill(a,(byte)0x19);Arrays.fill(b,(byte)0x72);
    }
    @Override protected void tearDown() throws Exception {
        SessionGate.finished();KeyStoreConfig.prefs(context).edit().clear().commit();
        Arrays.fill(a,(byte)0);Arrays.fill(b,(byte)0);super.tearDown();
    }
    private Profile add(String name,String ip,byte[] key) throws Exception { return ProfileStore.save(context,null,name,ip,"1.1.1.1",key).selected(); }
    private interface Action { void run() throws Exception; }
    private void rejects(Action action) throws Exception { try { action.run();fail("Must fail closed"); } catch(Exception expected) { } }
    public void testTwoKeysBlankEditsSelectionPersistenceDelete() throws Exception {
        Profile first=add("同名","192.0.2.1",a),second=add("同名","192.0.2.2",b);
        assertFalse(first.id.equals(second.id));assertTrue(Arrays.equals(a,KeyStoreConfig.decrypt(first)));assertTrue(Arrays.equals(b,KeyStoreConfig.decrypt(second)));
        ProfileStore.select(context,first.id);
        Profile edited=ProfileStore.save(context,first.id,"改名","192.0.2.3","8.8.8.8",null).selected();
        assertEquals(first.encrypted,edited.encrypted);assertTrue(Arrays.equals(a,KeyStoreConfig.load(context)));
        assertTrue(Arrays.equals(b,KeyStoreConfig.decrypt(ProfileStore.read(context).get(second.id))));
        Context fresh=context.createPackageContext(context.getPackageName(),0);
        assertEquals(first.id,ProfileStore.read(fresh).selectedId);
        ProfileStore.delete(context,first.id);assertEquals(second.id,ProfileStore.read(fresh).selectedId);
        assertTrue(Arrays.equals(b,KeyStoreConfig.load(context)));
        ProfileStore.delete(context,second.id);assertTrue(ProfileStore.read(context).profiles.isEmpty());
        rejects(() -> ProfileStore.save(context,null,"new","192.0.2.9","1.1.1.1",null));
    }
    public void testNewProfileNeverInheritsKeyAndRemovedIdCannotBeEdited() throws Exception {
        Profile first=add("A","192.0.2.1",a);
        rejects(() -> ProfileStore.save(context,null,"B","192.0.2.2","1.1.1.1",null));
        ProfileStore.delete(context,first.id);
        rejects(() -> ProfileStore.save(context,first.id,"A","192.0.2.1","1.1.1.1",b));
    }
    public void testNoPlaintextKeyAndProfileIdBindsCiphertext() throws Exception {
        Profile first=add("A","192.0.2.1",a),second=add("B","192.0.2.2",b);
        SharedPreferences prefs=KeyStoreConfig.prefs(context);
        assertFalse(prefs.contains("psk"));assertFalse(prefs.contains("psk_encrypted"));
        String stored=prefs.getString(ProfileStore.DATA,null);
        String decoded=new String(java.util.Base64.getDecoder().decode(stored),java.nio.charset.StandardCharsets.ISO_8859_1);
        String hex=new String(new char[32]).replace("\0","19"),raw=new String(a,java.nio.charset.StandardCharsets.ISO_8859_1);
        assertFalse(stored.contains(hex));assertFalse(decoded.contains(hex));assertFalse(decoded.contains(raw));assertFalse(decoded.contains(Base64.encodeToString(a,Base64.NO_WRAP)));
        Profile swapped=new Profile(second.id,second.name,second.server,second.dns,first.iv,first.encrypted,2);
        rejects(() -> KeyStoreConfig.decrypt(swapped));
    }
    private String[] seedLegacy() throws Exception {
        // Ensure the existing v1 alias exists, then encrypt with the exact v0.5 no-AAD format.
        add("temporary","192.0.2.1",a);
        KeyStore ks=KeyStore.getInstance("AndroidKeyStore");ks.load(null);
        Cipher cipher=Cipher.getInstance("AES/GCM/NoPadding");cipher.init(Cipher.ENCRYPT_MODE,(SecretKey)ks.getKey("icmp-vpn-psk-v1",null));
        String iv=Base64.encodeToString(cipher.getIV(),Base64.NO_WRAP),encrypted=Base64.encodeToString(cipher.doFinal(a),Base64.NO_WRAP);
        assertTrue(KeyStoreConfig.prefs(context).edit().clear().putString("server","192.0.2.1").putString("dns","8.8.8.8").putString("iv",iv).putString("psk_encrypted",encrypted).commit());
        return new String[]{iv,encrypted};
    }
    public void testLegacyMigrationPreservesExactEncryptedKeyAndIsIdempotent() throws Exception {
        String[] original=seedLegacy();ProfileList migrated=ProfileStore.read(context);Profile profile=migrated.selected();
        assertEquals(1,migrated.profiles.size());assertEquals(original[0],profile.iv);assertEquals(original[1],profile.encrypted);assertEquals(1,profile.keyFormat);
        assertEquals("8.8.8.8",profile.dns);assertTrue(Arrays.equals(a,KeyStoreConfig.load(context)));
        assertFalse(KeyStoreConfig.prefs(context).contains("server"));assertFalse(KeyStoreConfig.prefs(context).contains("psk_encrypted"));
        assertEquals(profile.id,ProfileStore.read(context).selectedId);
        add("B","192.0.2.2",b);ProfileStore.select(context,profile.id);assertTrue(Arrays.equals(a,KeyStoreConfig.load(context)));
    }
    public void testIncompleteAndCorruptedLegacyPreservedWithoutMigration() throws Exception {
        for(String missing:new String[]{"server","dns","iv","psk_encrypted"}) {
            KeyStoreConfig.prefs(context).edit().clear().commit();seedLegacy();
            KeyStoreConfig.prefs(context).edit().remove(missing).commit();Map<String,?> before=KeyStoreConfig.prefs(context).getAll();
            rejects(() -> ProfileStore.read(context));assertEquals(before,KeyStoreConfig.prefs(context).getAll());
        }
        KeyStoreConfig.prefs(context).edit().clear().commit();seedLegacy();
        KeyStoreConfig.prefs(context).edit().putString("psk_encrypted",Base64.encodeToString(new byte[48],Base64.NO_WRAP)).commit();
        Map<String,?> before=KeyStoreConfig.prefs(context).getAll();rejects(() -> ProfileStore.read(context));assertEquals(before,KeyStoreConfig.prefs(context).getAll());
    }
    public void testCorruptedListOrLostListNeverSilentlyReset() throws Exception {
        add("A","192.0.2.1",a);SharedPreferences prefs=KeyStoreConfig.prefs(context);String valid=prefs.getString(ProfileStore.DATA,null);
        prefs.edit().putString(ProfileStore.DATA,"broken").commit();rejects(() -> ProfileStore.read(context));assertEquals("broken",prefs.getString(ProfileStore.DATA,null));
        prefs.edit().remove(ProfileStore.DATA).commit();rejects(() -> ProfileStore.read(context));assertFalse(prefs.contains(ProfileStore.DATA));
        prefs.edit().putString(ProfileStore.DATA,valid).remove(ProfileStore.INITIALIZED).commit();rejects(() -> ProfileStore.read(context));
        prefs.edit().putBoolean(ProfileStore.INITIALIZED,true).commit();Profile first=ProfileStore.read(context).selected();
        Profile corrupt=new Profile(first.id,first.name,first.server,first.dns,first.iv,Base64.encodeToString(new byte[48],Base64.NO_WRAP),2);
        String broken=new ProfileList(Collections.singletonList(corrupt),corrupt.id).encode();prefs.edit().putString(ProfileStore.DATA,broken).commit();
        rejects(() -> ProfileStore.read(context));rejects(() -> ProfileStore.save(context,first.id,"repair","192.0.2.1","1.1.1.1",b));assertEquals(broken,prefs.getString(ProfileStore.DATA,null));
    }
    public void testImmutableConnectionSnapshotAndMutationInterlock() throws Exception {
        Profile first=add("A","192.0.2.1",a),second=add("B","192.0.2.2",b);ProfileStore.select(context,first.id);
        String token=ProfileStore.reserveSelected(context);
        rejects(() -> ProfileStore.select(context,second.id));rejects(() -> ProfileStore.delete(context,first.id));
        rejects(() -> ProfileStore.save(context,first.id,"changed","192.0.2.3","8.8.8.8",b));
        assertTrue(SessionGate.launch(token));Profile snapshot=SessionGate.accept(token);assertNotNull(snapshot);
        // Simulate out-of-band preferences modification: reconnect still uses captured ciphertext/DNS/IP.
        ProfileList changed=new ProfileList(Collections.singletonList(second),second.id);
        KeyStoreConfig.prefs(context).edit().putString(ProfileStore.DATA,changed.encode()).commit();
        assertEquals(first.id,snapshot.id);assertEquals("192.0.2.1",snapshot.server);assertEquals("1.1.1.1",snapshot.dns);assertTrue(Arrays.equals(a,KeyStoreConfig.decrypt(snapshot)));
        SessionGate.stopping();rejects(() -> ProfileStore.select(context,second.id));SessionGate.finished();assertEquals(second.id,ProfileStore.read(context).selectedId);
    }
}
