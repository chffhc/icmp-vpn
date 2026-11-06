package org.nousresearch.icmpvpn;
import android.content.Context;
import android.content.SharedPreferences;
import android.security.keystore.KeyGenParameterSpec;
import android.security.keystore.KeyProperties;
import android.util.Base64;
import java.nio.charset.StandardCharsets;
import java.security.KeyStore;
import java.util.Arrays;
import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;

final class KeyStoreConfig {
    private static final String ALIAS="icmp-vpn-psk-v1";
    static SharedPreferences prefs(Context c) { return c.getSharedPreferences("vpn",Context.MODE_PRIVATE); }
    private static synchronized SecretKey key(boolean create) throws Exception {
        KeyStore ks=KeyStore.getInstance("AndroidKeyStore");ks.load(null);
        if(ks.containsAlias(ALIAS)) return (SecretKey)ks.getKey(ALIAS,null);
        if(!create) throw new IllegalStateException("Saved encryption key unavailable");
        KeyGenerator gen=KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_AES,"AndroidKeyStore");
        gen.init(new KeyGenParameterSpec.Builder(ALIAS,KeyProperties.PURPOSE_ENCRYPT|KeyProperties.PURPOSE_DECRYPT)
            .setKeySize(256).setBlockModes(KeyProperties.BLOCK_MODE_GCM).setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE).build());
        return gen.generateKey();
    }
    static Profile encrypt(String id,String name,String server,String dns,byte[] psk) throws Exception {
        if(psk==null || psk.length!=32) throw new IllegalArgumentException("Invalid key length");
        Profile.validateFields(name,server,dns);
        Cipher cipher=Cipher.getInstance("AES/GCM/NoPadding");cipher.init(Cipher.ENCRYPT_MODE,key(true));
        cipher.updateAAD(id.getBytes(StandardCharsets.UTF_8));
        byte[] ciphertext=cipher.doFinal(psk);
        try { return new Profile(id,name,server,dns,Base64.encodeToString(cipher.getIV(),Base64.NO_WRAP),Base64.encodeToString(ciphertext,Base64.NO_WRAP),2); }
        finally { Arrays.fill(ciphertext,(byte)0); }
    }
    static byte[] decrypt(Profile profile) throws Exception {
        byte[] iv=Base64.decode(profile.iv,Base64.NO_WRAP),encrypted=Base64.decode(profile.encrypted,Base64.NO_WRAP);
        if(iv.length!=12 || encrypted.length!=48) throw new IllegalStateException("Invalid encrypted key");
        Cipher cipher=Cipher.getInstance("AES/GCM/NoPadding");cipher.init(Cipher.DECRYPT_MODE,key(false),new GCMParameterSpec(128,iv));
        if(profile.keyFormat==2) cipher.updateAAD(profile.id.getBytes(StandardCharsets.UTF_8));
        byte[] psk=cipher.doFinal(encrypted);
        if(psk.length!=32) { Arrays.fill(psk,(byte)0);throw new IllegalStateException("Invalid stored key"); }
        return psk;
    }
    /** Compatibility for existing internal callers/tests; now saves the selected profile. */
    static void save(Context c,String server,String dns,byte[] psk) throws Exception {
        synchronized(SessionGate.class) {
            Profile selected=ProfileStore.read(c).selected();
            ProfileStore.save(c,selected==null?null:selected.id,selected==null?"默认服务器":selected.name,server,dns,psk);
        }
    }
    static byte[] load(Context c) throws Exception {
        synchronized(SessionGate.class) {
            Profile selected=ProfileStore.read(c).selected();
            if(selected==null) throw new IllegalStateException("Configure a PSK first");return decrypt(selected);
        }
    }
}
