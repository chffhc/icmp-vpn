package org.nousresearch.icmpvpn;

import android.content.Context;
import android.content.SharedPreferences;
import java.util.*;

/** One atomic preferences transaction holds list, selection and migration marker.
 * Never recover malformed/missing initialized data by replacing it with an empty list.
 */
final class ProfileStore {
    static final String DATA="profiles_v1", INITIALIZED="profiles_initialized";
    private static boolean writeFailed;
    static ProfileList read(Context context) throws Exception {
        synchronized(SessionGate.class) {
            if(writeFailed) throw new IllegalStateException("Persistence failed; restart app");
            SharedPreferences prefs=KeyStoreConfig.prefs(context);
            if(prefs.contains(DATA) || prefs.contains(INITIALIZED)) {
                if(!prefs.contains(DATA) || !prefs.getBoolean(INITIALIZED,false)) throw new IllegalStateException("Profile storage incomplete");
                ProfileList list=ProfileList.decode(prefs.getString(DATA,null));validateKeys(list);return list;
            }
            boolean any=prefs.contains("server") || prefs.contains("dns") || prefs.contains("iv") || prefs.contains("psk_encrypted");
            ProfileList list;
            if(any) {
                // v0.5 saves all four together; any partial state is an error, not a fresh installation.
                for(String field:new String[]{"server","dns","iv","psk_encrypted"})
                    if(!prefs.contains(field)) throw new IllegalStateException("Incomplete legacy configuration");
                Profile migrated=new Profile(UUID.randomUUID().toString(),"默认服务器（已迁移）",prefs.getString("server",null),prefs.getString("dns",null),prefs.getString("iv",null),prefs.getString("psk_encrypted",null),1);
                list=new ProfileList(Collections.singletonList(migrated),migrated.id);validateKeys(list);
            } else list=new ProfileList(Collections.emptyList(),null);
            // Validate and decrypt BEFORE any legacy removal. The single commit is atomic on disk.
            persist(context,list,true);return list;
        }
    }
    private static void validateKeys(ProfileList list) throws Exception {
        for(Profile profile:list.profiles) { byte[] key=KeyStoreConfig.decrypt(profile);Arrays.fill(key,(byte)0); }
    }
    private static void persist(Context context,ProfileList list,boolean migrating) throws Exception {
        SharedPreferences.Editor edit=KeyStoreConfig.prefs(context).edit().putString(DATA,list.encode()).putBoolean(INITIALIZED,true);
        if(migrating) edit.remove("server").remove("dns").remove("iv").remove("psk_encrypted");
        if(!edit.commit()) { writeFailed=true;throw new IllegalStateException("Could not persist profiles"); }
    }
    static ProfileList save(Context c,String id,String name,String server,String dns,byte[] newKey) throws Exception {
        synchronized(SessionGate.class) {
            SessionGate.requireIdle();ProfileList list=read(c);boolean isNew=id==null;
            Profile.validateFields(name,server,dns);
            if(isNew && list.profiles.size()>=Profile.MAX_PROFILES) throw new IllegalArgumentException("最多保存 64 个配置");
            Profile old=isNew?null:list.get(id);String target=isNew?UUID.randomUUID().toString():id;
            if(newKey==null && old==null) throw new IllegalArgumentException("新配置必须填写 PSK");
            Profile next=newKey==null?new Profile(target,name,server,dns,old.iv,old.encrypted,old.keyFormat):KeyStoreConfig.encrypt(target,name,server,dns,newKey);
            list=list.save(next,isNew);persist(c,list,false);return list;
        }
    }
    static ProfileList select(Context c,String id) throws Exception {
        synchronized(SessionGate.class) { SessionGate.requireIdle();ProfileList list=read(c).select(id);persist(c,list,false);return list; }
    }
    static ProfileList delete(Context c,String id) throws Exception {
        synchronized(SessionGate.class) { SessionGate.requireIdle();ProfileList list=read(c).delete(id);persist(c,list,false);return list; }
    }
    static String reserveSelected(Context c) throws Exception {
        synchronized(SessionGate.class) { SessionGate.requireIdle();return SessionGate.reserve(read(c).selected()); }
    }
}
