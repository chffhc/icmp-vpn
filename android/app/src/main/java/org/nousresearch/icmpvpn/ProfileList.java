package org.nousresearch.icmpvpn;

import java.io.*;
import java.util.*;

/** Deterministic bounded model and strict versioned serialization. */
final class ProfileList {
    final List<Profile> profiles;
    final String selectedId;
    ProfileList(List<Profile> profiles,String selectedId) {
        if(profiles.size()>Profile.MAX_PROFILES) throw new IllegalArgumentException("Too many profiles");
        Set<String> ids=new HashSet<>();
        for(Profile p:profiles) if(!ids.add(p.id)) throw new IllegalArgumentException("Duplicate ID");
        if(profiles.isEmpty()?selectedId!=null:!ids.contains(selectedId)) throw new IllegalArgumentException("Invalid selection");
        this.profiles=Collections.unmodifiableList(new ArrayList<>(profiles));this.selectedId=selectedId;
    }
    Profile get(String id) {
        for(Profile p:profiles) if(p.id.equals(id)) return p;
        throw new IllegalArgumentException("Profile missing");
    }
    Profile selected() { return selectedId==null?null:get(selectedId); }
    ProfileList save(Profile profile,boolean isNew) {
        ArrayList<Profile> next=new ArrayList<>(profiles);int index=-1;
        for(int i=0;i<next.size();i++) if(next.get(i).id.equals(profile.id)) index=i;
        if(isNew) { if(index>=0) throw new IllegalArgumentException("Duplicate ID");next.add(profile); }
        else { if(index<0) throw new IllegalArgumentException("Profile missing");next.set(index,profile); }
        return new ProfileList(next,profile.id);
    }
    ProfileList select(String id) { get(id);return new ProfileList(profiles,id); }
    ProfileList delete(String id) {
        get(id);ArrayList<Profile> next=new ArrayList<>(profiles);next.removeIf(p -> p.id.equals(id));
        return new ProfileList(next,id.equals(selectedId)?(next.isEmpty()?null:next.get(0).id):selectedId);
    }
    String encode() throws IOException {
        ByteArrayOutputStream bytes=new ByteArrayOutputStream();DataOutputStream out=new DataOutputStream(bytes);
        out.writeInt(1);out.writeUTF(selectedId==null?"":selectedId);out.writeInt(profiles.size());
        for(Profile p:profiles) { out.writeUTF(p.id);out.writeUTF(p.name);out.writeUTF(p.server);out.writeUTF(p.dns);out.writeUTF(p.iv);out.writeUTF(p.encrypted);out.writeInt(p.keyFormat); }
        out.close();return Base64.getEncoder().encodeToString(bytes.toByteArray());
    }
    static ProfileList decode(String text) throws IOException {
        if(text==null || text.length()>65536) throw new IOException("Invalid profile storage");
        try {
            DataInputStream in=new DataInputStream(new ByteArrayInputStream(Base64.getDecoder().decode(text)));
            if(in.readInt()!=1) throw new IOException("Unsupported profile storage");
            String selected=in.readUTF();int count=in.readInt();if(count<0 || count>Profile.MAX_PROFILES) throw new IOException("Invalid profile count");
            ArrayList<Profile> profiles=new ArrayList<>();
            for(int i=0;i<count;i++) profiles.add(new Profile(in.readUTF(),in.readUTF(),in.readUTF(),in.readUTF(),in.readUTF(),in.readUTF(),in.readInt()));
            if(in.read()!=-1) throw new IOException("Trailing profile data");
            return new ProfileList(profiles,selected.isEmpty()?null:selected);
        } catch(IllegalArgumentException e) { throw new IOException("Invalid profile storage",e); }
    }
}
