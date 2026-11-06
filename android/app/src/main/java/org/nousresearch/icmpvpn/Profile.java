package org.nousresearch.icmpvpn;

import java.util.UUID;

/** Immutable stored profile. Only ciphertext, never a plaintext key. */
final class Profile {
    static final int MAX_NAME=64, MAX_PROFILES=64;
    final String id,name,server,dns,iv,encrypted;
    final int keyFormat;

    Profile(String id,String name,String server,String dns,String iv,String encrypted,int keyFormat) {
        if(id==null || !UUID.fromString(id).toString().equals(id)) throw new IllegalArgumentException("Invalid profile ID");
        validateFields(name,server,dns);
        if(iv==null || iv.length()>32 || encrypted==null || encrypted.length()>128 || (keyFormat!=1 && keyFormat!=2))
            throw new IllegalArgumentException("Invalid encrypted key");
        this.id=id;this.name=name;this.server=server;this.dns=dns;this.iv=iv;this.encrypted=encrypted;this.keyFormat=keyFormat;
    }
    static void validateFields(String name,String server,String dns) {
        if(name==null || name.isEmpty() || name.length()>MAX_NAME || !name.equals(name.trim())) throw new IllegalArgumentException("Name must have 1–64 characters");
        for(int i=0;i<name.length();i++) if(Character.isISOControl(name.charAt(i))) throw new IllegalArgumentException("Invalid name");
        Config.ipv4(server);Config.ipv4(dns);
    }
    @Override public String toString() { return name+" — "+server; }
}
