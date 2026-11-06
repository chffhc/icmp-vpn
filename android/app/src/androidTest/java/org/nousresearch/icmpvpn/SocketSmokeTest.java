package org.nousresearch.icmpvpn;

import android.test.InstrumentationTestCase;
import android.content.Context;
import android.content.ComponentName;
import android.content.pm.ServiceInfo;
import android.net.VpnService;
import android.os.Process;
import android.system.*;
import java.io.FileDescriptor;
import java.net.InetAddress;
import java.util.Arrays;

/** Emulator smoke only: no claim of physical-device or WAN end-to-end coverage. */
@SuppressWarnings("deprecation")
public final class SocketSmokeTest extends InstrumentationTestCase {
    public void testUnrootedAppUidPingSocketLoopback() throws Exception {
        assertTrue("Must execute as app UID, not shell or root",Process.myUid()>=10000);
        FileDescriptor fd=Os.socket(OsConstants.AF_INET,OsConstants.SOCK_DGRAM|OsConstants.O_NONBLOCK,OsConstants.IPPROTO_ICMP);
        try {
            Os.connect(fd,InetAddress.getByAddress(new byte[]{127,0,0,1}),0);
            byte[] payload="unrooted-app-icmp-smoke".getBytes(java.nio.charset.StandardCharsets.US_ASCII);
            byte[] request=Protocol.echo(payload,17);assertEquals(request.length,Os.write(fd,request,0,request.length));
            StructPollfd ready=new StructPollfd();ready.fd=fd;ready.events=(short)OsConstants.POLLIN;
            assertEquals(1,Os.poll(new StructPollfd[]{ready},2000));assertTrue((ready.revents&OsConstants.POLLIN)!=0);
            byte[] reply=new byte[2048];int n=Os.read(fd,reply,0,reply.length);
            assertEquals(8+payload.length,n);assertEquals(0,reply[0]);assertEquals(0,reply[1]);
            assertEquals(0,Protocol.checksum(Arrays.copyOf(reply,n)));
            assertTrue(Arrays.equals(payload,Arrays.copyOfRange(reply,8,n)));
        } finally { Os.close(fd); }
    }
    public void testVpnManifestAndConsentEntryPoint() throws Exception {
        Context c=getInstrumentation().getTargetContext();
        ServiceInfo service=c.getPackageManager().getServiceInfo(new ComponentName(c,TunnelService.class),0);
        assertEquals("android.permission.BIND_VPN_SERVICE",service.permission);assertFalse(service.exported);
        assertEquals(ServiceInfo.FOREGROUND_SERVICE_TYPE_SYSTEM_EXEMPTED,service.getForegroundServiceType());
        assertTrue(c.getApplicationInfo().targetSdkVersion>=35);
        // This call must be legal without root; it may return the expected consent activity.
        VpnService.prepare(c);
    }
    public void testKeystoreEncryptedPskRoundTrip() throws Exception {
        Context c=getInstrumentation().getTargetContext();byte[] key=new byte[32];new java.security.SecureRandom().nextBytes(key);
        try {
            KeyStoreConfig.save(c,"192.0.2.1","1.1.1.1",key);assertTrue(Arrays.equals(key,KeyStoreConfig.load(c)));
            assertFalse(KeyStoreConfig.prefs(c).contains("psk"));assertNotNull(KeyStoreConfig.prefs(c).getString(ProfileStore.DATA,null));
        } finally { Arrays.fill(key,(byte)0);KeyStoreConfig.prefs(c).edit().clear().commit(); }
    }
}
