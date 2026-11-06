package org.nousresearch.icmpvpn;

import android.app.Activity;
import android.app.AlertDialog;
import android.content.Intent;
import android.os.Bundle;
import android.os.Handler;
import android.os.Looper;
import android.net.VpnService;
import android.text.InputFilter;
import android.text.InputType;
import android.view.View;
import android.view.WindowManager;
import android.widget.*;
import java.util.ArrayList;
import java.util.Arrays;

public final class MainActivity extends Activity {
    private EditText name,server,dns,psk;
    private Spinner profiles;
    private Button create,save,delete,start,stop;
    private TextView status,current;
    private ProfileList list;
    private String editingId,consentLease;
    private int expectedPosition, nextConsentRequest=1, pendingRequest=-1;
    private boolean storageError;
    private final Handler handler=new Handler(Looper.getMainLooper());
    private final Runnable refresh=new Runnable() { public void run() { refreshControls();handler.postDelayed(this,250); } };

    @Override public void onCreate(Bundle state) {
        super.onCreate(state);if(state!=null) nextConsentRequest=state.getInt("nextConsentRequest",1);getWindow().addFlags(WindowManager.LayoutParams.FLAG_SECURE);
        LinearLayout layout=new LinearLayout(this);layout.setOrientation(LinearLayout.VERTICAL);layout.setPadding(24,24,24,24);
        layout.setOnApplyWindowInsetsListener((v,insets) -> {
            v.setPadding(24+insets.getSystemWindowInsetLeft(),24+insets.getSystemWindowInsetTop(),24+insets.getSystemWindowInsetRight(),24+insets.getSystemWindowInsetBottom());return insets;
        });
        TextView title=new TextView(this);title.setText("ICMP VPN — 多服务器配置\nIPv4 full tunnel; IPv6 captured and blocked. 仅限授权网络。");layout.addView(title);
        current=new TextView(this);layout.addView(current);
        profiles=new Spinner(this);profiles.setSaveEnabled(false);layout.addView(profiles);
        name=input(layout,"配置名称（1–64 字）");name.setFilters(new InputFilter[]{new InputFilter.LengthFilter(Profile.MAX_NAME)});
        server=input(layout,"服务器 IPv4（不支持域名）");dns=input(layout,"DNS IPv4");
        psk=input(layout,"64 位十六进制 PSK；编辑留空仅保留本配置密钥");
        psk.setInputType(InputType.TYPE_CLASS_TEXT|InputType.TYPE_TEXT_VARIATION_PASSWORD|InputType.TYPE_TEXT_FLAG_NO_SUGGESTIONS);
        psk.setImeOptions(psk.getImeOptions()|android.view.inputmethod.EditorInfo.IME_FLAG_NO_PERSONALIZED_LEARNING);
        create=button(layout,"新建 / New",() -> { if(canEdit()) { expectedPosition=0;profiles.setSelection(0);showForm(null); } });
        save=button(layout,"保存 / Save",() -> { if(canEdit()) saveForm(); });
        delete=button(layout,"删除 / Delete",this::deleteProfile);
        start=button(layout,"启动 / Start（保存并连接）",this::start);
        stop=button(layout,"停止 / Stop",this::stop);
        status=new TextView(this);layout.addView(status);
        TextView warning=new TextView(this);warning.setText("启动、连接、重连或停止期间不能修改/切换配置，请先停止 VPN。\nNo built-in kill switch: stopping/failure may allow direct networking. For fail-closed behavior enable Always-on VPN + Block connections without VPN in Android settings. ICMP filtering/rate limits may prevent connection.");layout.addView(warning);
        ScrollView scroll=new ScrollView(this);scroll.addView(layout);setContentView(scroll);
        try { render(ProfileStore.read(this)); } catch(Exception e) { failStorage(); }
        profiles.setOnItemSelectedListener(new AdapterView.OnItemSelectedListener() {
            @Override public void onNothingSelected(AdapterView<?> parent) { }
            @Override public void onItemSelected(AdapterView<?> parent,View view,int position,long id) {
                if(position==expectedPosition) return;
                if(!canEdit()) { profiles.setSelection(expectedPosition);return; }
                if(position==0) { expectedPosition=0;showForm(null);return; }
                try { render(ProfileStore.select(MainActivity.this,list.profiles.get(position-1).id)); }
                catch(Exception e) { failStorage(); }
            }
        });
        refreshControls();
    }
    private EditText input(LinearLayout layout,String hint) {
        EditText e=new EditText(this);e.setSingleLine(true);e.setHint(hint);
        e.setInputType(InputType.TYPE_CLASS_TEXT|InputType.TYPE_TEXT_FLAG_NO_SUGGESTIONS);
        e.setSaveEnabled(false);e.setImportantForAutofill(View.IMPORTANT_FOR_AUTOFILL_NO_EXCLUDE_DESCENDANTS);
        layout.addView(e);return e;
    }
    private Button button(LinearLayout layout,String text,Runnable action) {
        Button b=new Button(this);b.setText(text);b.setOnClickListener(v -> action.run());layout.addView(b);return b;
    }
    private boolean canEdit() { return !storageError && !SessionGate.busy(); }
    private void render(ProfileList next) {
        list=next;ArrayList<String> labels=new ArrayList<>();labels.add("新配置（未保存）");expectedPosition=0;
        for(int i=0;i<list.profiles.size();i++) { Profile p=list.profiles.get(i);labels.add(p.toString());if(p.id.equals(list.selectedId)) expectedPosition=i+1; }
        profiles.setAdapter(new ArrayAdapter<>(this,android.R.layout.simple_spinner_dropdown_item,labels));profiles.setSelection(expectedPosition);
        showForm(list.selected());refreshControls();
    }
    private void showForm(Profile p) {
        editingId=p==null?null:p.id;name.setText(p==null?"":p.name);server.setText(p==null?"":p.server);dns.setText(p==null?"1.1.1.1":p.dns);psk.setText("");
        current.setText(p==null?"新配置：必须填写独立 PSK":"当前配置："+p);
        refreshControls();
    }
    private boolean saveForm() {
        byte[] key=null;
        try {
            String label=name.getText().toString(),host=server.getText().toString(),resolver=dns.getText().toString();
            Profile.validateFields(label,host,resolver);
            if(psk.length()!=0) key=Protocol.parseKey(psk.getText().toString());
            if(editingId==null && key==null) throw new IllegalArgumentException("New profile requires PSK");
            render(ProfileStore.save(this,editingId,label,host,resolver,key));return true;
        } catch(IllegalArgumentException e) { toast("检查名称、IPv4 和 64 位十六进制 PSK。新配置必须填写密钥；最多 64 个配置。");return false; }
        catch(Exception e) { failStorage();return false; }
        finally { if(key!=null) Arrays.fill(key,(byte)0);psk.setText(""); }
    }
    private void deleteProfile() {
        if(!canEdit() || editingId==null) return;final String target=editingId;
        new AlertDialog.Builder(this).setTitle("删除配置？").setMessage("删除 "+list.get(target)+" 的本地配置和加密密钥；此操作不能撤销。")
            .setNegativeButton("取消",null).setPositiveButton("删除",(dialog,which) -> {
                if(!canEdit() || !target.equals(editingId)) return;
                try { render(ProfileStore.delete(this,target)); } catch(Exception e) { failStorage(); }
            }).show();
    }
    private void start() {
        if(!canEdit() || !saveForm()) return;
        try {
            consentLease=ProfileStore.reserveSelected(this);refreshControls();
            Intent consent=VpnService.prepare(this);
            if(consent!=null) {
                if(nextConsentRequest>65535) throw new IllegalStateException("Reopen activity");
                pendingRequest=nextConsentRequest++;startActivityForResult(consent,pendingRequest);
            } else launch();
        } catch(Exception e) {
            SessionGate.cancelConsent(consentLease);consentLease=null;toast("无法启动 VPN，请检查系统 VPN 授权。");refreshControls();
        }
    }
    private void launch() {
        String lease=consentLease;consentLease=null;
        if(!SessionGate.launch(lease)) { refreshControls();return; }
        try {
            // Notification permission is optional for FGS; ask only after VPN consent,
            // never overlap its dialog or use a permission result to choose a profile.
            if(android.os.Build.VERSION.SDK_INT>=33 && checkSelfPermission(android.Manifest.permission.POST_NOTIFICATIONS)!=android.content.pm.PackageManager.PERMISSION_GRANTED)
                requestPermissions(new String[]{android.Manifest.permission.POST_NOTIFICATIONS},2);
            startForegroundService(new Intent(this,TunnelService.class).setAction(TunnelService.START).putExtra(TunnelService.LEASE,lease));
        }
        catch(RuntimeException e) { SessionGate.failedLaunch(lease);toast("VPN 启动被系统拒绝。"); }
        refreshControls();
    }
    private void stop() {
        consentLease=null;pendingRequest=-1;SessionGate.stopping();
        try { startService(new Intent(this,TunnelService.class).setAction(TunnelService.STOP)); }
        catch(RuntimeException e) { toast("停止请求被系统拒绝，请使用系统 VPN 设置停止。"); }
        refreshControls();
    }
    @Override protected void onActivityResult(int request,int result,Intent data) {
        super.onActivityResult(request,result,data);
        if(request!=pendingRequest) return;pendingRequest=-1;
        if(result==RESULT_OK && consentLease!=null) launch();
        else { SessionGate.cancelConsent(consentLease);consentLease=null;refreshControls(); }
    }
    private void failStorage() {
        storageError=true;psk.setText("");toast("配置读取/保存或密钥验证失败。为保护现有配置已禁用修改与启动；不会清空或覆盖损坏数据。");refreshControls();
    }
    private void toast(String text) { Toast.makeText(this,text,Toast.LENGTH_LONG).show(); }
    private void refreshControls() {
        if(status==null) return;boolean editable=canEdit();
        for(View v:new View[]{profiles,name,server,dns,psk,create,save,start}) v.setEnabled(editable);
        delete.setEnabled(editable && editingId!=null);stop.setEnabled(SessionGate.busy());
        status.setText((storageError?"配置错误：请保留应用数据并排查，禁止自动重置。\n":"")+(SessionGate.busy()?"VPN 忙碌 / "+SessionGate.state()+"；请先停止再切换。\n":"")+TunnelService.status);
    }
    @Override protected void onResume() { super.onResume();handler.post(refresh); }
    @Override protected void onPause() { handler.removeCallbacks(refresh);super.onPause(); }
    @Override protected void onSaveInstanceState(Bundle out) {
        out.putInt("nextConsentRequest",nextConsentRequest);super.onSaveInstanceState(out);
    }
    @Override protected void onDestroy() {
        SessionGate.cancelConsent(consentLease);consentLease=null;psk.setText("");handler.removeCallbacks(refresh);super.onDestroy();
    }
}
