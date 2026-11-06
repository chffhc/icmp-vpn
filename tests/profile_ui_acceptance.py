"""Disposable emulator acceptance; synthetic profiles only. Never point at a real phone."""
import base64
import io
import json
import re
import struct
import subprocess
import time
import xml.etree.ElementTree as ET
from pathlib import Path
ADB = ['/opt/homebrew/share/android-commandlinetools/platform-tools/adb', '-s', 'emulator-5560']
PACKAGE = 'org.nousresearch.icmpvpn'
OUT = Path(__file__).resolve().parents[1] / 'build/profiles-v051'

def run(args):
    return subprocess.run(ADB + args, capture_output=True, text=True, check=True, timeout=20).stdout

def nodes():
    run(['shell','uiautomator','dump','/sdcard/icmpvpn-acceptance.xml'])
    return [n.attrib for n in ET.fromstring(run(['exec-out','cat','/sdcard/icmpvpn-acceptance.xml'])).iter('node')]

def tap_node(n):
    x1,y1,x2,y2=map(int,re.findall(r'\d+',n['bounds']))
    run(['shell','input','tap',str((x1+x2)//2),str((y1+y2)//2)])
    nodes()  # uiautomator waits for UI idle; adb input completion is not a commit barrier.

def button(part):
    tap_node(next(n for n in nodes() if n.get('class')=='android.widget.Button' and part in n.get('text','')))

def fill(index,value):
    edit=[n for n in nodes() if n.get('class')=='android.widget.EditText'][index]
    tap_node(edit)
    run(['shell','input','keyevent','KEYCODE_MOVE_END'])
    # Select all with CTRL+A, then replace (only synthetic fixture text).
    run(['shell','input','keycombination','113','29'])
    run(['shell','input','text',value])
    run(['shell','input','keyevent','KEYCODE_BACK'])

def stored():
    xml=run(['exec-out','run-as',PACKAGE,'cat','shared_prefs/vpn.xml'])
    d={n.attrib['name']:n.text for n in ET.fromstring(xml)}
    f=io.BytesIO(base64.b64decode(d['profiles_v1']))
    def number(): return struct.unpack('>i',f.read(4))[0]
    def string(): return f.read(struct.unpack('>H',f.read(2))[0]).decode('utf-8')
    assert number()==1
    selected=string(); result=[]
    for _ in range(number()):
        row=dict(zip(['id','name','server','dns','iv','ciphertext'],[string() for _ in range(6)]))
        row['format']=number();result.append(row)
    return selected,result

def launch():
    run(['shell','am','start','-n',PACKAGE+'/.MainActivity'])

assert run(['shell','getprop','ro.kernel.qemu']).strip()=='1', 'Disposable emulator required'
assert 'Success' in run(['shell','pm','clear',PACKAGE])
launch()
button('NEW');fill(0,'Fixture-A');fill(1,'192.0.2.11');fill(3,'19'*32);button('SAVE')
a_id,rows=stored();assert len(rows)==1 and rows[0]['name']=='Fixture-A'
button('NEW');fill(0,'Fixture-B');fill(1,'10.0.2.2');fill(2,'8.8.8.8');fill(3,'72'*32);button('SAVE')
b_id,rows=stored();assert len(rows)==2 and b_id!=a_id
assert [r['server'] for r in rows]==['192.0.2.11','10.0.2.2']
assert rows[0]['ciphertext']!=rows[1]['ciphertext']
run(['shell','am','force-stop',PACKAGE]);launch()
ns=nodes();assert any(n.get('text')=='Fixture-B' for n in ns)
assert stored()[0]==b_id
# Selection through the real Spinner, not reflection or preference injection.
tap_node(next(n for n in ns if n.get('class')=='android.widget.Spinner'))
tap_node(next(n for n in nodes() if n.get('text')=='Fixture-A — 192.0.2.11'))
assert stored()[0]==a_id
fill(0,'Fixture-A-edited');button('SAVE')
assert stored()[1][0]['ciphertext']==rows[0]['ciphertext']
button('DELETE');button('取消');assert len(stored()[1])==2
button('DELETE');button('删除');assert len(stored()[1])==1 and stored()[0]==b_id
# Real OS VPN consent cancellation and acceptance.
run(['shell','appops','set',PACKAGE,'ACTIVATE_VPN','ignore'])
button('START');ns=nodes()
assert any(n.get('package')=='com.android.vpndialogs' for n in ns), 'Expected actual Android VPN consent dialog'
run(['shell','input','keyevent','KEYCODE_BACK'])
ns=nodes();assert next(n for n in ns if n.get('class')=='android.widget.Button' and 'START' in n.get('text',''))['enabled']=='true'
button('START');ns=nodes()
tap_node(next(n for n in ns if n.get('resource-id')=='android:id/button1'))
ns=nodes()
permission=next((n for n in ns if n.get('resource-id','').endswith(':id/permission_allow_button')),None)
if permission is not None:
    tap_node(permission)
# Bound actual service startup, then check edit controls are disabled.
end=time.monotonic()+8
while time.monotonic()<end:
    ns=nodes()
    if any('VPN 忙碌' in n.get('text','') for n in ns):break
else:raise AssertionError('service never became busy')
assert all(n['enabled']=='false' for n in ns if n.get('class') in ['android.widget.EditText','android.widget.Spinner'])
# Reuse the just-verified live layout while status counters are changing;
# another UIAutomator wait-for-idle can starve on continuous VPN stats updates.
stop_node=next(n for n in ns if n.get('class')=='android.widget.Button' and 'STOP' in n.get('text',''))
tap_node(stop_node);ns=nodes()
assert all(n['enabled']=='true' for n in ns if n.get('class')=='android.widget.EditText')
assert len(stored()[1])==1 and stored()[0]==b_id
result={'status':'PASS','synthetic_fixtures_only':True,'real_ui_add_two_profiles':True,'edit_blank_key_preserves_only_selected':True,'force_stop_relaunch':True,'spinner_selection_persisted':True,'delete_cancel_and_confirm':True,'real_os_consent_cancel_then_accept':True,'active_controls_locked_and_stop_unlocks':True,'phone_wan_test':False}
OUT.mkdir(parents=True,exist_ok=True)
(OUT/'ui-acceptance.json').write_text(json.dumps(result,indent=2)+'\n')
print(json.dumps(result,indent=2))
