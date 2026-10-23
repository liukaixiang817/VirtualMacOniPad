"""Run the real configure body in isolated host filesystem/protocol fixtures.

Root identity, chown, uicache and Dopamine replies are explicit mocks. This
does not replace an actual iPad installation test.
"""
import hashlib
import json
import os
from pathlib import Path
import subprocess
import tempfile

R=Path(__file__).resolve().parents[3]
N=R/'DeviceDiagnostics/2026-10-08-full-macos27-cpu-vmm'
SOURCE=Path(__file__).with_name('configure-complete-dual-beta6-v1.sh')
O=N/'beta6-configure-host-fixtures-v1'

def scenario(name,info_error=0,add_error=0,tamper=False,repeat=False,binding=False):
    with tempfile.TemporaryDirectory(prefix='vm27-beta6-install-',dir='/private/tmp') as tmp:
        root=Path(tmp);jb=root/'different-device-preboot/dopamine-portable/procursus'
        alias=root/'jb';jb.mkdir(parents=True);alias.symlink_to(jb,target_is_directory=True)
        app=alias/'Applications/VirtualMacIndependent27.app'
        runtime=root/'runtime27';full13=root/'runtime13';metadata=alias/'usr/share/virtualmac-independent27'
        for path in [app,runtime,full13,metadata,jb/'basebin',jb/'usr/bin']:path.mkdir(parents=True,exist_ok=True)
        files=[app/'VirtualMacIndependent27',runtime/'provider.dylib']
        rows=[]
        for index,path in enumerate(files):
            path.write_bytes(('fixture-'+str(index)).encode())
            rows.append((str(index+1)*40,hashlib.sha256(path.read_bytes()).hexdigest(),str(path)))
        (metadata/'files.sha256').write_text(''.join(f'{sha}  {path}\n'for cd,sha,path in rows))
        (metadata/'trustcache-v2.txt').write_text(''.join(f'{cd} {sha} {path}\n'for cd,sha,path in rows))
        (metadata/'symlinks.tsv').write_text('')
        tc=root/'tc';tc.write_text('');calls=root/'calls'
        tool=jb/'basebin/jbctl'
        tool.write_text('''#!/bin/sh
set -eu
[ "$1" = trustcache ] || exit 80
case "$2" in
info)
 if [ "$FAKE_INFO_ERROR" != 0 ]; then echo 'fixture-loader-error-127' >&2; exit "$FAKE_INFO_ERROR"; fi
 printf 'Jailbreak Trustcache 0 <UUID: fixture> (length: 2)\\n'
 while IFS= read -r hash; do printf '| 1:\\t%s\\n' "$hash"; done < "$FAKE_TC";;
add)
 printf '%s\\n' "$3" >> "$FAKE_CALLS"
 [ "$FAKE_ADD_ERROR" = 0 ] || exit "$FAKE_ADD_ERROR"
 printf '%s\\n' "$3" >> "$FAKE_TC";;
*) exit 81;;
esac
''');tool.chmod(0o700)
        (jb/'usr/bin/jbctl').symlink_to('../../basebin/jbctl')
        if tamper:files[0].write_bytes(b'tampered')
        if binding:(metadata/'trustcache-v2.txt').write_text('9'*40+' '+'f'*64+' '+str(files[0])+'\n')
        body=SOURCE.read_text().replace('/var/jb',str(alias))
        body=body.replace('/private/var/mobile/Library/VirtualMacIndependent27Runtime-v1',str(runtime))
        body=body.replace('/private/var/mobile/Library/VirtualMacFull13Runtime-v1',str(full13))
        body=body.replace('/private/var/mobile/Library/VirtualMacIndependent27Cache-v1',str(root/'cache'))
        script=root/'configure.sh'
        mocks='''set -eu
awk() { echo 'awk: command not found' >&2; exit 127; }
id() { printf '0\\n'; }
chown() { :; }
sha256sum() { [ "$1" = --status ] && [ "$2" = -c ]; /usr/bin/shasum -a 256 -c "$3" >/dev/null; }
uicache() { printf 'registered\\n' >> "$FAKE_REGISTERED"; }
'''
        script.write_text(mocks+body)
        env=dict(os.environ,FAKE_INFO_ERROR=str(info_error),FAKE_ADD_ERROR=str(add_error),
            FAKE_TC=str(tc),FAKE_CALLS=str(calls),FAKE_REGISTERED=str(root/'registered'))
        def run():return subprocess.run(['/bin/sh',str(script),'configure'],capture_output=True,env=env,timeout=20)
        result=run();log=(metadata/'configure.log').read_text()
        expected=1 if tamper or binding else add_error
        assert result.returncode==expected,(name,result.returncode,result.stderr.decode(),log)
        assert (root/'registered').exists()==(expected==0)
        if info_error:assert 'fixture-loader-error-127' in log
        if expected==0:
            assert set(tc.read_text().split())=={row[0]for row in rows}
            assert str(jb/'basebin/jbctl') in log
            assert (root/'cache/virtualization').is_dir()
            assert (root/'cache').stat().st_mode & 0o7777 == 0o700
            assert (root/'cache/virtualization').stat().st_mode & 0o7777 == 0o700
        if repeat:
            before=calls.read_bytes();again=run()
            assert again.returncode==0 and calls.read_bytes()==before
        return dict(name=name,exit=result.returncode,passed=True,
            nativeAPIExplicitMock=True,filesystemActuallyVerified=True)

def main():
    O.mkdir(mode=0o700)
    results=[scenario('canonical-root-idempotence',repeat=True),
        scenario('info127-native-add-succeeds',info_error=127),
        scenario('info127-add127-must-fail',info_error=127,add_error=127),
        scenario('tampered-file-must-fail',tamper=True),
        scenario('wrong-hash-file-binding-must-fail',binding=True)]
    (O/'results.json').write_text(json.dumps(dict(results=results,deviceOperations=0),indent=2)+'\n')
    print(json.dumps(results))

if __name__=='__main__':main()
