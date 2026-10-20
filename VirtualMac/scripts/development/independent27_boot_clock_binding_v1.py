"""Same-UUID boot identity with a one-second allowance for measured NTP slewing.

This rewrites only the old boottime equality, never hardware, product, process,
signature, lease, timeout or handoff checks. The actual kernel UUID is checked
at every replacement, including historical health text lacking that check.
"""
import hashlib,pathlib,re
N=pathlib.Path(__file__).resolve().parents[3]/'DeviceDiagnostics/2026-10-08-full-macos27-cpu-vmm'
PROOF=N/'independent27-normal140-current-device-identity-read-v1-attempt1/stdout'
PROOF_SHA='d9d356a34c92b5160597646954847d4e5e86789484354c3abef6a428a8f917a3'
UUID='C7D63D1F-86E9-4224-A1C7-108F02E91942'
SECONDS=1792161312
def bind(text,generation):
    proof=PROOF.read_bytes()
    assert hashlib.sha256(proof).hexdigest()==PROOF_SHA
    assert b'{ sec = 1792161311, usec = 963205 }' in proof and UUID.encode() in proof
    assert generation['bootSessionUUID']==UUID and generation['bootSeconds']==SECONDS
    lines=text.splitlines(keepends=True);count=0
    for index,line in enumerate(lines):
        plain=line.rstrip('\n')
        if not (plain.startswith('[ "$(sysctl -n kern.boottime | sed -n ') and plain.endswith('" = '+str(SECONDS)+' ]')):continue
        expression=plain[len('[ "'):plain.rindex('" = ')]
        assert expression.startswith('$(sysctl -n kern.boottime | sed -n "') and expression.endswith('")')
        allowed='|'.join(str(SECONDS+offset)for offset in (-1,0,1))
        lines[index]='case "'+expression+'" in '+allowed+') ;; *) exit 77;; esac\n[ "$(sysctl -n kern.bootsessionuuid)" = '+UUID+' ]\n'
        count+=1
    assert count>0,'At least one complete exact historical boot-second guard'
    return ''.join(lines)
def bind_controller(controller,generation):
    original=controller.prefix
    controller.prefix=lambda uid:bind(original(uid),generation)
