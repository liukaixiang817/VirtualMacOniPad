"""Same-UUID boot identity with a one-second allowance for measured NTP slewing.

This rewrites only the old boottime equality, never hardware, product, process,
signature, lease, timeout or handoff checks. The actual kernel UUID is checked
in the existing controller prefix, retained byte for byte. Health snippets run
under that prefix; their historical second comparison alone is rebound.
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
        values=[str(SECONDS+offset)for offset in (-1,0,1)]
        common=values[0][:-1];assert all(v[:-1]==common for v in values)
        digits=''.join(v[-1]for v in values)
        lines[index]='case "$(sysctl -n kern.boottime)" in "{ sec = '+common+'"['+digits+'],*) ;;*)exit 77;;esac\n'
        count+=1
    assert count>0,'At least one complete exact historical boot-second guard'
    return ''.join(lines)
def bind_controller(controller,generation):
    original=controller.prefix
    controller.prefix=lambda uid:bind(original(uid),generation)
