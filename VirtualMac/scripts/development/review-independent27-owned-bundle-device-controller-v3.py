#!/usr/bin/env python3
"""Finite HOST-only independent review; no packet import or device operations."""
from pathlib import Path, PurePosixPath
import ast
import hashlib
import io
import json
import re
import shlex
import struct
import subprocess
import tarfile

R = Path('/Users/liukaixiang/Documents/VirtualMacOniPad')
N = R/'DeviceDiagnostics/2026-10-08-full-macos27-cpu-vmm'
P = N/'independent27-owned-bundle-device-v3-attempt1'
O = N/'independent27-owned-bundle-controller-peer-v3-attempt3'

def pin(p):
    p = Path(p)
    assert p.is_file() and not p.is_symlink()
    b = p.read_bytes()
    return dict(path=str(p), bytes=len(b), sha256=hashlib.sha256(b).hexdigest())

def exact(row):
    assert pin(row['path']) == row, row['path']
    return Path(row['path'])

def read(p):
    return json.loads(Path(p).read_bytes())

def dump(p, obj):
    Path(p).write_text(json.dumps(obj, indent=2)+'\n')

def cdhash(b):
    assert b[:4] == b'\xcf\xfa\xed\xfe'
    n = struct.unpack_from('<I', b, 16)[0]
    cursor = 32
    signatures = []
    for _ in range(n):
        cmd, size = struct.unpack_from('<II', b, cursor)
        assert size >= 8 and cursor+size <= len(b)
        if cmd == 0x1d:
            offset, length = struct.unpack_from('<II', b, cursor+8)
            signatures.append(b[offset:offset+length])
        cursor += size
    assert len(signatures) == 1
    sig = signatures[0]
    magic, length, count = struct.unpack_from('>III', sig)
    assert magic == 0xfade0cc0 and length <= len(sig) and not any(sig[length:])
    found = []
    for i in range(count):
        slot, offset = struct.unpack_from('>II', sig, 12+8*i)
        if slot == 0:
            magic, length = struct.unpack_from('>II', sig, offset)
            assert magic == 0xfade0c02
            directory = sig[offset:offset+length]
            assert len(directory) == length and directory[37] == 2
            found.append(hashlib.sha256(directory).hexdigest()[:40])
    assert len(found) == 1
    return found[0]

def source_nodes(text):
    rows = text.splitlines(keepends=True)
    return {n.name: ''.join(rows[n.lineno-1:n.end_lineno]) for n in ast.parse(text).body if isinstance(n, ast.FunctionDef)}

def literal(text, name):
    for n in ast.parse(text).body:
        if isinstance(n, ast.Assign) and any(isinstance(t, ast.Name) and t.id == name for t in n.targets):
            return ast.literal_eval(n.value)
    raise AssertionError(name)

def main():
    O.mkdir(exist_ok=False)
    candidate = read(P/'candidate.json')
    scope = read(exact(candidate['scope']))
    assert pin(P/'candidate.json')['sha256'] == '99a5497b769a056089f3711e5c6b3352ace9516817489f94c0db148bf359b7aa'
    assert candidate['scope']['sha256'] == '60124386cf0cdfb00b1ce53b862cce84eb56e217e1f08f162716935443d08611'
    frozen = read(P/'freeze.json')
    for row in frozen['files']:
        exact(row)
    checks = []
    def passed(name, evidence):
        checks.append(dict(name=name, passed=True, evidence=evidence))

    passed('Actual packet freeze unchanged', dict(files=len(frozen['files']), deviceOperations=frozen['deviceOperations']))
    for version in (1, 2):
        previous = N/f'independent27-owned-bundle-device-v{version}-attempt1'
        for f in ('control.py', 'products.tar', *[a+'.sh' for a in candidate['scripts']]):
            assert (P/f).read_bytes() == (previous/f).read_bytes(), (version, f)
    passed('V3 changes metadata only', 'Controller, archive and all 8 scripts equal V1 and V2 whole bytes.')

    old = read(exact(scope['oldScope']))
    oldrows = {r['devicePath']: r for r in old['files']}
    rows = {r['devicePath']: r for r in scope['files']}
    assert len(rows) == len(oldrows) == 252 and rows.keys() == oldrows.keys()
    assert scope['directories'] == old['directories']
    changed = {p for p in rows if rows[p]['local']['sha256'] != oldrows[p]['local']['sha256']}
    assert len(changed) == 9 and changed == {r['devicePath'] for r in scope['deltaFiles']}
    for delta in scope['deltaFiles']:
        path = delta['devicePath']
        assert delta['old'] == oldrows[path]['local'] and delta['new'] == rows[path]['local']
        assert delta['mode'] == oldrows[path]['mode'] == rows[path]['mode']
        exact(delta['old']); exact(delta['new'])
    passed('Nine-file delta matches installed PluginV2 catalog', dict(changed=9, unchanged=243, unchangedDirectories=len(scope['directories'])))

    post = read(exact(scope['oldActualPost']))
    assert scope['oldActualPost'] == scope['currentInstalledProductsPost'] == candidate['currentInstalledProductsPost']
    assert post['transportExit'] == 0 and post['transportError'] is None
    stdout = exact(post['stdout']).read_text()
    exact(post['stderr'])
    assert 'INDEPENDENT27_ALL_ACTUAL_PRODUCTS_EXACT' in stdout
    assert 'OWN_RETAINED_LOG_BYTES 1972' in stdout
    logsha = 'be1f005937b820b916bea907793a8f3702a26bec1bd37f43d72d746f6fb4681a'
    assert logsha in stdout
    assert 'currentInstalledProductsReadonly' not in scope
    for k in ('historicalAncestorExternalSignaturePost', 'historicalPriorRuntime4ProductsReadonly'):
        exact(scope[k])
    passed('Current post0 and historical labels accurate', dict(actualPost=scope['oldActualPost'], retainedLogBytes=1972, retainedLogSHA256=logsha))

    raw = exact(candidate['archive']).read_bytes()
    assert len(raw) == scope['deltaArchiveBytes'] and hashlib.sha256(raw).hexdigest() == scope['deltaArchiveSHA256']
    archive_rows = []
    actual_new_cd = []
    with tarfile.open(fileobj=io.BytesIO(raw), mode='r:') as archive:
        members = archive.getmembers()
        assert [m.name for m in members] == ['new-'+str(i) for i in range(9)]
        for i, (m, d) in enumerate(zip(members, scope['deltaFiles'], strict=True)):
            assert d['index'] == i and m.type == tarfile.REGTYPE and not m.linkname and not m.pax_headers
            assert m.uid == m.gid == m.mtime == 0 and m.mode == 0o600 and m.size == d['new']['bytes']
            data = archive.extractfile(m).read()
            assert data == exact(d['new']).read_bytes()
            assert hashlib.sha256(data).hexdigest() == d['new']['sha256']
            item = dict(name=m.name, bytes=m.size, sha256=d['new']['sha256'], devicePath=d['devicePath'])
            if 'cdhash' in rows[d['devicePath']]:
                value = cdhash(data)
                assert value == rows[d['devicePath']]['cdhash']
                item['actualCodeDirectorySHA256Truncated20'] = value
                actual_new_cd.append(value)
            archive_rows.append(item)
    assert sorted(actual_new_cd) == scope['newTrustCacheCDHashes'] and len(set(actual_new_cd)) == 6
    old_cd = {r['cdhash'] for r in old['files'] if 'cdhash' in r}
    new_cd = {r['cdhash'] for r in rows.values() if 'cdhash' in r}
    assert len(old_cd) == len(new_cd) == 140 and len(old_cd & new_cd) == 134
    assert sorted(new_cd-old_cd) == scope['newTrustCacheCDHashes']
    previous_entries = set()
    history = []
    for d in ('independent27-device-bootstrap-controller-v3-attempt1', 'independent27-main-identity-device-v1-attempt1', 'independent27-external-signature-device-v1-attempt1', 'independent27-unbuffered-log-device-v1-attempt1', 'independent27-child-plugin-device-v2-attempt1'):
        h = N/d/'scope.json'; j = read(h)
        values = j.get('newTrustCacheCDHashes', j['trustCacheCDHashes'])
        previous_entries.update(values)
        history.append(dict(scope=pin(h), authorizedEntryCount=len(values)))
    assert len(previous_entries) == 156 and previous_entries.isdisjoint(actual_new_cd)
    passed('Actual archive and CodeDirectory delta', dict(archiveMembers=archive_rows, actualNewCDHashes=sorted(actual_new_cd), unchangedSignedImages=134, previousEntriesNotRepeated=156, historicalScopes=history))

    controller = exact(candidate['controller']).read_text()
    prior = exact(candidate['priorController']).read_text()
    current_functions, prior_functions = source_nodes(controller), source_nodes(prior)
    for name in ('pin', 'exact', 'prefix', 'off_check', 'run_remote', 'prior_receipt'):
        assert current_functions[name] == prior_functions[name], name
    process = literal(controller, 'PROCESS_FUNCTIONS')
    assert process == literal(prior, 'PROCESS_FUNCTIONS')
    bodies, syntax = {}, []
    quoted = {}
    for action, row in candidate['scripts'].items():
        scriptpath = exact(row); text = scriptpath.read_text()
        body = shlex.split(text)[-1]; bodies[action] = body
        for kind, source in (('outer', text), ('inner', body)):
            result = subprocess.run(['/bin/sh', '-n'], input=source.encode(), capture_output=True, timeout=10)
            assert result.returncode == 0 and not result.stdout and not result.stderr, (action, kind)
            syntax.append(dict(action=action, body=kind, command=['/bin/sh', '-n'], exit=result.returncode))
        duration = 20 if action == 'close-current-own' else 45
        assert '/var/jb/usr/bin/timeout --signal=TERM --kill-after=3 '+str(duration)+' /var/jb/bin/sh -c ' in text
        assert '[ "$(id -u)" = '+('501' if action == 'launch' else '0')+' ]' in text
        command = ('sudo -k -S -p "" ' if action != 'launch' else '')+'/var/jb/bin/sh -c '+shlex.quote(text)
        quoted[action] = len(command.encode())
    assert quoted == candidate['quotedCommandBytes'] and max(quoted.values()) == 214676
    assert max(quoted.values())+10000 < 262144
    passed('All actual shell syntax and external bounds', dict(syntaxChecks=syntax, quotedCommandBytes=quoted, ARG_MAX=262144, reservedEnvironmentBytes=10000, transportSeconds=55))

    stage = bodies['stage']; lines = stage.splitlines()
    moves = [(i, shlex.split(l)) for i, l in enumerate(lines) if l.startswith('mv -f ')]
    assert len(moves) == 9
    first_mv = moves[0][0]
    backup_lines = []
    for i, d in enumerate(scope['deltaFiles']):
        backup = 'cp -p '+d['devicePath']+' "$OWN_STAGE/backup-'+str(i)+'"'
        n = lines.index(backup); backup_lines.append(n+1)
        assert n < first_mv and d['old']['sha256'] in lines[n+1]
        mvline, tokens = moves[i]
        assert tokens[:2] == ['mv', '-f'] and tokens[3] == d['devicePath']
        temp = PurePosixPath(tokens[2]); target = PurePosixPath(tokens[3])
        assert temp.parent == target.parent and temp.name == '.VM27-owned-bundle-v1-'+str(i)+'.pending'
        before = '\n'.join(lines[mvline-6:mvline])
        assert 'check_own_file '+str(temp)+' '+d['new']['sha256'] in before
        assert 'check_own_file '+str(target)+' '+d['old']['sha256'] in before
        assert 'check_own_file '+str(target)+' '+d['new']['sha256'] in lines[mvline+1]
    logbackup = lines.index('cp -p "$OWN_LOG" "$OWN_STAGE/backup-app-log"')
    assert logbackup < first_mv and logsha in lines[logbackup+1]
    assert stage.index(': > "$OWN_LOG"') > stage.index(lines[moves[-1][0]])
    assert 'own_log_identity=$(stat -c %d:%i "$OWN_LOG")' in stage
    assert '[ "$(stat -c %d:%i "$OWN_LOG")" = "$own_log_identity" ]' in stage
    assert 'set -C; : > "$OWN_STAGE/stage-complete"' in stage
    passed('All backups precede first atomic replacement', dict(fileBackupLines=backup_lines, logBackupLine=logbackup+1, firstMoveLine=first_mv+1, replacementMoves=9, exactSameDirectoryTemporaryFiles=True, logInodePreserved=True))

    trust = bodies['trust']
    additions = re.findall(r'^jbctl trustcache add ([a-f0-9]{40})$', trust, re.M)
    assert additions == scope['newTrustCacheCDHashes']
    assert trust.index('INDEPENDENT27_ALL_ACTUAL_PRODUCTS_EXACT') < trust.index('jbctl trustcache add')
    assert trust.index('trust-dispatched') < trust.index('jbctl trustcache add')
    assert scope['trustCacheRegistrationCount'] == 6 and scope['trustCacheFixedBatchCounts'] == [6]
    assert scope['individualTrustCacheWithdrawalProven'] is False and scope['deleteFilesWithdrawsTrust'] is False
    assert scope['trustCacheGlobalClear'] is False and scope['deviceSystemFilesModified'] is False
    passed('Exactly six trust additions after complete verification', dict(actualAdditions=additions, retainedUntilRebootPossible=True, noIndividualWithdrawalClaim=True))

    launch = bodies['launch']; postbody = bodies['post']; close = bodies['close-current-own']
    for action in ('launch', 'post', 'close-current-own'):
        assert process in bodies[action]
    assert launch.count('/var/jb/usr/bin/uiopen --bundleid com.mac.virtual.independent27') == 1
    assert launch.count('/var/jb/usr/bin/uiopen virtualmac27://runtime-startup') == 1
    assert "trap finish_own EXIT" in launch and "trap 'exit 143' TERM INT HUP" in launch
    assert 'cleanup_own || own_status=78' in launch and 'exit "$own_status"' in launch
    assert '[ "$own_result" = \'[Independent27] runtime-startup result=1 errorDomain= errorCode=0 error=\' ]' in launch
    assert '[ -n "$app_rows" ] && [ -n "$child_rows" ]' in launch
    assert 'INDEPENDENT27_TRUE_PARENT_CHILD_BOOTSTRAP_READY_GUEST_NOT_REQUESTED' in launch
    assert "IFS=' ' read -r own_app_pid own_app_start own_child_pid own_child_start" in postbody
    close_active = close[close.index(process)+len(process):]
    assert close_active.count('[ "$own_child_pid" = 0 ]') == 2 and 'cleanup_own' not in close_active
    assert 'signal_own TERM "$own_app_pid"' in close_active and 'signal_own KILL "$own_app_pid"' in close_active
    assert not re.search(r'(^|\n)(pkill|killall)\b', '\n'.join(bodies.values()))
    passed('Cleanup keeps actual PID UID path PPID and start binding', 'Unchanged helpers recapture only exact own App; child initial capture requires live direct parent. Each signal rereads PID/UID/path/PPID/start; mismatch refuses. Close signals App only; launch traps preserve status; post consumes genuine captured IDs.')

    gate = current_functions['ready_gate']; dispatch = current_functions['dispatch']
    for token in ('readyForRootSerialDispatch', 'packetCandidate', 'packetFreeze', "pin(__file__)", 'independentReviews', "review.get('findings') == []", 'controllerPacketCandidate', 'humanUserAuthorization', "auth['scope'] == pin(packet/'scope.json')", "auth['trustCacheCDHashes'] == scope['newTrustCacheCDHashes']", "auth['trustCacheRegistrationCount'] == 6", "auth['initializationExternalWallSeconds'] == 45", 'exact nine ordinary delta members'):
        assert token in gate, token
    assert 'os.O_WRONLY|os.O_CREAT|os.O_EXCL' in dispatch
    assert dispatch.index("args.action+'-dispatched.json'") < dispatch.index('getpass.getpass') < dispatch.index('run_remote(')
    assert "need(not output.exists(), 'serial action never repeated')" in dispatch
    assert "success=args.action != 'post'" in dispatch
    assert "root': args.action != 'launch'" in dispatch
    assert "'guestBootRequested': False" in dispatch
    assert "parent[1] == '1'" in dispatch and "child[1] == parent[0]" in dispatch
    assert "need(kind not in found" in dispatch
    assert 'password = None' in dispatch and 'transportExit' in dispatch
    assert "if __name__ == '__main__':\n    main()" in controller
    assert 'timeout=55' in current_functions['run_remote'] and 'StrictHostKeyChecking=yes' in current_functions['run_remote']
    assert "'mobile@127.0.0.1'" in current_functions['run_remote']
    assert literal(controller, 'ACTIONS') == ('close-current-own','preflight','stage','verify','trust','launch','post')
    passed('Pinned human gate and serial once-only phases', 'Exact six-entry human scope including nine archive members; independent candidate-bound reviews; exclusive lock and persistent dispatched marker before SSH; predecessor success gates; failed launch still admits exact post cleanup; root registration then mobile launch; actual transport receipts, no retry or fabricated success.')

    assert candidate['deviceOperations'] == candidate['trustCacheOperations'] == 0
    assert candidate['readyForDeviceExecution'] is False and candidate['guestBootRequested'] is False
    assert not (P/'device-receipts').exists()
    report = dict(schema='Finite independent owned bundle device packet/controller review v3', findings=[], finiteLocalScopePassed=True, controllerScopePassed=True, controllerPacketCandidate=pin(P/'candidate.json'), packetScope=pin(P/'scope.json'), packetFreeze=pin(P/'freeze.json'), reviewedController=pin(P/'control.py'), reviewedPreparer=candidate['preparer'], checks=checks, deviceOperations=0, trustCacheOperations=0, guestBootRequested=False, actualDeviceExecutionProven=False, humanAuthorizationCreatedByReviewer=False, readyForDeviceExecution=False, limitations=['This HOST review does not prove live parent/child handshake or guest boot.', 'Individual trust-cache withdrawal remains unproven; deletion of installed files does not revoke entries.', 'No full signature page models repeated here; product composition is separately reviewed.'])
    dump(O/'review.json', report)
    inputs = [Path(__file__), P/'candidate.json', P/'scope.json', P/'freeze.json', P/'control.py', P/'products.tar', Path(candidate['preparer']['path']), Path(candidate['priorController']['path']), Path(scope['oldScope']['path']), Path(scope['oldActualPost']['path']), Path(post['stdout']['path']), Path(post['stderr']['path']), *[Path(r['path']) for r in candidate['scripts'].values()], O/'review.json']
    dump(O/'freeze.json', dict(files=[pin(p) for p in dict.fromkeys(inputs)], deviceOperations=0))
    print(json.dumps(dict(review=pin(O/'review.json'), freeze=pin(O/'freeze.json'), checks=len(checks), findings=[]), indent=2))

if __name__ == '__main__':
    main()
