#!/usr/bin/env python3
"""Recover an unopened update after a precisely identified own App reappeared."""
import importlib.util
import json
import pathlib
import shlex
import shutil
import subprocess
import sys
sys.dont_write_bytecode = True
R = pathlib.Path(__file__).resolve().parents[3]
N = R/'DeviceDiagnostics/2026-10-08-full-macos27-cpu-vmm'
OLD = N/'independent27-main-identity-device-v1-attempt1'
OUT = N/'independent27-main-identity-recovery-v2-attempt1'
sp = importlib.util.spec_from_file_location('frozen_five_delta', OLD/'control.py')
m = importlib.util.module_from_spec(sp)
sp.loader.exec_module(m)
pin, need, dump = m.pin, m.need, m.dump


def main():
    need(not OUT.exists(), 'fresh recovery packet')
    failure = OLD/'device-receipts/preflight/receipt.json'
    failed = json.loads(failure.read_bytes())
    need(failed['transportExit'] == 8, 'actual pre-write own-process refusal')
    need(not any((OLD/(action+'-dispatched.json')).exists() for action in ('stage', 'trust', 'launch')),
         'no previous update, new trust or initialization was executed')
    snapshot = N/'independent27-before-delta-recovery-readonly-v1/receipt.json'
    read = json.loads(snapshot.read_bytes())
    need(read['transportExit'] == 0 and read['deviceWrites'] == read['processSignals'] == 0, 'actual read-only identity')
    stdout = m.exact(read['stdout']).read_text()
    expected = 'OWN_APP_ID 90350 1 501 0546501f976260f13090eb6feb86c2bb104f27b8e6e0e2551eca9ad402ea75a9 '+m.APP_MAIN
    need(expected+'\n' in stdout and 'OWN_CHILD_ID ' not in stdout, 'exact live own App and no child')
    need('OWN_LOG_META 16777220:47302916:501:501:600:1:671\n' in stdout and
         'OWN_LOG_SHA256 80a2d77b0daa3fcd615e7ce62a482bcc311efb9e52a3464d8f93cc3a706413cb ' in stdout,
         'actual log remains exact original671')
    for row in json.loads((OLD/'freeze.json').read_bytes())['files']:
        m.exact(row)
    body = m.prefix(0)+m.PROCESS_FUNCTIONS+'''
own_app_pid=90350
own_app_start=0546501f976260f13090eb6feb86c2bb104f27b8e6e0e2551eca9ad402ea75a9
scan_own
[ "$own_child_pid" = 0 ]
[ "$(realpath "$OWN_APP_MAIN")" = "$OWN_APP_MAIN" ]
[ "$(stat -c %u:%g:%a:%h:%s "$OWN_APP_MAIN")" = 501:501:755:1:869696 ]
[ "$(sha256sum "$OWN_APP_MAIN" | cut -d ' ' -f1)" = 0d621fdffa11d3298575ee66c8f1776c0c930c18cfa473dc232da831b1a860bc ]
[ ! -e "$OWN_STAGE" ] && [ ! -L "$OWN_STAGE" ]
printf 'OWN_READONLY_IDENTIFIED_REOPENED_APP 90350 1 501 0546501f976260f13090eb6feb86c2bb104f27b8e6e0e2551eca9ad402ea75a9\n'
cleanup_own
'''+m.off_check()+'''
[ -f "$OWN_LOG" ] && [ ! -L "$OWN_LOG" ]
[ "$(stat -c %d:%i:%u:%g:%a:%h:%s "$OWN_LOG")" = 16777220:47302916:501:501:600:1:671 ]
[ "$(sha256sum "$OWN_LOG" | cut -d ' ' -f1)" = 80a2d77b0daa3fcd615e7ce62a482bcc311efb9e52a3464d8f93cc3a706413cb ]
printf 'INDEPENDENT27_EXACT_REOPENED_OWN_APP_OFF_OLD_LOG_RETAINED\n'
'''
    close = m.prefix(0)+'/var/jb/usr/bin/timeout --signal=TERM --kill-after=3 20 /var/jb/bin/sh -c '+shlex.quote(body)+'\n'
    source = (OLD/'control.py').read_text()
    before = "ACTIONS = ('preflight', 'stage', 'verify', 'trust', 'launch', 'post')"
    need(source.count(before) == 1, 'one exact action list')
    source = source.replace(before, "ACTIONS = ('close-reopened', 'preflight', 'stage', 'verify', 'trust', 'launch', 'post')")
    before = "auth['scope'] == pin(packet/'scope.json') and"
    need(source.count(before) == 1, 'one exact specific authorization scope')
    source = source.replace(before, "auth['scope'] == json.loads((packet/'candidate.json').read_bytes())['authorizedOriginalScope'] and\n         pin(packet/'scope.json')['sha256'] == auth['scope']['sha256'] and pin(packet/'scope.json')['bytes'] == auth['scope']['bytes'] and")
    before = "previous = {'stage': 'preflight', 'verify': 'stage', 'trust': 'verify', 'launch': 'trust', 'post': 'launch'}.get(args.action)"
    need(source.count(before) == 1, 'one exact dependency chain')
    source = source.replace(before, "previous = {'preflight': 'close-reopened', 'stage': 'preflight', 'verify': 'stage', 'trust': 'verify', 'launch': 'trust', 'post': 'launch'}.get(args.action)")
    compile(source, str(OUT/'control.py'), 'exec')
    OUT.mkdir(mode=0o700)
    shutil.copyfile(OLD/'scope.json', OUT/'scope.json')
    shutil.copyfile(OLD/'products.tar', OUT/'products.tar')
    (OUT/'control.py').write_text(source)
    scripts = {'close-reopened': close}
    for action in ('preflight', 'stage', 'verify', 'trust', 'launch', 'register', 'post'):
        scripts[action] = (OLD/(action+'.sh')).read_text()
    rows = {}
    sizes = {}
    for action, script in scripts.items():
        subprocess.run(['/bin/sh', '-n'], input=script.encode(), check=True)
        command = ('sudo -k -S -p "" ' if action != 'launch' else '')+'/var/jb/bin/sh -c '+shlex.quote(script)
        need(len(command.encode())+10000 < 262144, 'actual argv reserve')
        path = OUT/(action+'.sh')
        path.write_text(script)
        rows[action] = pin(path)
        sizes[action] = len(command.encode())
    old = json.loads((OLD/'candidate.json').read_bytes())
    candidate = dict(schema='Same authorized five-hash own-product recovery v2', preparer=pin(__file__),
        priorCandidate=pin(OLD/'candidate.json'), authorizedOriginalScope=pin(OLD/'scope.json'),
        scope=pin(OUT/'scope.json'), archive=pin(OUT/'products.tar'), controller=pin(OUT/'control.py'),
        scripts=rows, priorActualPreflightFailure=pin(failure), actualOwnAppReadonlySnapshot=pin(snapshot),
        unchangedAllSevenOriginalActionScripts=True, identicalAuthorizedScopeAndDeltaArchive=True,
        readonlyIdentifiedOwnPID=90350, readonlyIdentifiedOwnPIDStartHash='0546501f976260f13090eb6feb86c2bb104f27b8e6e0e2551eca9ad402ea75a9',
        actions=['close-reopened', 'preflight', 'stage', 'verify', 'trust', 'launch', 'post'],
        actualChangedFiles=8, actualUnchangedFiles=244, actualNewTrustEntries=5,
        actualUnchangedSignedImages=135, maximumQuotedCommandBytes=max(sizes.values()), quotedCommandBytes=sizes,
        processIdentityCleanupAndTransportFunctionsUnchanged=True, closeOwnAppExternalWallSeconds=20,
        allOriginalActionsExternalWallSeconds=45, transportTimeoutSeconds=55,
        deviceOperations=0, trustCacheOperations=0, guestBootRequested=False, readyForDeviceExecution=False)
    dump(OUT/'candidate.json', candidate)
    files = json.loads((OLD/'freeze.json').read_bytes())['files']
    files += [pin(path) for path in OUT.iterdir() if path.is_file()]
    files += [pin(__file__), pin(failure), failed['stdout'], failed['stderr'], pin(snapshot), read['script'], read['stdout'], read['stderr']]
    for row in files:
        m.exact(row)
    dump(OUT/'freeze.json', dict(files=list({row['path']: row for row in files}.values()), deviceOperations=0))
    print(json.dumps({'candidate': pin(OUT/'candidate.json'), 'scopeBytesAndSHAUnchanged': True,
                      'newTrustEntries': 5, 'deviceOperations': 0}))


if __name__ == '__main__':
    main()
