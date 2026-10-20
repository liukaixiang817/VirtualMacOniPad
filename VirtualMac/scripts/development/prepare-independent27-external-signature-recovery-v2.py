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
OLD = N/'independent27-external-signature-device-v1-attempt1'
OUT = N/'independent27-external-signature-recovery-v2-attempt1'
sp = importlib.util.spec_from_file_location('frozen_six_delta', OLD/'control.py')
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
    snapshot = N/'independent27-before-external-signature-recovery-readonly-v1/receipt.json'
    read = json.loads(snapshot.read_bytes())
    need(read['transportExit'] == 0 and read['deviceWrites'] == read['processSignals'] == 0, 'actual read-only identity')
    stdout = m.exact(read['stdout']).read_text()
    expected = 'OWN_APP_ID 91431 1 501 3cde1b76a3d3abe85c5b87597ea8af5d4a81792c79817425bf0119094784c789 '+m.APP_MAIN
    need(expected+'\n' in stdout and 'OWN_CHILD_ID ' not in stdout, 'exact live own App and no child')
    need('OWN_LOG_META 16777220:47302916:501:501:600:1:751\n' in stdout and
         'OWN_LOG_SHA256 f3a4328f1791518149bd06c7f9086d1b06d0ce6f648f8665bdd35fd97395caf0 ' in stdout,
         'actual log remains exact original751')
    for row in json.loads((OLD/'freeze.json').read_bytes())['files']:
        m.exact(row)
    body = m.prefix(0)+m.PROCESS_FUNCTIONS+'''
own_app_pid=91431
own_app_start=3cde1b76a3d3abe85c5b87597ea8af5d4a81792c79817425bf0119094784c789
scan_own
[ "$own_child_pid" = 0 ]
[ "$(realpath "$OWN_APP_MAIN")" = "$OWN_APP_MAIN" ]
[ "$(stat -c %u:%g:%a:%h:%s "$OWN_APP_MAIN")" = 501:501:755:1:870288 ]
[ "$(sha256sum "$OWN_APP_MAIN" | cut -d ' ' -f1)" = 586eec6115501e8331ac76fde31e802401217aa30346a9f829437b888fa8106a ]
[ ! -e "$OWN_STAGE" ] && [ ! -L "$OWN_STAGE" ]
printf 'OWN_READONLY_IDENTIFIED_REOPENED_APP 91431 1 501 3cde1b76a3d3abe85c5b87597ea8af5d4a81792c79817425bf0119094784c789\n'
cleanup_own
'''+m.off_check()+'''
[ -f "$OWN_LOG" ] && [ ! -L "$OWN_LOG" ]
[ "$(stat -c %d:%i:%u:%g:%a:%h:%s "$OWN_LOG")" = 16777220:47302916:501:501:600:1:751 ]
[ "$(sha256sum "$OWN_LOG" | cut -d ' ' -f1)" = f3a4328f1791518149bd06c7f9086d1b06d0ce6f648f8665bdd35fd97395caf0 ]
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
    candidate = dict(schema='Same authorized six-hash own-product recovery v2', preparer=pin(__file__),
        priorCandidate=pin(OLD/'candidate.json'), authorizedOriginalScope=pin(OLD/'scope.json'),
        scope=pin(OUT/'scope.json'), archive=pin(OUT/'products.tar'), controller=pin(OUT/'control.py'),
        scripts=rows, priorActualPreflightFailure=pin(failure), actualOwnAppReadonlySnapshot=pin(snapshot),
        unchangedAllSevenOriginalActionScripts=True, identicalAuthorizedScopeAndDeltaArchive=True,
        readonlyIdentifiedOwnPID=91431, readonlyIdentifiedOwnPIDStartHash='3cde1b76a3d3abe85c5b87597ea8af5d4a81792c79817425bf0119094784c789',
        actions=['close-reopened', 'preflight', 'stage', 'verify', 'trust', 'launch', 'post'],
        actualChangedFiles=9, actualUnchangedFiles=243, actualNewTrustEntries=6,
        actualUnchangedSignedImages=134, maximumQuotedCommandBytes=max(sizes.values()), quotedCommandBytes=sizes,
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
                      'newTrustEntries': 6, 'deviceOperations': 0}))


if __name__ == '__main__':
    main()
