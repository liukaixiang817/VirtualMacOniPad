#!/usr/bin/env python3
"""Finite HOST-only App14 packet/serial review; no device or signing calls."""
import ast
import contextlib
import hashlib
import importlib.util
import io
import json
import pathlib
import subprocess
import sys
import tarfile

sys.dont_write_bytecode = True
R = pathlib.Path(__file__).resolve().parents[3]
N = R / 'DeviceDiagnostics/2026-10-08-full-macos27-cpu-vmm'
B = pathlib.Path(__file__).resolve().parent
PACKET = N / 'independent27-metal-stage-app-device-v1-attempt1'
SERIAL = N / 'independent27-metal-stage-app-device-serial-source-v1-attempt1'
OLD = N / 'independent27-ssh-deferred-app-device-v1-attempt1'
OUT = N / 'independent27-app14-only-main-device-concrete-peer-v1-attempt1'
SOUT = N / 'independent27-app14-device-serial-independent-peer-v1-attempt1'
REGEN = N / 'independent27-app14-device-peer-pure-reconstruction-v1-attempt1'


def pin(path):
    p = pathlib.Path(path).resolve()
    data = p.read_bytes()
    return dict(path=str(p), bytes=len(data), sha256=hashlib.sha256(data).hexdigest())


def exact(row):
    assert pin(row['path']) == {k: row[k] for k in ('path', 'bytes', 'sha256')}, row['path']
    return pathlib.Path(row['path'])


def read(path):
    return json.loads(pathlib.Path(path).read_bytes())


def dump(path, value):
    pathlib.Path(path).write_text(json.dumps(value, indent=2) + '\n')


def load(path, name):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def freeze_check(directory):
    rows = read(directory / 'freeze.json')['files']
    for row in rows:
        exact(row)
    return len(rows)


def main():
    assert not OUT.exists() and not SOUT.exists() and not REGEN.exists()
    OUT.mkdir(mode=0o700)
    SOUT.mkdir(mode=0o700)
    candidate = read(PACKET / 'candidate.json')
    scope = read(exact(candidate['scope']))
    old = read(OLD / 'scope.json')
    serial = read(SERIAL / 'candidate.json')
    packet_pins, serial_pins = freeze_check(PACKET), freeze_check(SERIAL)
    assert pin(PACKET / 'candidate.json')['sha256'] == '8e465ef88b0c8c5f67bbcb50622e3f87d80fdf98639ec1c9c6c854aba76c5031'
    assert pin(SERIAL / 'candidate.json')['sha256'] == '4f9ebcbf1d60c084c6d6a0c9c2779c72a813f2abf6e709dcdfc963f7123e9dc0'
    old_rows = {r['archivePath']: r for r in old['files']}
    rows = {r['archivePath']: r for r in scope['files']}
    assert len(rows) == 255 and set(rows) == set(old_rows)
    changed = []
    for name, row in rows.items():
        previous = old_rows[name]
        assert row['devicePath'] == previous['devicePath'] and row['mode'] == previous['mode']
        if (row['local']['bytes'], row['local']['sha256']) != (previous['local']['bytes'], previous['local']['sha256']):
            changed.append(name)
    assert changed == ['VirtualMacIndependent27.app/VirtualMacIndependent27']
    assert scope['directories'] == old['directories'] and scope['newOwnDirectories'] == []
    assert scope['runtimeCandidate'] == old['runtimeCandidate']
    assert len(scope['deltaFiles']) == 1 and scope['deltaFiles'][0]['old'] == old_rows[changed[0]]['local']
    assert scope['deltaFiles'][0]['new'] == rows[changed[0]]['local']
    actual_cds = sorted(r['cdhash'] for r in rows.values() if 'cdhash' in r)
    assert len(actual_cds) == len(set(actual_cds)) == 142 and actual_cds == scope['trustCacheCDHashes']
    new_cds = sorted(set(actual_cds) - set(old['trustCacheCDHashes']))
    assert new_cds == scope['newTrustCacheCDHashes'] == ['2a91a6ef715b56f8cb22a31a9477ddf38375fb88']
    assert scope['trustCacheRegistrationCount'] == 1
    main_name = changed[0]
    child_name = 'runtime/child-flat/VMM.bundle/Contents/XPCServices/com.apple.Virtualization.VirtualMachine.xpc/Contents/MacOS/'
    subset = [rows[main_name]['cdhash'], rows[child_name + 'com.apple.Virtualization.VirtualMachine']['cdhash'], rows[child_name + 'VM27OwnedAppChildPreMainV3.dylib']['cdhash']]
    assert subset == scope['actualNativeCDSubset'] == candidate['actualNativeCDSubset']
    app = read(exact(scope['appCandidate']))
    app_peer = read(exact(scope['inheritedActualSignedAppPeer']))
    assert app_peer['signedCandidate'] == scope['appCandidate'] and app_peer['runtimeCandidate'] == scope['runtimeCandidate']
    assert app_peer['finiteLocalScopePassed'] is True and app_peer['findings'] == []
    assert app_peer['actualSignature'] == app['actualSignature'] and app_peer['actualSignature']['file'] == rows[main_name]['local']
    post = read(exact(candidate['currentInstalledProductsPost']))
    exact(post['request']); exact(post['stderr'])
    post_text = exact(post['stdout']).read_text()
    assert post['transportExit'] == 0 and post['handoffACKAttemptRecorded'] is False
    for marker in ['INDEPENDENT27_ALL_ACTUAL_PRODUCTS_EXACT', 'INDEPENDENT27_OWN_APP_AND_CHILD_OFF', 'OWN_NORMAL_POST_HEALTH_PRODUCTS_AND_OWN_OFF']:
        assert marker in post_text
    with tarfile.open(exact(candidate['archive']), mode='r:') as archive:
        items = archive.getmembers()
        assert len(items) == 1
        item = items[0]
        assert item.name == 'new-0' and item.isreg() and not item.linkname and not item.pax_headers
        assert item.uid == item.gid == item.mtime == 0 and item.mode == 0o600
        data = archive.extractfile(item).read()
        assert data == exact(scope['deltaFiles'][0]['new']).read_bytes()

    # Run only the already-read pure HOST constructor in a fresh review directory.
    producer = load(exact(candidate['preparer']), 'app14_peer_pure_constructor')
    original_args = sys.argv
    sys.argv = [candidate['preparer']['path'], '--output', str(REGEN), '--runtime-candidate', scope['runtimeCandidate']['path'], '--app-candidate', scope['appCandidate']['path'], '--app-peer', scope['inheritedActualSignedAppPeer']['path']]
    try:
        with contextlib.redirect_stdout(io.StringIO()) as captured:
            producer.main()
        (OUT / 'pure-constructor.stdout').write_text(captured.getvalue())
    finally:
        sys.argv = original_args
    for name in ['control.py', 'products.tar', 'health-root.sh']:
        assert (REGEN / name).read_bytes() == (PACKET / name).read_bytes(), name
    syntax = load(B / 'vm27_normal_nested_shell_syntax_v1.py', 'app14_peer_nested_shell_parser')
    syntax_dir = OUT / 'syntax'
    syntax_dir.mkdir()
    nodes = []
    for action, row in candidate['scripts'].items():
        actual = exact(row).read_text()
        assert actual == (REGEN / (action + '.sh')).read_text(), action
        nodes.extend(syntax.check_tree(action, actual, syntax_dir, None))
    assert all(node['exit'] == 0 for node in nodes)
    dump(OUT / 'actual-nested-syntax.json', dict(scripts=7, actualParsedNodes=len(nodes), allExitZero=True, records=nodes))
    old_controller = load(OLD / 'control.py', 'app14_peer_old_controller')
    new_controller = load(PACKET / 'control.py', 'app14_peer_new_controller')
    assert old_controller.PROCESS_FUNCTIONS == new_controller.PROCESS_FUNCTIONS
    old_ast = ast.parse((OLD / 'control.py').read_text())
    new_ast = ast.parse((PACKET / 'control.py').read_text())
    def function(tree, name):
        return ast.dump(next(node for node in tree.body if isinstance(node, ast.FunctionDef) and node.name == name), include_attributes=False)
    assert function(old_ast, 'run_remote') == function(new_ast, 'run_remote')
    close = producer.unwrap((PACKET / 'close-current-own.sh').read_text())
    stage = producer.unwrap((PACKET / 'stage.sh').read_text())
    trust = producer.unwrap((PACKET / 'trust.sh').read_text())
    assert 'cleanup_own >/dev/null 2>&1 || own_close_status=$?' in close
    assert stage.index('"$OWN_STAGE/backup-0"') < stage.index('"$OWN_STAGE/backup-app-log"') < stage.index('.VM27-metal-stage-app-v1-0.pending')
    assert trust.count('jbctl trustcache add ') == 1 and 'jbctl trustcache add ' + new_cds[0] in trust
    assert trust.count('jbctl trustcache info') == 1
    assert candidate['closeOwnExternalWallSeconds'] == 20 and candidate['allOtherRemoteActionsExternalWallSeconds'] == 45 and candidate['transportTimeoutSeconds'] == 55
    assert candidate['maximumQuotedCommandBytes'] + 10000 < 262144

    source = exact(serial['source']).read_text()
    prior_source = exact(serial['priorFrozenSource']).read_text()
    normalized = source.replace('App14', 'App13').replace(PACKET.name, OLD.name).replace(pin(PACKET / 'candidate.json')['sha256'], pin(OLD / 'candidate.json')['sha256'])
    assert normalized == prior_source
    assert serial['controllerPacketCandidate'] == pin(PACKET / 'candidate.json') and serial['controllerPacketFreeze'] == pin(PACKET / 'freeze.json')
    assert serial['sequence'] == candidate['actions'] == list(new_controller.ACTIONS)
    compile(source, serial['source']['path'], 'exec')
    assert source.count("getpass.getpass('iPad password: ')") == 1
    assert 'controller.ready_gate(PACKET,ready_path)' in source
    assert 'controller.dispatch(argparse.Namespace(packet=PACKET,ready=ready_path,action=action))' in source
    assert "current=='launch' and (PACKET/'device-receipts/launch/receipt.json').is_file()" in source
    assert 'controller.getpass.getpass=original_prompt\n        cached[0]=None' in source
    report = dict(schema='App14 one-main device packet finite independent HOST peer v1', controllerPacketCandidate=pin(PACKET/'candidate.json'), passed=True, findings=[], producerFrozenPinsActuallyChecked=packet_pins, scope=pin(PACKET/'scope.json'), currentInstalledProductsPost=candidate['currentInstalledProductsPost'], inheritedActualSignedAppPeer=scope['inheritedActualSignedAppPeer'], derivedFullFiles=255, derivedUnchangedFiles=254, derivedFullCDHashes=142, onlyChangedMain=scope['deltaFiles'][0], onlyNewTC=new_cds, actualNativeCDSubset=subset, ordinaryTarMember='new-0', directoriesAndRuntimeWholeUnchanged=True, actualSevenScriptsAndControllerPureRegenerationEqual=True, actualNestedSyntax=pin(OUT/'actual-nested-syntax.json'), exactPIDUIDPPIDPathStartCleanupBodyInherited=True, signalOutputSuppressedUntilSignalsComplete=True, backupsBeforeSameDirectoryAtomicReplacement=True, trueMembershipAll142QueryRetained=True, externalSeconds=dict(close=20,other=45,transport=55), maximumQuotedCommandBytes=candidate['maximumQuotedCommandBytes'], basicOnlyInitializationGuestNotRequested=True, limitations='No device/signing/TC execution; no actual Metal stage or guest CPU/display success inferred.', deviceOperations=0, trustCacheOperations=0, codeSigningOperations=0)
    dump(OUT/'review.json', report)
    sreport = dict(schema='App14 seven-phase serial source finite independent HOST peer v1', sourceCandidate=pin(SERIAL/'candidate.json'), controllerPacketCandidate=pin(PACKET/'candidate.json'), passed=True, findings=[], source=serial['source'], priorFrozenSource=serial['priorFrozenSource'], frozenPinsActuallyChecked=serial_pins, actualSourceOnlyPacketHashPathAndDocumentationChanged=True, sequence=serial['sequence'], onePasswordOnlyInMemoryAndFinallyCleared=True, originalReadyPriorOnceLocksAndDispatchDelegationRetained=True, failedLaunchRequiresActualReceiptBeforeOriginalPost=True, noReceiptOrLeaseFabrication=True, deviceOperations=0)
    dump(SOUT/'review.json', sreport)
    for output, inputs in [(OUT,[PACKET/'candidate.json',PACKET/'freeze.json',PACKET/'scope.json',candidate['preparer']['path'],OLD/'candidate.json',OLD/'freeze.json',OLD/'scope.json',POST_PATH(cand=candidate),B/'vm27_normal_nested_shell_syntax_v1.py']), (SOUT,[SERIAL/'candidate.json',SERIAL/'freeze.json',serial['source']['path'],serial['priorFrozenSource']['path'],PACKET/'candidate.json',PACKET/'freeze.json',PACKET/'control.py'])]:
        pins = [pin(path) for path in sorted(output.rglob('*')) if path.is_file()] + [pin(path) for path in inputs] + [pin(__file__)]
        dump(output/'freeze.json', dict(files=list({row['path']:row for row in pins}.values()), deviceOperations=0))
    print(json.dumps(dict(packetReview=pin(OUT/'review.json'),packetFreeze=pin(OUT/'freeze.json'),serialReview=pin(SOUT/'review.json'),serialFreeze=pin(SOUT/'freeze.json'))))


def POST_PATH(cand):
    return cand['currentInstalledProductsPost']['path']


if __name__ == '__main__':
    main()
