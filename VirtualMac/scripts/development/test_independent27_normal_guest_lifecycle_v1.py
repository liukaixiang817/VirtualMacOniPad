#!/usr/bin/env python3
"""Finite HOST pipe/ledger checks; no device, initializer, or guest fixtures.

The local executable emulates the wire only. Its records cannot satisfy the
production ready gate or initializer receipt gate, and are kept as host fixtures.
"""
import importlib.util
import json
import pathlib
import shlex
import shutil
import subprocess
import sys
from unittest import mock

sys.dont_write_bytecode = True
import independent27_normal_guest_common_v2 as common


FAKE = r'''
import json,pathlib,sys
mode,output,app,child,nonce=sys.argv[1:]
parent='a'*64;childStart='b'*64
print('OWN_APP_ID 31001 1 501 '+parent+' '+app,flush=True)
print('OWN_CHILD_ID 31002 31001 501 '+childStart+' '+child,flush=True)
offeredNonce=('c'*64 if mode=='wrong-nonce' else nonce)
offeredPID=('31003' if mode=='wrong-identity' else '31001')
print('OWN_HANDOFF_OFFER '+offeredNonce+' '+offeredPID+' '+parent+' 31002 '+childStart+' 1:2 1 3',flush=True)
if mode in ('wrong-nonce','wrong-identity'):
 sys.stdin.readline();sys.exit(0)
if mode=='early-eof':sys.exit(0)
line=sys.stdin.readline().rstrip('\n')
root=pathlib.Path(output)
if line=='ACK '+nonce:
 assert (root/'handoff-ledger.json').is_file() and (root/'handoff-ack.json').is_file()
 ledger=json.loads((root/'handoff-ledger.json').read_bytes())
 assert pathlib.Path(ledger['actualReceivedStdoutPrefix']['path']).is_file()
 (root/'local-ACK-observed').write_text(line)
 print('OWN_HANDOFF_COMMITTED '+nonce,flush=True)
 if mode=='duplicate-offer':
  print('OWN_HANDOFF_OFFER '+nonce+' 31001 '+parent+' 31002 '+childStart+' 1:2 1 3',flush=True)
else:
 print('INDEPENDENT27_OWN_APP_AND_CHILD_OFF',flush=True)
 sys.exit(81)
'''


def load(path, name):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def main():
    root = common.N / 'independent27-normal-guest-lifecycle-host-wire-v1-attempt3'
    common.need(not root.exists(), 'new finite HOST-only model directory')
    root.mkdir(mode=0o700)
    source_dir = pathlib.Path(__file__).resolve().parent
    lifecycle = load(source_dir / 'independent27_normal_guest_lifecycle_v1.py', 'normal_host_wire_lifecycle')
    builder = load(source_dir / 'prepare-independent27-normal-guest-lifecycle-v1.py', 'normal_host_syntax_builder')
    actual_controller = common.N / 'independent27-owned-bundle-device-v3-attempt1/control.py'
    controller = load(actual_controller, 'actual_process_guard_source')
    (root / 'fake-wire.py').write_text(FAKE)
    real_popen = subprocess.Popen
    tests = []
    for mode, confirm, expected in (('success', True, 0), ('no-confirm', False, 81),
                                   ('wrong-nonce', True, 125), ('wrong-identity', True, 125),
                                   ('early-eof', True, 0), ('duplicate-offer', True, 125)):
        output = root / mode
        output.mkdir(mode=0o700)
        common.dump(output / 'request.json', dict(hostWireFixture=True, noDevice=True, action='start'))
        (output / 'candidate.json').write_text('{}\n')
        candidate = dict(sessionNonce='d' * 64, ownAppMain=controller.APP_MAIN,
                         ownChildMain=controller.CHILD_MAIN, ownLog=common.LOG)
        def local_popen(*args, **kwargs):
            return real_popen([sys.executable, str(root / 'fake-wire.py'), mode, str(output),
                              candidate['ownAppMain'], candidate['ownChildMain'], candidate['sessionNonce']],
                             **kwargs)
        with mock.patch.object(lifecycle.subprocess, 'Popen', local_popen):
            status, stdout, stderr, error, sent = lifecycle.stream_start(common, output, candidate,
                output, '# HOST wire fixture; never sent to SSH', 'unused-host-fixture', confirm)
        common.need(status == expected, 'expected finite actual pipe outcome: ' + mode)
        ledger = (output / 'handoff-ledger.json').exists()
        ack = (output / 'handoff-ack.json').exists()
        if mode in ('success', 'duplicate-offer'):
            common.need(ledger and ack and sent and (output / 'local-ACK-observed').exists(), 'durable records precede actual ACK')
        if mode == 'no-confirm':
            common.need(ledger and not ack and not sent and b'OWN_APP_AND_CHILD_OFF' in stdout, 'EOF retains armed cleanup')
        if mode in ('wrong-nonce', 'wrong-identity'):
            common.need(not ledger and not ack and not sent, 'bad offer never acknowledged')
        tests.append(dict(mode=mode, status=status, ledgerPersisted=ledger, ackAttemptPersisted=ack,
                          ACKSent=sent, actualPipeOnly=True, error=error))
    # Only render fragments with explicit syntax placeholders; no production packet or ready artifact.
    facts = dict(priorLogMetadata='1:2:501:501:600:1:0', priorLogSHA256='0' * 64)
    syntax = {'start': builder.render_start(controller, {}, facts, 'd' * 64),
              'observe': builder.render_owned(controller, 'observe').replace('@NONCE@', "'" + 'd' * 64 + "'"),
              'stop': builder.render_owned(controller, 'stop').replace('@NONCE@', "'" + 'd' * 64 + "'"),
              'guest': common.guest_shell()}
    for name, text in syntax.items():
        subprocess.run(['/bin/sh', '-n'], input=text.encode(), check=True)
        (root / (name + '-syntax-only.sh')).write_text(text)
    inner = {name: shlex.split(text)[-1] for name, text in syntax.items() if name != 'guest'}
    common.need(controller.PROCESS_FUNCTIONS in inner['start'] and controller.PROCESS_FUNCTIONS in inner['stop'],
                'actual process guards copied whole, not rewritten')
    uiopen = [shlex.split(line) for line in inner['start'].splitlines() if line.startswith('/var/jb/usr/bin/uiopen ')]
    common.need(sum(len(call) == 2 and call[1].startswith('virtualmac27://start-vm?') for call in uiopen) == 1,
                'one real normal URL call site')
    common.need('OWN_HANDOFF_OFFER' in inner['start'] and 'own_handoff=1' in inner['start'] and
                inner['start'].index('IFS= read -r own_ack') < inner['start'].index('own_handoff=1'),
                'remote cleanup disarms only after exact ACK and rescan')
    common.need('132 /var/jb/bin/sh -c' in syntax['start'] and '20 /var/jb/bin/sh -c' in syntax['stop'],
                '132+3 maximum start and20+3 stop bounds')
    common.need('own_late_progress' in syntax['start'], 'late actual frame advancement required')
    common.need('CS_ENTITLEMENTS_VALIDATED' not in '\n'.join(syntax.values()) and 'jbctl' not in '\n'.join(syntax.values()),
                'no permission flag or TC mutation in normal source')
    report = dict(schema='Finite normal guest HOST pipe/ledger source checks v1', tests=tests,
        syntaxChecks=list(syntax), processFunctionsSHA256=__import__('hashlib').sha256(controller.PROCESS_FUNCTIONS.encode()).hexdigest(),
        findings=[], finiteHostScopePassed=True, deviceOperations=0, actualInitializerReceiptGenerated=False,
        actualGuestReadyGenerated=False, actualGuestStarted=False, actualVSOCKOrSSHTested=False,
        limitations=['Local child wire only; not SSH/sudo/iPad shell, UIKit, VZ or guest execution.',
                    'Syntax placeholders are not candidate facts and never create a production packet.'])
    common.dump(root / 'report.json', report)
    common.dump(root / 'freeze.json', dict(files=[common.pin(p) for p in (
        pathlib.Path(__file__).resolve(), source_dir / 'independent27_normal_guest_common_v2.py',
        source_dir / 'independent27_normal_guest_lifecycle_v1.py', source_dir / 'prepare-independent27-normal-guest-lifecycle-v1.py',
        actual_controller, root / 'fake-wire.py', root / 'report.json',
        *[root / (name + '-syntax-only.sh') for name in syntax])], deviceOperations=0))
    print(json.dumps(dict(report=common.pin(root / 'report.json'), freeze=common.pin(root / 'freeze.json'))))


if __name__ == '__main__':
    main()
