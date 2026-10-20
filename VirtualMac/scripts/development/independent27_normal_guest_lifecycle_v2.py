#!/usr/bin/env python3
"""Explicit Root lifecycle. No dispatch occurs at import or packet preparation.

A successful handoff is owned by the named Root active goal until exact stop.
The durable ACK record also retains ownership if the SSH response is lost.
"""
import argparse
import datetime
import getpass
import hashlib
import importlib.util
import json
import os
import pathlib
import re
import selectors
import shlex
import subprocess
import sys
import time

sys.dont_write_bytecode = True


def load_common(packet):
    candidate = json.loads((packet / 'candidate.json').read_bytes())
    spec = importlib.util.spec_from_file_location('normal_guest_exact_common', candidate['common']['path'])
    common = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(common)
    common.exact(candidate['common'])
    return common, candidate


def gate(common, packet, candidate, ready_path):
    common.need(pathlib.Path(__file__).resolve() == packet / 'control.py', 'exact copied packet dispatcher')
    ready = json.loads(ready_path.read_bytes())
    common.need(ready.get('readyForRootSerialDispatch') is True and ready.get('owningRootTask') == '/root' and
                ready.get('noNewTrustCacheEntries') is True and
                ready.get('packetCandidate') == common.pin(packet / 'candidate.json') and
                ready.get('packetFreeze') == common.pin(packet / 'freeze.json'), 'actual Root concrete normal packet ready')
    for row in json.loads((packet / 'freeze.json').read_bytes())['files']:
        common.exact(row)
    common.need(ready.get('independentReviews'), 'actual concrete normal lifecycle peer review')
    for row in ready['independentReviews']:
        review = json.loads(common.exact(row).read_bytes())
        common.need(review.get('findings') == [] and review.get('controllerPacketCandidate') == common.pin(packet / 'candidate.json'),
                    'exact concrete normal lifecycle peer findings')
    common.initializer_success(candidate['initializerCandidate']['path'],
        common.exact(candidate['initializerLaunch']), common.exact(candidate['initializerPost']))
    common.guest_success(common.exact(candidate['freshGuestReadonly']), common.exact(candidate['freshGuestConfiguration']),
        candidate['initializerPost'])
    return ready


def prior(common, packet, action, success):
    output = packet / 'device-receipts' / action
    receipt = json.loads((output / 'receipt.json').read_bytes())
    request = json.loads(common.exact(receipt['request']).read_bytes())
    common.need(request['packetCandidate'] == common.pin(packet / 'candidate.json') and request['action'] == action,
                'same packet actual predecessor')
    common.exact(receipt['stdout']);common.exact(receipt['stderr'])
    if success:
        common.need(receipt['transportExit'] == 0, 'actual predecessor must succeed')
    return receipt, common.pin(output / 'receipt.json')


def offer_clock_valid_v4(observation_started, late_progress, actual_monotonic_now):
    return observation_started is not None and actual_monotonic_now - observation_started >= 90 and late_progress


def stream_start(common, packet, candidate, output, script, password, confirm):
    env = dict(os.environ)
    env.update(VIRTUALMAC_SSH_PASSWORD=password, SSH_ASKPASS='/private/tmp/virtualmac-ipad-tools/ssh-askpass',
               SSH_ASKPASS_REQUIRE='force', DISPLAY='virtualmac-debug')
    command = '/var/jb/bin/sh -c ' + shlex.quote(script)
    argv = ['ssh', '-p', '2221', '-o', 'ConnectTimeout=8', '-o', 'ControlMaster=no', '-o', 'ControlPath=none',
            '-o', 'UserKnownHostsFile=/private/tmp/virtualmac-ipad-known-hosts', '-o', 'StrictHostKeyChecking=yes',
            'mobile@127.0.0.1', command]
    child = None
    selector = selectors.DefaultSelector()
    stdout, stderr, pending = bytearray(), bytearray(), bytearray()
    offer_seen = False
    observation_started = None
    late_baseline = None
    host_late_progress = False
    ack_sent = False
    error = None
    started = time.monotonic()
    try:
        child = subprocess.Popen(argv, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, env=env)
        for channel, stream in (('stdout', child.stdout), ('stderr', child.stderr)):
            os.set_blocking(stream.fileno(), False)
            selector.register(stream, selectors.EVENT_READ, channel)
        while selector.get_map():
            remaining = 145 - (time.monotonic() - started)
            if remaining <= 0:
                error = 'SSH 145-second bound; durable ACK retains declared Root ownership if possibly transferred'
                child.kill()
                break
            for key, _ in selector.select(min(remaining, 1.0)):
                raw = os.read(key.fd, 65536)
                if not raw:
                    selector.unregister(key.fileobj)
                    continue
                target = stdout if key.data == 'stdout' else stderr
                target.extend(raw)
                common.need(len(target) <= 4194304, 'bounded actual transport output')
                if key.data != 'stdout':
                    continue
                pending.extend(raw)
                while b'\n' in pending:
                    line, _, tail = pending.partition(b'\n')
                    pending = bytearray(tail)
                    text = line.decode('utf-8', 'strict')
                    if text.startswith('OWN_OBSERVATION_CLOCK_BEGIN_V4 '):
                        common.need(observation_started is None, 'one actual observation start marker')
                        observation_started = time.monotonic()
                    if text.startswith('OWN_OBSERVE '):
                        print(text, flush=True)
                        match = re.fullmatch(r'OWN_OBSERVE elapsed=([0-9]+) accept=([01]) state1=([01]) frames=([0-9]+) first=([0-9]+) last=([0-9]+) lateProgress=([01]) source=guarded-date', text)
                        common.need(match is not None and observation_started is not None, 'actual guarded wall observation row')
                        last_frame = int(match.group(6))
                        if time.monotonic() - observation_started >= 45:
                            if late_baseline is None:
                                late_baseline = last_frame
                            elif last_frame > late_baseline and match.group(3) == '1':
                                host_late_progress = True
                    if not text.startswith('OWN_HANDOFF_OFFER '):
                        continue
                    common.need(offer_clock_valid_v4(observation_started, host_late_progress, time.monotonic()), 'actual host monotonic90s and after45s advancing frames required before ACK')
                    common.need(not offer_seen, 'one actual handoff offer')
                    offer_seen = True
                    fields = text.split()
                    common.need(len(fields) == 9 and fields[1] == candidate['sessionNonce'], 'exact session handoff offer')
                    identities = common.identity_rows(stdout.decode(), candidate['ownAppMain'], candidate['ownChildMain'])
                    common.need(fields[2] == str(identities['APP']['pid']) and fields[3] == identities['APP']['startHash'] and
                                fields[4] == str(identities['CHILD']['pid']) and fields[5] == identities['CHILD']['startHash'],
                                'offered identities must equal captured actual direct App/child')
                    common.need(re.fullmatch(r'[1-9][0-9]*:[1-9][0-9]*', fields[6]) is not None and
                                fields[7].isdigit() and fields[8].isdigit() and 0 < int(fields[7]) < int(fields[8]),
                                'true log inode and advancing frame offer')
                    # A crash after ACK must still leave the actual received prefix.
                    with open(output / 'handoff-stdout-prefix', 'xb') as stream:
                        stream.write(stdout)
                        stream.flush()
                        os.fsync(stream.fileno())
                    ledger = dict(schema='Actual normal guest offered ownership ledger v1', owningRootTask='/root',
                        packetCandidate=common.pin(packet / 'candidate.json'), actualRequest=common.pin(output / 'request.json'),
                        createdUTC=common.utc(), nonce=fields[1], actualIdentities=identities,
                        actualReceivedStdoutPrefix=common.pin(output / 'handoff-stdout-prefix'),
                        actualLog=dict(path=candidate['ownLog'], inode=fields[6], uid=501, gid=501, mode=600, nlink=1, maxBytes=2097152),
                        observedFirstFrame=int(fields[7]), observedLastFrame=int(fields[8]),
                        offerLine=text, ownership='offered; remote cleanup remains armed until sole ACK',
                        actualVisibleGuest=False, actualSSHAvailable=False)
                    common.dump(output / 'handoff-ledger.json', ledger)
                    if not confirm:
                        child.stdin.close()  # EOF executes the still-armed remote cleanup trap.
                        continue
                    # Both durable records exist before even attempting the ACK write.
                    common.dump(output / 'handoff-ack.json', dict(ledger=common.pin(output / 'handoff-ledger.json'),
                        owningRootTask='/root', packetCandidate=common.pin(packet / 'candidate.json'),
                        createdUTC=common.utc(), explicitRootConfirmHandoff=True,
                        obligation='Root retains exact ownership from this attempted ACK until actual stop/off proof'))
                    child.stdin.write(('ACK ' + fields[1] + '\n').encode())
                    child.stdin.flush()
                    child.stdin.close()
                    ack_sent = True
        remaining = 145 - (time.monotonic() - started)
        if not error and remaining <= 0:
            raise subprocess.TimeoutExpired(argv, 145)
        status = child.wait(timeout=remaining) if not error else 124
    except (OSError, ValueError, UnicodeError, subprocess.TimeoutExpired) as caught:
        error = type(caught).__name__ + ': ' + str(caught)
        status = 125
        if child:
            # SSH closure triggers HUP or the independent132+3 remote deadline.
            if child.stdin and not child.stdin.closed:
                child.stdin.close()
            if child.poll() is None:
                child.kill()
    finally:
        selector.close()
        env.pop('VIRTUALMAC_SSH_PASSWORD', None)
        if child:
            if child.poll() is None:
                child.kill()
            child.wait()
            for stream in (child.stdout, child.stderr, child.stdin):
                if stream and not stream.closed:
                    stream.close()
    return status, bytes(stdout), bytes(stderr), error, ack_sent


def lease_data(common, packet, candidate, lease_path):
    lease_path = lease_path.resolve()
    start = packet / 'device-receipts' / 'start'
    common.need(lease_path == start / 'handoff-ledger.json', 'only exact actual offered ledger')
    ledger = json.loads(lease_path.read_bytes())
    ack = json.loads((start / 'handoff-ack.json').read_bytes())
    common.need(ack['ledger'] == common.pin(lease_path) and ack['owningRootTask'] == '/root' and
                ack['packetCandidate'] == common.pin(packet / 'candidate.json') and
                ledger['packetCandidate'] == ack['packetCandidate'] and ledger['nonce'] == candidate['sessionNonce'],
                'durable actual Root attempted ACK ownership, never arbitrary numeric PID')
    request = json.loads(common.exact(ledger['actualRequest']).read_bytes())
    common.need(request['action'] == 'start' and request['packetCandidate'] == ack['packetCandidate'], 'exact originating start')
    # The stdout prefix persisted at actual completion must reproduce both captures and this offer.
    stdout = common.exact(ledger['actualReceivedStdoutPrefix']).read_text()
    common.need(ledger['offerLine'] in stdout.splitlines(), 'actual received offered ledger line')
    identities = common.identity_rows(stdout, candidate['ownAppMain'], candidate['ownChildMain'])
    common.need(identities == ledger['actualIdentities'], 'immutable actual direct captures')
    actual_log = ledger['actualLog']
    common.need(actual_log['path'] == candidate['ownLog'] and
                re.fullmatch(r'[1-9][0-9]*:[1-9][0-9]*', actual_log['inode']) is not None, 'actual offered log generation')
    app, child = identities['APP'], identities['CHILD']
    data = f'{app["pid"]} {app["startHash"]} {child["pid"]} {child["startHash"]} {actual_log["inode"]} {candidate["sessionNonce"]}\n'
    return data.encode(), common.pin(lease_path)


def dispatch(args):
    packet = args.packet.resolve()
    common, candidate = load_common(packet)
    common.need(packet.parent == common.N, 'workspace actual packet')
    gate(common, packet, candidate, args.ready.resolve())
    action = args.action
    label = action if action != 'observe' else 'observe-' + str(args.sequence)
    common.need(action != 'observe' or args.sequence >= 1, 'positive exclusive observation sequence')
    output_root = packet / 'device-receipts'
    output_root.mkdir(mode=0o700, exist_ok=True)
    common.need(not output_root.is_symlink(), 'ordinary actual receipt root')
    output = output_root / label
    common.need(not output.exists(), 'bounded phase never repeated')
    lock = packet / 'normal-dispatch.lock'
    fd = os.open(lock, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    identity = os.fstat(fd)
    try:
        data = b''
        previous = []
        if action == 'start':
            row, row_pin = prior(common, packet, 'preflight', True)
            common.need((datetime.datetime.now(datetime.timezone.utc) -
                         datetime.datetime.fromisoformat(row['finishedUTC'])).total_seconds() <= 120,
                        'normal preflight must be fresh; no automatic retry')
            previous.append(row_pin)
        elif action in ('observe', 'stop'):
            common.need(args.lease is not None, 'exact actual durable Root lease required')
            data, row_pin = lease_data(common, packet, candidate, args.lease)
            previous.append(row_pin)
            common.need(not (packet / 'device-receipts/stop/receipt.json').exists(), 'lease cannot resume after stop attempt')
        elif action == 'post':
            if (packet / 'device-receipts/stop/receipt.json').exists():
                _, row_pin = prior(common, packet, 'stop', True)
            else:
                row, row_pin = prior(common, packet, 'start', False)
                common.need(row['transportExit'] != 0 and not (packet / 'device-receipts/start/handoff-ack.json').exists(),
                            'failed start post is independent readonly OFF-first only; no ACK ownership may be discarded')
                # The actual post script starts with fresh OFF detection and
                # rejects live processes. An initial prefix in old stdout is
                # never evidence of terminal cleanup from the failed start.
            previous.append(row_pin)
        output.mkdir(mode=0o700)
        common.dump(packet / (label + '-dispatched.json'), dict(action=action, label=label,
            packetCandidate=common.pin(packet / 'candidate.json'), startedUTC=common.utc()))
        script = common.exact(candidate['actions'][action]).read_text()
        common.dump(output / 'request.json', dict(action=action, label=label, packetCandidate=common.pin(packet / 'candidate.json'),
            ready=common.pin(args.ready.resolve()), script=common.pin(packet / (action + '.sh')), startedUTC=common.utc(),
            priorPins=previous, inputBytes=len(data), inputSHA256=hashlib.sha256(data).hexdigest(),
            explicitRootConfirmHandoff=args.confirm_handoff if action == 'start' else False,
            guestBootRequested=action == 'start', trustCacheOperations=0, owningRootTask='/root',
            failedStartPostCleanupFromInitialPrefixClaimed=False,
            failedStartPostIsIndependentReadonlyOffFirst=action == 'post'))
        password = getpass.getpass('iPad password: ')
        ack = False
        if action == 'start':
            status, stdout, stderr, error, ack = stream_start(common, packet, candidate, output, script, password, args.confirm_handoff)
        else:
            controller = common.load_module(common.exact(candidate['inheritedController']), 'normal_exact_short_transport')
            if action == 'observe':
                # This new135 bound cannot reuse the inherited55-second initializer transport.
                status, stdout, stderr, error = run_owned_long(script, data, password)
            else:
                status, stdout, stderr, error = controller.run_remote(script, data, action in ('preflight', 'post'), password)
        password = None
        (output / 'stdout').write_bytes(stdout)
        (output / 'stderr').write_bytes(stderr)
        committed = action == 'start' and ack and ('OWN_HANDOFF_COMMITTED ' + candidate['sessionNonce']) in stdout.decode(errors='replace').splitlines()
        if action == 'start' and status == 0 and not committed:
            status, error = 74, 'SSH returned0 without the exact real ownership commit; attempted ACK remains owned'
        common.dump(output / 'receipt.json', dict(action=action, label=label, finishedUTC=common.utc(),
            request=common.pin(output / 'request.json'), transportExit=status, transportError=error,
            stdout=common.pin(output / 'stdout'), stderr=common.pin(output / 'stderr'),
            handoffACKAttemptRecorded=(output / 'handoff-ack.json').exists(), handoffACKSent=ack,
            handoffCommitObserved=committed, owningRootTask='/root' if (output / 'handoff-ack.json').exists() or previous and action in ('observe', 'stop') else None,
            actualVisibleGuest=False, actualSSHAvailable=False, trustCacheOperations=0))
        if action == 'start' and (output / 'handoff-ack.json').exists():
            common.dump(output / 'handoff-result.json', dict(actualReceipt=common.pin(output / 'receipt.json'),
                ledger=common.pin(output / 'handoff-ledger.json'), ack=common.pin(output / 'handoff-ack.json'),
                owningRootTask='/root', commitObserved=committed,
                obligation='Explicit Root owner remains responsible until actual stop plus post/off; uncertain transport never releases owner'))
        print(json.dumps(json.loads((output / 'receipt.json').read_bytes())))
        print(stdout.decode(errors='replace')[-16000:])
        common.need(status == 0, 'actual bounded phase failed; preserve receipt and exact Root ownership/cleanup obligation')
    finally:
        live = os.lstat(lock)
        common.need((live.st_dev, live.st_ino) == (identity.st_dev, identity.st_ino), 'exact serial lock identity')
        os.close(fd)
        os.unlink(lock)


def run_owned_long(script, data, password):
    env = dict(os.environ)
    env.update(VIRTUALMAC_SSH_PASSWORD=password, SSH_ASKPASS='/private/tmp/virtualmac-ipad-tools/ssh-askpass',
               SSH_ASKPASS_REQUIRE='force', DISPLAY='virtualmac-debug')
    argv = ['ssh', '-p', '2221', '-o', 'ConnectTimeout=8', '-o', 'ControlMaster=no', '-o', 'ControlPath=none',
            '-o', 'UserKnownHostsFile=/private/tmp/virtualmac-ipad-known-hosts', '-o', 'StrictHostKeyChecking=yes',
            'mobile@127.0.0.1', '/var/jb/bin/sh -c ' + shlex.quote(script)]
    try:
        result = subprocess.run(argv, input=data, env=env, capture_output=True, timeout=145)
        return result.returncode, result.stdout, result.stderr, None
    except subprocess.TimeoutExpired as error:
        return 124, error.stdout or b'', error.stderr or b'', 'SSH145 timeout; exact Root lease remains owned'
    except OSError:
        return 125, b'', b'', 'SSH transport failed; exact Root lease remains owned'
    finally:
        env.pop('VIRTUALMAC_SSH_PASSWORD', None)


def main():
    parser = argparse.ArgumentParser()
    for name in ('packet', 'ready'):
        parser.add_argument('--' + name, type=pathlib.Path, required=True)
    parser.add_argument('--action', choices=('preflight', 'start', 'observe', 'stop', 'post'), required=True)
    parser.add_argument('--lease', type=pathlib.Path)
    parser.add_argument('--sequence', type=int, default=1)
    parser.add_argument('--confirm-handoff', action='store_true')
    dispatch(parser.parse_args())


if __name__ == '__main__':
    main()
