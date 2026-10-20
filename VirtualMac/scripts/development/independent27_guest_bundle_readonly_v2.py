#!/usr/bin/env python3
"""Explicit read-only Root dispatcher; requires real successful initialization."""
import argparse
import getpass
import importlib.util
import json
import pathlib
import sys

sys.dont_write_bytecode = True


def main():
    parser = argparse.ArgumentParser()
    for name in ('packet', 'initializer-launch', 'initializer-post', 'peer-review', 'output'):
        parser.add_argument('--' + name, type=pathlib.Path, required=True)
    args = parser.parse_args()
    packet = args.packet.resolve()
    candidate = json.loads((packet / 'candidate.json').read_bytes())
    spec = importlib.util.spec_from_file_location('normal_guest_pinned_common', candidate['common']['path'])
    common = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(common)
    common.need(pathlib.Path(__file__).resolve() == packet / 'read.py', 'exact prepared readonly runner')
    for row in json.loads((packet / 'freeze.json').read_bytes())['files']:
        common.exact(row)
    review = json.loads(args.peer_review.read_bytes())
    common.need(review.get('findings') == [] and review.get('readonlyPacketCandidate') == common.pin(packet / 'candidate.json'),
                'actual independent readonly packet review')
    _, _, _, _ = common.initializer_success(candidate['initializerCandidate']['path'],
        args.initializer_launch, args.initializer_post)
    output = args.output.resolve()
    common.need(output.parent == common.N and not output.exists(), 'new exclusive actual read receipt directory')
    output.mkdir(mode=0o700)
    request = dict(action='guest-readonly', preparedCandidate=common.pin(packet / 'candidate.json'),
        initializerCandidate=candidate['initializerCandidate'], actualPriorLaunch=common.pin(args.initializer_launch.resolve()),
        actualPriorPost=common.pin(args.initializer_post.resolve()), independentReview=common.pin(args.peer_review.resolve()),
        startedUTC=common.utc(), script=candidate['script'], deviceWrites=0, processSignals=0, trustCacheOperations=0)
    common.dump(output / 'request.json', request)
    controller = common.load_module(common.exact(candidate['controller']), 'readonly_actual_initializer_transport')
    password = getpass.getpass('iPad password: ')
    status, stdout, stderr, error = controller.run_remote(common.exact(candidate['script']).read_text(), b'', True, password)
    password = None
    (output / 'stdout').write_bytes(stdout)
    (output / 'stderr').write_bytes(stderr)
    row = dict(action='guest-readonly', finishedUTC=common.utc(), request=common.pin(output / 'request.json'),
        transportExit=status, transportError=error, stdout=common.pin(output / 'stdout'), stderr=common.pin(output / 'stderr'),
        deviceWrites=0, processSignals=0, trustCacheOperations=0, nativeCPUOperations=0)
    common.dump(output / 'receipt.json', row)
    common.need(status == 0, 'actual guest read failed; preserved receipt, no retry')
    facts = common.parse_guest(stdout.decode(), output)
    facts.update(actualGuestReadonly=common.pin(output / 'receipt.json'), guestStarted=False)
    common.dump(output / 'configuration.json', facts)
    print(json.dumps(dict(receipt=common.pin(output / 'receipt.json'), configuration=common.pin(output / 'configuration.json'))))


if __name__ == '__main__':
    main()
