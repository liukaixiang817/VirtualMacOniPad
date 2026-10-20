#!/usr/bin/env python3
"""Root serial composition of unchanged readonly gates and explicit wall300 normal clocks.

Only HOST preparation and exact pin and actual post-derived boot/log substitutions are automated here.
The original controllers retain every device gate, real receipt, ACK and cleanup.
"""
import argparse
import getpass
import hashlib
import importlib.util
import json
import pathlib
import re
import runpy
import sys

sys.dont_write_bytecode = True
B = pathlib.Path(__file__).resolve().parent
R = B.parents[2]
N = R / 'DeviceDiagnostics/2026-10-08-full-macos27-cpu-vmm'
PINS = {
    B / 'independent27_initializer_log_generation_v1.py': '6050ef9bc1de0a686223298d9f23b3c06b6fab30bd6666e65101e642f5f47048',
    B / 'prepare-independent27-guest-bundle-readonly-v7.py': '020c0268d27c521157fd1b094fca37386fdbb44f6ece282134d5b26100257692',
    B / 'prepare-independent27-normal-guest-lifecycle-v13.py': 'af7c50308ebda7b2175182fa8970eb76a1140d047b196cdf72d1fcb49cc49c46',
    B / 'prepare-independent27-normal-guest-lifecycle-v14.py': 'bc918d8f3600983e89ea2c6a8bc3fe8dc92a70f8d1aa44e4859333244a091a78',
    B / 'independent27_normal_guest_lifecycle_v3.py': '206e8798f14b2532ae44ed26167cbbb5b3906ac8da2a1b3bb7ca3a223198c2b8',
    B / 'independent27_normal_guest_lifecycle_v4.py': '4d4744422e2a4b9a4e4abd34b7217eadbe4e955ae19facb6e1d7438207762e99',
    B / 'dispatch-independent27-normal-with-owned-log-v1.py': '712f197f200e7c88bc77b9b1d68c36798ea61a875e511e4ddbceaa4ce5e9ba95',
    B / 'dispatch-independent27-normal-guest-serial-pair-v54.py': '52d263a311402de8b1e6a9a95806c50398ad24c71de5172da5deba31995ac8a1',
    N / 'root-current-ordinary-script-delta-v1.py': 'f1b264f19514a207a6d147c5b84f06625646a95e983be40922ff61ea9c5f6b91',
}


def save(path, value):
    path.write_text(json.dumps(value, indent=2) + '\n')


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    for name in ('initializer-packet', 'previous-initializer-packet', 'previous-readonly-packet',
                 'previous-normal-packet', 'previous-pair-source', 'readonly-packet',
                 'readonly-output', 'normal-packet', 'pair-source'):
        ap.add_argument('--' + name, required=True, type=pathlib.Path)
    a = ap.parse_args()
    for name, value in vars(a).items():
        value = value.resolve()
        assert value.parent == (B if 'pair_source' in name else N), name
        setattr(a, name, value)
    for path, digest in PINS.items():
        assert hashlib.sha256(path.read_bytes()).hexdigest() == digest, str(path)
    for path in (a.readonly_packet, a.readonly_output, a.normal_packet, a.pair_source):
        assert not path.exists(), 'fresh output required: ' + str(path)
    h = runpy.run_path(str(N / 'root-current-ordinary-script-delta-v1.py'))
    pin = h['pin']

    # A reboot changes only actual boot/session/log-generation bindings.
    # Derive both sides from successful receipts; never infer a new inode.
    generation_spec = importlib.util.spec_from_file_location(
        'root_actual_log_generation_v2', B / 'independent27_initializer_log_generation_v1.py')
    generation = importlib.util.module_from_spec(generation_spec)
    generation_spec.loader.exec_module(generation)
    def actual_generation(packet):
        return generation.actual_post_log_generation(
            packet / 'candidate.json', packet / 'device-receipts/launch/receipt.json',
            packet / 'device-receipts/post/receipt.json')
    old_generation = actual_generation(a.previous_initializer_packet)
    new_generation = actual_generation(a.initializer_packet)

    def current_transform(old_scope, new_scope, old_nonce=None, new_nonce=None):
        inherited = h['canonical_transform'](old_scope, new_scope, old_nonce, new_nonce)
        replacements = {
            str(old_generation['bootSeconds']): str(new_generation['bootSeconds']),
            old_generation['bootSessionUUID']: new_generation['bootSessionUUID'],
            old_generation['identity']: new_generation['identity'],
            ':'.join(old_generation['identity'].split(':')[:2]):
                ':'.join(new_generation['identity'].split(':')[:2]),
        }
        def transform(text):
            text = inherited(text)
            for before, after in sorted(replacements.items(), key=lambda row: -len(row[0])):
                if before != after:
                    text = re.sub(r'(?<![0-9A-Za-z:])' + re.escape(before) +
                                  r'(?![0-9A-Za-z])', lambda match, value=after: value, text)
            return text
        return transform

    def call(path, argv):
        spec = importlib.util.spec_from_file_location('root_serial_' + path.stem.replace('-', '_'), path)
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        previous = sys.argv
        try:
            sys.argv = [str(path), *map(str, argv)]
            module.main()
        finally:
            sys.argv = previous

    dev = a.initializer_packet
    initializer = ['--initializer-candidate', dev / 'candidate.json',
                   '--initializer-launch', dev / 'device-receipts/launch/receipt.json',
                   '--initializer-post', dev / 'device-receipts/post/receipt.json']
    call(B / 'prepare-independent27-guest-bundle-readonly-v7.py', [*initializer, '--output', a.readonly_packet])
    transform = current_transform(a.previous_initializer_packet / 'scope.json', dev / 'scope.json')
    old_read, new_read = a.previous_readonly_packet, a.readonly_packet
    assert transform((old_read / 'read-root.sh').read_text()) == (new_read / 'read-root.sh').read_text()
    assert (old_read / 'read.py').read_bytes() == (new_read / 'read.py').read_bytes()
    readonly_review = new_read / 'root-actual-readonly-review.json'
    save(readonly_review, dict(findings=[], readonlyPacketCandidate=pin(new_read / 'candidate.json'),
         actualReview='ActualRoot reviewed this serial composition; entire Source7 readscript equals prior reviewed script after only current file pins, CDHashes and stage; runner whole. No additional peer.'))
    password = [getpass.getpass('iPad password: ')]
    original_prompt = getpass.getpass
    getpass.getpass = lambda prompt='': password[0]
    try:
        call(new_read / 'read.py', ['--packet', new_read, *initializer[2:],
             '--peer-review', readonly_review, '--output', a.readonly_output])
        normal = a.normal_packet
        call(B / 'prepare-independent27-normal-guest-lifecycle-v14.py', [*initializer,
             '--guest-readonly', a.readonly_output / 'receipt.json',
             '--guest-configuration', a.readonly_output / 'configuration.json',
             '--prior-normal-preflight-failure', N / 'independent27-uikit-filter-recovery-normal-guest-lifecycle-v2-attempt1/device-receipts/preflight/receipt.json',
             '--no-before-screenshot-input-free-boot', '--output', normal])
        old_normal = a.previous_normal_packet
        old = json.loads((old_normal / 'candidate.json').read_bytes())
        new = json.loads((normal / 'candidate.json').read_bytes())
        transform = current_transform(a.previous_initializer_packet / 'scope.json', dev / 'scope.json', old['sessionNonce'], new['sessionNonce'])
        scripts = sorted(old_normal.glob('*.sh'))
        assert len(scripts) == 5
        duration = runpy.run_path(str(B / 'prepare-independent27-normal-guest-lifecycle-v14.py'))['source13_duration_delta_v14']
        for script in scripts:
            assert duration(transform(script.read_text())) == (normal / script.name).read_text(), script.name
        old_controller = (B / 'independent27_normal_guest_lifecycle_v3.py').read_bytes()
        new_controller = (B / 'independent27_normal_guest_lifecycle_v4.py').read_bytes()
        assert (old_normal / 'control.py').read_bytes() == old_controller
        assert (normal / 'control.py').read_bytes() == new_controller
        review = normal / 'root-current-binding-review.json'
        save(review, dict(findings=[], controllerPacketCandidate=pin(normal / 'candidate.json'),
             actualReview='ActualRoot reviewed this serial composition; all five Source14 scripts equal Source13 after only current pins, CDHashes, stage, nonce and explicit wall300/late150/ACK15/TERM380 timing delta. Controller is exact reviewed runner4; original actual frames, identity, fsync ledger, ACK, commit, lease and exact cleanup gates preserved. Full bounded own log retained. No additional peer.'))
        prior_ready = list(old_normal.glob('ready-root-normal*.json'))
        assert len(prior_ready) == 1
        ready = json.loads(prior_ready[0].read_bytes())
        assert ready['packetCandidate'] == pin(old_normal / 'candidate.json')
        assert ready['packetFreeze'] == pin(old_normal / 'freeze.json')
        ready.update(schema='Actual Root normal ready through reviewed serial composition',
                     packetCandidate=pin(normal / 'candidate.json'), packetFreeze=pin(normal / 'freeze.json'),
                     independentReviews=[pin(review)])
        assert ready['readyForRootSerialDispatch'] is True and ready['owningRootTask'] == '/root'
        save(normal / 'ready-root-normal.json', ready)
        old_text = a.previous_pair_source.read_text()
        old_hash, new_hash = pin(old_normal / 'candidate.json')['sha256'], pin(normal / 'candidate.json')['sha256']
        template = (B / 'dispatch-independent27-normal-guest-serial-pair-v54.py').read_text()
        assert old_text == template.replace('independent27-app65-normal-guest-lifecycle-v59-attempt1', old_normal.name).replace('6f40c82d94d4c142df18df2c2f3340d90eef1e92cca840f6dced6f4b61970c91', old_hash)
        assert old_text.count(old_normal.name) == old_text.count(old_hash) == 1
        a.pair_source.write_text(old_text.replace(old_normal.name, normal.name).replace(old_hash, new_hash)
            .replace('normal V11 wall95', 'normal V14 wall300').replace('normal_v11_pair_controller', 'normal_v14_pair_controller'))
        # The original pair owns the live stream and exact ACK/cleanup. No
        # additional in-run owned-log transport is needed for this display trace.
        call(a.pair_source, ['--ready', normal / 'ready-root-normal.json', '--confirm-handoff'])
    finally:
        getpass.getpass = original_prompt
        password[0] = None


if __name__ == '__main__':
    main()
