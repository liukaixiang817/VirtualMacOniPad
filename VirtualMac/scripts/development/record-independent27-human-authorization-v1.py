#!/usr/bin/env python3
"""Record the actual human reply for the frozen 140-hash bootstrap scope."""
import datetime
import hashlib
import importlib.util
import json
import pathlib
import sys

sys.dont_write_bytecode = True
R = pathlib.Path(__file__).resolve().parents[3]
N = R / 'DeviceDiagnostics/2026-10-08-full-macos27-cpu-vmm'
P = N / 'independent27-device-bootstrap-controller-v3-attempt1'
O = N / 'independent27-user-authorized-initialization-v1'


def pin(path):
    data = path.read_bytes()
    return {'path': str(path), 'bytes': len(data),
            'sha256': hashlib.sha256(data).hexdigest()}


def write(path, data):
    with path.open('x') as stream:
        json.dump(data, stream, ensure_ascii=False, indent=2)
        stream.write('\n')


scope_pin = pin(P / 'scope.json')
assert scope_pin['sha256'] == '5eb7c12fc8f5f7bdedd369240bcb829106dbb059b9caf23441c74f26aba7f488'
scope = json.loads((P / 'scope.json').read_bytes())
assert len(scope['trustCacheCDHashes']) == len(set(scope['trustCacheCDHashes'])) == 140
review = N / 'independent27-final-firmware-products-controller-peer-v1-attempt1/controller-review.json'
assert pin(review)['sha256'] == 'add0fad0dca0c003fa715531a33de541d2afeb59779e3ae74def2ece1eb9b303'
O.mkdir(mode=0o700)
write(O / 'authorization.json', {
    'schema': 'Actual human exact independent27 initialization authorization v1',
    'authorized': True,
    'humanUserAuthorization': True,
    'recordedUTC': datetime.datetime.now(datetime.timezone.utc).isoformat(),
    'questionItemId': '["request_user_input_async","call_Ga7Y0iYgaTCd3KU1Jz9SDS0E",0]',
    'humanReplyVerbatim': '授权这份 140 条目清单及有界初始化',
    'scope': scope_pin,
    'trustCacheCDHashes': scope['trustCacheCDHashes'],
    'trustCacheRegistrationCount': 140,
    'initializationExternalWallSeconds': 45,
    'questionTerms': {
        'newOwnedDirectoryInstallation': True,
        'mobileAppAndChildInitializationOnce': True,
        'cleanupOnlyExactlyIdentifiedOwnedProcesses': True,
        'individualTrustCacheWithdrawalProven': False,
        'trustMayRemainUntilIPadReboot': True,
        'deletingFilesDoesNotWithdrawTrust': True
    },
    'deviceOperationsByThisRecorder': 0
})
ready = {
    'schema': 'Root concrete reviewed independent27 serial dispatch ready v1',
    'readyForRootSerialDispatch': True,
    'packetCandidate': pin(P / 'candidate.json'),
    'packetFreeze': pin(P / 'freeze.json'),
    'controller': pin(P / 'control.py'),
    'independentReviews': [pin(review)],
    'specificUserAuthorization': pin(O / 'authorization.json'),
    'deviceOperationsByThisRecorder': 0
}
write(O / 'ready.json', ready)
module_spec = importlib.util.spec_from_file_location('frozen_controller', P / 'control.py')
module = importlib.util.module_from_spec(module_spec)
module_spec.loader.exec_module(module)
module.ready_gate(P, O / 'ready.json')
write(O / 'freeze.json', {'files': [pin(O / 'authorization.json'),
       pin(O / 'ready.json'), pin(pathlib.Path(__file__).resolve())],
       'deviceOperations': 0})
print(json.dumps({'authorization': pin(O / 'authorization.json'),
                 'ready': pin(O / 'ready.json'), 'freeze': pin(O / 'freeze.json'),
                 'actualExactReadyGatePassed': True}))
