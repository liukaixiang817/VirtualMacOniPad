"""Prepare the bounded App258 resource-only update from installed App257."""
from pathlib import Path
import hashlib
import io
import json
import shlex
import tarfile

R = Path(__file__).resolve().parents[3]
N = R / 'DeviceDiagnostics/2026-10-08-full-macos27-cpu-vmm'
O = N / 'native-cache-ownership-device-v235-attempt2'
O.mkdir(mode=0o700)


def pin(path):
    path = Path(path).resolve()
    data = path.read_bytes()
    return dict(path=str(path), bytes=len(data), sha256=hashlib.sha256(data).hexdigest())


old = json.loads((N / 'complete-dual-signed-app-v257-attempt1/candidate.json').read_bytes())
new = json.loads((N / 'complete-dual-signed-app-v258-attempt1/candidate.json').read_bytes())
assert old['actualSignature']['embeddedEntitlements'] == new['actualSignature']['embeddedEntitlements']
previous_scope = json.loads((N / 'gic-wake-subset-device-v234-attempt1/scope.json').read_bytes())
device = str(Path(previous_scope['files'][0]['path']).parent)
files = []
for relative in ['VirtualMacIndependent27', '_CodeSignature/CodeResources', 'GuestTools/VirtualMacGuestTools.tar.gz']:
    before = pin(Path(old['app']) / relative)
    after = pin(Path(new['app']) / relative)
    if before['sha256'] != after['sha256']:
        files.append(dict(path=device + '/' + relative, old=before, new=after,
                          mode='755' if relative == 'VirtualMacIndependent27' else '644'))
assert len(files) == 3
hashes = [new['actualSignature']['cdhash']]
stage = '/private/var/mobile/Library/.VM27-native-cache-ownership-v235'
scope = dict(schema='App258 remove automatic live icon-cache deletion and Apple-service restart',
    files=files, newTrustCacheCDHashes=hashes, stage=stage, permissionsUnchanged=True,
    mainCodeWhole=True, allRuntimeFilesWhole=True, guestSystemServicesUnmodified=True)
(O / 'scope.json').write_text(json.dumps(scope, indent=2) + '\n')
with tarfile.open(O / 'product.tar', 'w') as archive:
    for index, row in enumerate(files):
        data = Path(row['new']['path']).read_bytes()
        info = tarfile.TarInfo('new-' + str(index))
        info.size = len(data)
        info.mode = int(row['mode'], 8)
        archive.addfile(info, io.BytesIO(data))
q = shlex.quote
body = (N / 'native-defaults-device-v233-attempt1/install-root.sh').read_text().split('[ -f /private/preboot/', 1)[0]
body = body.replace('.VM27-native-defaults-v233', '.VM27-native-cache-ownership-v235')
template_prior = json.loads((N / 'complete-dual-signed-app-v255-attempt1/candidate.json').read_bytes())
assert template_prior['binary']['sha256'] in body
body = body.replace(template_prior['binary']['sha256'], old['binary']['sha256'])
for row in files:
    body += f'[ -f {q(row["path"])} ] && [ ! -L {q(row["path"])} ]\n'
    body += f'[ "$(sha256sum {q(row["path"])} | cut -d \' \' -f1)" = {row["old"]["sha256"]} ]\n'
body += '[ ! -e "$STAGE" ] && [ ! -L "$STAGE" ]\nmkdir -m 700 "$STAGE"\ncat > "$STAGE/product.tar"\n'
body += f'[ "$(sha256sum "$STAGE/product.tar" | cut -d \' \' -f1)" = {pin(O / "product.tar")["sha256"]} ]\n'
body += 'tar -xpf "$STAGE/product.tar" -C "$STAGE"\n'
for index, row in enumerate(files):
    body += f'cp -p {q(row["path"])} "$STAGE/backup-{index}"\n'
    body += f'[ "$(sha256sum "$STAGE/new-{index}" | cut -d \' \' -f1)" = {row["new"]["sha256"]} ]\n'
for value in hashes:
    body += 'jbctl trustcache add ' + value + '\n'
for index, row in enumerate(files):
    body += f'chown 501:501 "$STAGE/new-{index}"\nchmod {row["mode"]} "$STAGE/new-{index}"\n'
    body += f'mv "$STAGE/new-{index}" {q(row["path"])}\n'
body += 'cp -p /tmp/VirtualMacIndependent27.log "$STAGE/previous-app-log"\n: > /tmp/VirtualMacIndependent27.log\n'
body += "printf 'NATIVE_CACHE_OWNERSHIP_UPDATE_COMPLETE\\n'\n"
(O / 'install-root.sh').write_text(body)
controller = (N / 'root-install-native-defaults-app256-v1.py').read_text()
controller = controller.replace('native-defaults-device-v233-attempt1', O.name)
controller = controller.replace('NATIVE_DEFAULTS_UPDATE_COMPLETE', 'NATIVE_CACHE_OWNERSHIP_UPDATE_COMPLETE')
(N / 'root-install-native-cache-ownership-app258-v1.py').write_text(controller)
start = (N / 'normal285-gic-wake-subset-start-v1.sh').read_text()
start = start.replace(old['binary']['sha256'], new['binary']['sha256'])
start = start.replace('APP257_GIC_WAKE_SUBSET_NORMAL285', 'APP258_NATIVE_CACHE_OWNERSHIP_NORMAL286')
(N / 'normal286-native-cache-ownership-start-v1.sh').write_text(start)
print(json.dumps(dict(scope=pin(O / 'scope.json'), files=len(files), hashes=hashes)))
