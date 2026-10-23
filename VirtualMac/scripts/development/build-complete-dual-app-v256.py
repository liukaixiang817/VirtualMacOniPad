"""App256: App255 code whole, with owned native graphics defaults migration."""
import copy
import hashlib
import io
import json
import pathlib
import shutil
import tarfile

R = pathlib.Path(__file__).resolve().parents[3]
N = R / 'DeviceDiagnostics/2026-10-08-full-macos27-cpu-vmm'


def pin(path):
    path = pathlib.Path(path).resolve()
    data = path.read_bytes()
    return dict(path=str(path), bytes=len(data), sha256=hashlib.sha256(data).hexdigest())


previous = N / 'complete-dual-actual-app-v255-attempt1/candidate.json'
old = json.loads(previous.read_bytes())
for row in old['sourceFiles'] + old['objects'] + old['actualIncludeClosure'] + old['appFiles']:
    assert pin(row['path']) == row, row['path']
payload = pathlib.Path('/private/tmp/vm27-native-graphics-guest-tools-v3/guest-tools/VirtualMacGuestTools.tar.gz')
migration = R / 'VirtualMac/vz/guest/restore_owned_native_graphics_v1.sh'
with tarfile.open(payload, 'r:gz') as archive:
    members = archive.getmembers()
    assert all(not item.issym() and not item.islnk() and not pathlib.PurePosixPath(item.name).is_absolute()
               and '..' not in pathlib.PurePosixPath(item.name).parts for item in members)
    resource = 'Library/VirtualMac/Virtual Mac Guest Tools.app/Contents/Resources/' + migration.name
    assert archive.extractfile(resource).read() == migration.read_bytes()
    library = 'Library/VirtualMac/OpenGLPVGCompat.dylib'
    old_payload = pathlib.Path(old['guestToolsPayload']['path'])
    with tarfile.open(old_payload, 'r:gz') as baseline:
        previous_library = baseline.extractfile(library).read()
output = N / 'complete-dual-actual-app-v256-attempt1'
output.mkdir(mode=0o700)
# Preserve the exercised OpenGL binary, including its existing install-name.
# A rebuild in a different directory changes that load-command unnecessarily.
assembled_payload = output / 'VirtualMacGuestTools.tar.gz'
with tarfile.open(payload, 'r:gz') as source, tarfile.open(assembled_payload, 'w:gz') as target:
    for member in source.getmembers():
        data = previous_library if member.name == library else (
            source.extractfile(member).read() if member.isfile() else None)
        if data is not None:
            member.size = len(data)
        target.addfile(member, io.BytesIO(data) if data is not None else None)
app = output / 'VirtualMacIndependent27.app'
shutil.copytree(pathlib.Path(old['binary']['path']).parent, app)
shutil.copyfile(assembled_payload, app / 'GuestTools/VirtualMacGuestTools.tar.gz')
binary = app / 'VirtualMacIndependent27'
assert binary.read_bytes() == pathlib.Path(old['binary']['path']).read_bytes()
inputs = [pin(R / path) for path in (
    'VirtualMac/vz/guest/VirtualMacGuestToolsApp_v3_native_graphics_defaults.m',
    'VirtualMac/vz/guest/restore_owned_native_graphics_v1.sh',
    'VirtualMac/scripts/build-guest-tools.sh',
)]
candidate = copy.deepcopy(old)
candidate.update(schema='App256 App255 code whole with owned native graphics defaults migration',
    builder=pin(__file__), inheritedCompiledAppCandidate=pin(previous), binary=pin(binary),
    appFiles=[pin(path) for path in sorted(app.rglob('*')) if path.is_file()],
    actualChangedAppObjectIndices=[], actualUnchangedCompiledObjects=len(old['objects']),
    actualNewAppCompilations=0, guestToolsPayload=pin(assembled_payload), guestToolsSourceInputs=inputs,
    guestToolsBuiltArchive=pin(payload), previousOpenGLLibraryPreserved=True,
    nativeGraphicsMigrationRequiresOwnedBackup=True, nativeGraphicsUserEditsPreserved=True,
    codeSigned=False, deviceOperations=0, trustCacheOperations=0)
(output / 'candidate.json').write_text(json.dumps(candidate, indent=2) + '\n')
(output / 'freeze.json').write_text(json.dumps(dict(files=[
    pin(path) for path in sorted(output.rglob('*')) if path.is_file()
] + [pin(__file__), pin(previous), pin(payload), *inputs], deviceOperations=0), indent=2) + '\n')
print(json.dumps(dict(candidate=pin(output / 'candidate.json'), guestToolsPayload=pin(assembled_payload))))
