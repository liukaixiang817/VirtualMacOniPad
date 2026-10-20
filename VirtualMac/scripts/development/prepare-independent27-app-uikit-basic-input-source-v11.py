#!/usr/bin/env python3
"""Copy the actual App10 source and select genuine USB devices for owned UIKit."""
import argparse
import copy
import difflib
import hashlib
import json
import pathlib

R = pathlib.Path(__file__).resolve().parents[3]
N = R / 'DeviceDiagnostics/2026-10-08-full-macos27-cpu-vmm'
BASE = N / 'independent27-app-genuine-ssh-source-v10-attempt1/candidate.json'

def pin(path):
    path = pathlib.Path(path).resolve()
    data = path.read_bytes()
    return dict(path=str(path), bytes=len(data), sha256=hashlib.sha256(data).hexdigest())

def save(path, value):
    path.write_text(json.dumps(value, indent=2, ensure_ascii=False) + '\n')

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--output', required=True, type=pathlib.Path)
    args = parser.parse_args()
    out = args.output.resolve()
    assert out.parent == N and not out.exists()
    base = json.loads(BASE.read_bytes())
    assert pin(BASE)['sha256'] == '16ee1982d4423944d7cf83abc2af08450f3769bda8c1ea97cabeb8de7c5479aa'
    source_path = pathlib.Path(base['source']['path'])
    assert pin(source_path) == base['source']
    original = source_path.read_text()
    text = original
    edits = [
        ('BOOL useUSBKeyboard = [keyboardChoice isEqualToString:@"USBKeyboard"];',
         'BOOL useUSBKeyboard = VZIndependent27SourceRouteSelected() || [keyboardChoice isEqualToString:@"USBKeyboard"];'),
        ('BOOL useUSBMouse = [pointingChoice isEqualToString:@"USBMouse"];',
         'BOOL useUSBMouse = VZIndependent27SourceRouteSelected() || [pointingChoice isEqualToString:@"USBMouse"];'),
    ]
    for before, after in edits:
        assert text.count(before) == 1
        text = text.replace(before, after, 1)
    restored = text
    for before, after in edits:
        restored = restored.replace(after, before, 1)
    assert restored == original
    out.mkdir(mode=0o700)
    source = out / 'VirtualMacApp.independent27.uikit-basic-input-source-v11.m'
    source.write_text(text)
    diff = out / 'app-v10-to-v11.diff'
    diff.write_text(''.join(difflib.unified_diff(original.splitlines(True), text.splitlines(True), fromfile=str(source_path), tofile=str(source))))
    result = copy.deepcopy(base)
    result.update(schema='Copied App11 genuine USB keyboard and screen coordinate pointer for owned independent27 UIKit',
        source=pin(source), priorSourceCandidate=pin(BASE), sourceDiff=pin(diff), preparer=pin(__file__),
        ownedUIKitSelectsActualUSBKeyboardConfiguration=True,
        ownedUIKitSelectsActualUSBScreenCoordinatePointingDeviceConfiguration=True,
        sourceChangesOnlyTwoActualDeviceSelectionExpressions=True,
        savedGuestOptionsOrFilesModified=False, inputRuntimeProfileStillRequired=True,
        actualInputDelivered=False, actualVZRuntimeExecuted=False, deviceOperations=0)
    save(out / 'candidate.json', result)
    files = [pin(path) for path in out.iterdir() if path.is_file()]
    files += [pin(__file__), pin(BASE), pin(source_path), base['backendSource'], *base['newSSHBuildUnits']]
    save(out / 'freeze.json', dict(files=files, deviceOperations=0, trustCacheOperations=0))
    print(json.dumps(dict(candidate=pin(out / 'candidate.json'), freeze=pin(out / 'freeze.json'), source=pin(source))))

if __name__ == '__main__':
    main()
