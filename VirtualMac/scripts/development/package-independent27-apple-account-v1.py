#!/usr/bin/env python3
"""Package the exact tested account App/runtime and its separate restore helpers.

Keeps the existing package and bundle identifiers, radio/media resources, and
the original 1.2.4 restore stack. Does not deploy or publish anything.
"""
import argparse
import importlib.util
import json
from pathlib import Path
import plistlib
import shutil
import tempfile

HERE = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location('radio_package', HERE / 'package-independent27-radio100.py')
prior = importlib.util.module_from_spec(spec)
spec.loader.exec_module(prior)
BASE_SHA = '37a44c51c9d691dab281c29086c61ae68fb86384927ab9fe15c4608cf1dc65a9'
RELEASE_BASE_SHA = 'ae80ea6406fb56e5ab04fd028b866c0c2d6aabd1d9b05852663ee941624d600c'
INSTALLER_VERSION = '2:1.2.4+617.1f873e57cc'


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--tested-deb', required=True, type=Path)
    parser.add_argument('--candidate', required=True, type=Path)
    parser.add_argument('--installer', required=True, type=Path)
    parser.add_argument('--output', required=True, type=Path)
    parser.add_argument('--version', default='1008-1')
    args = parser.parse_args()
    candidate = json.loads((args.candidate / 'candidate.json').read_text())
    assert prior.sha(args.tested_deb) == (RELEASE_BASE_SHA if candidate['release'] else BASE_SHA)
    installer = json.loads((args.installer / 'candidate.json').read_text())
    assert len(installer['files']) == 3
    assert candidate['newGuestAppleAccountEnabledByDefault']
    assert candidate['appleAccountAvailableDuringSetupAssistant']
    supported_builds = candidate['auditedGuestBuilds']
    assert supported_builds == ['24G90', '25G83', '26A5416b', '26B123']
    if candidate['release']:
        prior.run('dpkg', '--compare-versions', '1008', 'lt', args.version)
    output = args.output.resolve()
    output.mkdir(parents=True, exist_ok=True)
    filename = ('VirtualMac_2.0.0beta8-r1_' if candidate['release'] else 'VirtualMac_AppleAccount_')
    destination = output / (filename + args.version + '.deb')
    assert not destination.exists()
    with tempfile.TemporaryDirectory(prefix='virtualmac-account-package-') as temp:
        work = Path(temp)
        stage = work / 'stage'
        prior.run('dpkg-deb', '--raw-extract', args.tested_deb, stage)
        controls = stage / 'DEBIAN'
        metadata = stage / prior.METADATA
        old_catalog = prior.radio_catalog(stage / prior.APP)
        changed = set()
        for row in candidate['files']:
            prefix, relative = row['relativePath'].split('/', 1)
            root = prior.APP if prefix == 'app' else prior.RUNTIME27
            target = stage / root / relative
            source = Path(row['new']['path'])
            if row['old'] is None:
                assert prefix == 'app' and relative == 'RecommendedRestoreImages.plist'
                assert not target.exists()
            else:
                assert target.is_file() and not target.is_symlink()
                assert prior.sha(target) == row['old']['sha256'], row['relativePath']
            assert prior.sha(source) == row['new']['sha256']
            shutil.copyfile(source, target)
            changed.add('/' + target.relative_to(stage).as_posix())

        new_executables = set()
        for row in installer['files']:
            source = Path(row['path'])
            assert prior.sha(source) == row['sha256'] and source.stat().st_size == row['bytes']
            assert row['remote'].startswith('/var/root/VirtualMac/install/')
            target = stage / row['remote'][1:]
            assert not target.exists()
            target.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(source, target)
            target.chmod(int(row['mode'], 8))
            changed.add(row['remote'])
            if row.get('cdhash'):
                assert prior.cdhash(target) == row['cdhash']
                new_executables.add(row['remote'])

        pins = {}
        for line in (metadata / 'files.sha256').read_text().splitlines():
            digest, name = line.split(None, 1)
            actual = prior.sha(stage / name[1:])
            assert name in changed or actual == digest, name
            pins[name] = actual
        for name in changed: pins[name] = prior.sha(stage / name[1:])
        (metadata / 'files.sha256').write_text(''.join(f'{digest}  {name}\n' for name, digest in sorted(pins.items())))
        trust = []
        for line in (metadata / 'trustcache-v2.txt').read_text().splitlines():
            cdhash, digest, name = line.split(None, 2)
            if name in changed: cdhash, digest = prior.cdhash(stage / name[1:]), pins[name]
            assert pins[name] == digest
            trust.append((cdhash, digest, name))
        for name in sorted(new_executables): trust.append((prior.cdhash(stage / name[1:]), pins[name], name))
        (metadata / 'trustcache-v2.txt').write_text(''.join(' '.join(row) + '\n' for row in trust))
        (metadata / 'trustcache.txt').write_text(''.join(f'{cd} {name}\n' for cd, _, name in trust))

        # These helpers are new files below a root-owned original installation
        # directory. Do not change that package's ancestor directory modes.
        root_directories = {'var/root', 'var/root/VirtualMac', 'var/root/VirtualMac/install'}
        paths = sorted(p for p in stage.rglob('*') if controls not in (p, *p.parents)
            and p.relative_to(stage).as_posix() not in root_directories)
        body = (controls / 'control').read_text()
        old_version = next(line for line in body.splitlines() if line.startswith('Version: '))
        body = prior.replace_once(body, old_version + '\n', 'Version: ' + args.version + '\n')
        info = plistlib.loads((stage / prior.APP / 'Info.plist').read_bytes())
        assert info['CFBundleIdentifier'] == prior.PACKAGE
        if candidate['release']:
            assert info['VirtualMacPackageRevision'] == args.version
            assert 'VM27SharedRadioDevelopmentRevision' not in info
            old_name = next(line for line in body.splitlines() if line.startswith('Name: '))
            body = prior.replace_once(body, old_name + '\n',
                'Name: VirtualMac ' + info['CFBundleShortVersionString'] + '\n')
        dependency = next(line for line in body.splitlines() if line.startswith('Depends: '))
        body = prior.replace_once(body, dependency + '\n', dependency + ', com.mac.virtual (= ' + INSTALLER_VERSION + ')\n')
        size = sum(p.stat().st_size for p in paths if p.is_file() and not p.is_symlink())
        old_size = next(line for line in body.splitlines() if line.startswith('Installed-Size: '))
        body = prior.replace_once(body, old_size + '\n', f'Installed-Size: {(size + 1023)//1024}\n')
        body += (' Apple Account is enabled by default during Setup Assistant for new audited macOS 15, 26 and 27 guests.\n'
                 ' Each new guest receives a persistent identity before restore and its first boot.\n')
        (controls / 'control').write_text(body)

        for name in ['preinst', 'postinst', 'prerm']:
            script = controls / name
            text = script.read_text()
            # A restore is also an active VM owner. Refuse changes until it ends.
            marker = '*/VirtualMacFull13Runtime-v1/*)'
            if marker in text:
                text = prior.replace_once(text, marker,
                    '*/VirtualMacFull13Runtime-v1/*|*/VirtualMac/install/install-macos|'
                    '*/VirtualMac/install/install-account-v1|*/VirtualMac/payload/VirtualMachine.xpc/*|'
                    '*/VirtualMac/payload/Installation.xpc/*)')
            if name == 'postinst':
                text = text.replace('1006-2+radio100', args.version)
                if candidate['release']:
                    text = text.replace('beta6-r2', 'beta8-r1').replace('beta7', 'beta8-r1')
                    text = text.replace('revision=1007', 'revision=' + args.version)
                marker = '/var/jb/usr/lib/TweakInject/VM27GestureGuard.dylib|'
                text = prior.replace_once(text, marker, marker + '|'.join(sorted(new_executables)) + '|')
                provision = '\nphase=verify-account-installer\n'
                for row in installer['files']:
                    provision += 'test -f ' + row['remote'] + ' && test ! -L ' + row['remote'] + '\n'
                    provision += 'chown 0:0 ' + row['remote'] + '\nchmod ' + row['mode'] + ' ' + row['remote'] + '\n'
                text = prior.replace_once(text, '\nphase=provision-private-cache\n', provision + '\nphase=provision-private-cache\n')
            script.write_text(text)
            prior.run('/bin/sh', '-n', script)
        prior.run('codesign', '--verify', '--deep', '--strict', stage / prior.APP)
        assert prior.radio_catalog(stage / prior.APP) == old_catalog
        writer = prior.load_helper('build-virtualmac2-deb.py').write_deb
        result = work / destination.name
        writer(result, prior.archive(controls, sorted(controls.iterdir())), prior.archive(stage, paths), prior.EPOCH)
        verify = work / 'verified'
        prior.run('dpkg-deb', '--raw-extract', result, verify)
        for name, digest in pins.items():
            target = verify / name[1:]
            assert prior.sha(target) == digest, name
            assert target.stat().st_mode & 0o7777 == (stage / name[1:]).stat().st_mode & 0o7777
        prior.run('codesign', '--verify', '--deep', '--strict', verify / prior.APP)
        symbols = set(prior.run('nm', '-j', verify / prior.APP / 'VirtualMacIndependent27').decode().splitlines())
        for name in ('VMAppleAccountPrepareInstallationV1', 'VMAppleAccountPrepareBootV1',
                     'VMAppleAccountMakeProfileV1', 'VMAppleAccountRestoreBuildV1'):
            assert '_' + name in symbols, name
        for relative in ('parent-flat/VM27HVVMProduction.dylib',
            'child-flat/VMM.bundle/Contents/XPCServices/com.apple.Virtualization.VirtualMachine.xpc/Contents/MacOS/VM27HVVMProduction.dylib'):
            assert b'Setup Assistant\0' in (verify / prior.RUNTIME27 / relative).read_bytes()
        assert prior.radio_catalog(verify / prior.APP) == old_catalog
        shutil.copyfile(result, destination)
    (output / 'SHA256SUMS').write_text(prior.sha(destination) + '  ' + destination.name + '\n')
    (output / 'package-manifest.json').write_text(json.dumps(dict(package=prior.PACKAGE,
        version=args.version, sha256=prior.sha(destination), changedFiles=sorted(changed),
        appCDHash=candidate['appCDHash'], installerDependency=INSTALLER_VERSION,
        release=candidate['release'],
        newGuestAppleAccountEnabledByDefault=True,
        appleAccountAvailableDuringSetupAssistant=True,
        auditedGuestBuilds=supported_builds,
        installVersionRecommendations=candidate['installVersionRecommendations'],
        allVersionsAndLocalIPSWChoices=True,
        perGuestIdentityCreatedBeforeRestore=True,
        existingGuestIdentitiesNotReplaced=True,
        guestDataIncluded=False, cloudAcceptanceClaimed=False), indent=2) + '\n')
    print(destination)


if __name__ == '__main__': main()
