"""Rebuild the actual restore catalog and version chooser in the signed App."""
import json
from pathlib import Path
import shutil
import subprocess


def rebuild(root, out, app, link, run):
    host = root / 'VirtualMac/vz/host/portable_app_v1/host'
    for name in ('VZRestoreCatalog.h', 'VZNewVMViewController.h'):
        shutil.copyfile(host / name, out / name)
    for name in ('VZRestoreCatalog', 'VZNewVMViewController'):
        old = next(a for a in link if str(a).endswith('-' + name + '.o'))
        recipes = json.loads((Path(old).parent / 'commands.json').read_text())
        args = next(c['argv'][:] for c in recipes if '-c' in c.get('argv', []) and
            c['argv'][c['argv'].index('-o') + 1] == old)
        source = out / (name + '_install_versions.m')
        shutil.copyfile(host / (name + '.m'), source)
        obj = out / (name + '_install_versions.o')
        args[args.index('-c') + 1] = source
        args[args.index('-o') + 1] = obj
        if '-MF' in args:
            args[args.index('-MF') + 1] = out / (name + '.d')
        args[args.index('-target') + 1] = 'arm64e-apple-ios16.1'
        args[args.index('-isysroot') + 1] = subprocess.check_output(
            ['xcrun', '--sdk', 'iphoneos', '--show-sdk-path'], text=True).strip()
        run('compile-install-versions-' + name, args)
        assert link.count(old) == 1
        link[link.index(old)] = obj
    resource = 'RecommendedRestoreImages.plist'
    shutil.copyfile(root / 'VirtualMac/resources' / resource, app / resource)
    keys = (
        'Choose macOS Version', 'Other macOS Versions', 'Local Restore Image',
        'Choose Another macOS Version', 'Browse available releases and developer betas',
        'Apple Account sign-in verified', 'Apple Account sign-in not verified', 'Recommended',
        'Recommended versions have passed Apple Account sign-in checks. You can also install other versions, with compatibility shown below.',
        'Select an IPSW file downloaded from Apple.',
    )
    for language in ('en', 'zh_CN'):
        relative = language + '.lproj/Localizable.strings'
        import plistlib
        translations = plistlib.loads(subprocess.check_output(['plutil', '-convert', 'xml1', '-o', '-',
            root / 'VirtualMac/resources/Localizations' / relative]))
        existing = plistlib.loads(subprocess.check_output(['plutil', '-convert', 'xml1', '-o', '-', app / relative]))
        with (app / relative).open('a') as strings:
            for key in keys:
                if key not in existing:
                    strings.write('\n' + json.dumps(key) + ' = ' + json.dumps(translations[key], ensure_ascii=False) + ';\n')
    return [resource]
