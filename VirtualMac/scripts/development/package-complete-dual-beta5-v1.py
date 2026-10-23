#!/usr/bin/env python3
"""Package the two complete runtimes in their independent owned directories.

Consumes frozen local candidates. Does not contact a device or GitHub.
The output includes a versioned App, Debian archive and exact deployment pins.
"""
import argparse
import hashlib
import importlib.util
import io
import json
import lzma
from pathlib import Path
import plistlib
import re
import shutil
import subprocess
import tarfile
import tempfile

HERE = Path(__file__).resolve().parent
REPO = HERE.parents[1]
APP = "/var/jb/Applications/VirtualMacIndependent27.app"
RUNTIME = "/private/var/mobile/Library/VirtualMacIndependent27Runtime-v1"
FULL13 = "/private/var/mobile/Library/VirtualMacFull13Runtime-v1"
METADATA = "/var/jb/usr/share/virtualmac-independent27"


def digest(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def exact(row):
    path = Path(row["path"])
    assert path.is_file() and not path.is_symlink()
    assert path.stat().st_size == row["bytes"] and digest(path) == row["sha256"]
    return path


def run(*argv):
    return subprocess.run(list(map(str, argv)), capture_output=True, check=True)


def helper():
    spec = importlib.util.spec_from_file_location("previous_deb_format", HERE / "build-virtualmac2-deb.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


GUARD = r'''#!/bin/sh
set -eu
export PATH=/var/jb/usr/bin:/var/jb/usr/sbin:/var/jb/bin:/usr/bin:/bin:/usr/sbin:/sbin
rows=$(ps -axo comm=)
if printf '%s\n' "$rows" | awk '
 /\/VirtualMacIndependent27.app\/VirtualMacIndependent27$/ ||
 /\/VirtualMacIndependent27Runtime-v1\// ||
 /\/VirtualMacFull13Runtime-v1\// {active=1}
 END {exit !active}'; then
 echo 'Shut down the independent guest normally and close VirtualMac 27 first.' >&2
 exit 1
fi
'''

POSTINST = GUARD + "\n" + (HERE / "configure-complete-dual-beta5-v1.sh").read_text()


def archive(paths, stage, epoch):
    stream = io.BytesIO()
    with tarfile.open(fileobj=stream, mode="w", format=tarfile.GNU_FORMAT) as tar:
        for path in paths:
            name = str(path.relative_to(stage))
            item = tar.gettarinfo(str(path), "./" + name)
            mobile = name.startswith(APP.lstrip("/")) or name.startswith(RUNTIME.lstrip("/")) or name.startswith(FULL13.lstrip("/"))
            item.uid = item.gid = 501 if mobile else 0
            item.uname = item.gname = "mobile" if mobile else "root"
            item.mtime = epoch
            item.pax_headers = {}
            if item.isfile():
                with path.open("rb") as handle:
                    tar.addfile(item, handle)
            else:
                tar.addfile(item)
    return lzma.compress(stream.getvalue(), preset=6)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--app-candidate", type=Path, required=True)
    parser.add_argument("--runtime-candidate", type=Path, required=True)
    parser.add_argument("--complete13-candidate", type=Path, required=True)
    parser.add_argument("--network-proof", type=Path, required=True)
    parser.add_argument("--network-upstream", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    output = args.output.resolve()
    assert not output.exists()
    app = json.loads(args.app_candidate.read_bytes())
    runtime = json.loads(args.runtime_candidate.read_bytes())
    proof = json.loads(args.network_proof.read_bytes())
    assert proof["actualDHCPACK"] and proof["actualAppleDNSResolved"] and proof["actualHTTPS200"]
    assert runtime["canonicalDeviceRoot"] == app["runtimeRoot"] == RUNTIME
    for row in app["appFiles"]:
        exact(row)
    manifest_path = exact(runtime["manifest"])
    manifest = plistlib.loads(manifest_path.read_bytes())
    output.mkdir(mode=0o700)
    stage = output / "stage"
    app_path = stage / APP.lstrip("/")
    runtime_path = stage / RUNTIME.lstrip("/")
    full13_path = stage / FULL13.lstrip("/")
    metadata = stage / METADATA.lstrip("/")
    app_path.parent.mkdir(parents=True)
    shutil.copytree(app["app"], app_path)
    run("xattr", "-cr", app_path)
    # The durable guest SSH executable is shipped as a private resource;
    # the guest installer gives its installed copy executable permissions.
    (app_path / "GuestTools/vm27-guest-vsock-ssh-signed-v1").chmod(0o600)
    runtime_path.mkdir(parents=True)
    metadata.mkdir(parents=True)
    for row in manifest["files"]:
        relative = Path(row["path"])
        assert not relative.is_absolute() and ".." not in relative.parts
        source = Path(runtime["runtimeRoot"]) / relative
        assert not source.is_symlink() and digest(source) == row["sha256"]
        target = runtime_path / relative
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(source, target)
        # The platform-launch resource checks require the tested private
        # runtime's exact permissions, including its 0600 sandbox profile.
        target.chmod(0o700 if row["kind"] == "mach-o" else 0o600)
    shutil.copyfile(manifest_path, runtime_path / manifest_path.name)
    (runtime_path / manifest_path.name).chmod(0o600)
    for path in [runtime_path, *runtime_path.rglob("*")]:
        if path.is_dir():
            path.chmod(0o700)
    full13=json.loads(args.complete13_candidate.read_bytes())
    assert full13['canonicalDeviceRoot']==FULL13 and full13['admissionLocalTestsPassed']==6
    full13_source=Path(full13['runtimeRoot'])
    whole13_manifest=full13_source/'VM13OwnedRuntimeManifestV1.json'
    assert digest(whole13_manifest)==full13['manifestSHA256']
    whole13=json.loads(whole13_manifest.read_bytes())
    assert len(whole13['files'])==106 and sum(r['kind']=='mach-o' for r in whole13['files'])==68
    expected13={r['path']:r for r in whole13['files']}
    actual13={str(p.relative_to(full13_source)) for p in full13_source.rglob('*') if p.is_file() and not p.is_symlink()}
    assert actual13==set(expected13)|{'VM13OwnedRuntimeManifestV1.json'}
    expectedlinks={'payload/'+r['path']:r['target'] for r in whole13['relativeSymlinks']}
    actuallinks={str(p.relative_to(full13_source)):p.readlink().as_posix() for p in full13_source.rglob('*') if p.is_symlink()}
    assert actuallinks==expectedlinks
    for relative,row in expected13.items():
        source=full13_source/relative
        assert source.stat().st_size==row['bytes'] and digest(source)==row['sha256']
    for relative,target in expectedlinks.items():
        path=full13_source/relative
        assert not Path(target).is_absolute() and path.resolve(strict=True).is_relative_to(full13_source.resolve())
    shutil.copytree(full13_source,full13_path,symlinks=True)
    (metadata/'symlinks.tsv').write_text(''.join(FULL13+'/'+relative+'\t'+target+'\n' for relative,target in sorted(expectedlinks.items())))
    info_path = app_path / "Info.plist"
    info = plistlib.loads(info_path.read_bytes())
    assert info["CFBundleIdentifier"] == "com.mac.virtual.independent27"
    info.update(CFBundleShortVersionString="2.0.0beta5", CFBundleVersion="1005",
                CFBundleDisplayName="VirtualMac 2 beta5", MinimumOSVersion="15.0", VirtualMacPackageRevision="1005")
    # Historical diagnostic counts no longer describe the runtime configuration.
    info.pop("VirtualMacIndependent27ActualNICCount", None)
    info.pop("VirtualMacIndependent27ActualAudioDeviceCount", None)
    info_path.write_bytes(plistlib.dumps(info, sort_keys=False))
    # Sign outside Documents: Finder/indexing can attach bundle metadata
    # concurrently there. Those host xattrs never enter the Debian archive.
    with tempfile.TemporaryDirectory(prefix="vm27-beta5-sign-", dir="/private/tmp") as work:
        clean_app = Path(work) / app_path.name
        shutil.copytree(app_path, clean_app)
        run("xattr", "-cr", clean_app)
        binary = clean_app / info["CFBundleExecutable"]
        previous_sections = helper().code_identity(binary)
        run("codesign", "--force", "--sign", "-", "--timestamp=none", "--digest-algorithm=sha256",
            "--identifier", info["CFBundleIdentifier"], "--entitlements", REPO / "vz/host/VirtualMac_native_trackpad_v1.entitlements",
            "--generate-entitlement-der", clean_app)
        run("codesign", "--verify", "--strict", clean_app)
        assert helper().code_identity(binary) == previous_sections
        assert binary.stat().st_size <= 2 * 1024 * 1024
        description = run("codesign", "-d", "--verbose=4", clean_app).stderr.decode()
        for source in clean_app.rglob("*"):
            if source.is_file():
                target = app_path / source.relative_to(clean_app)
                shutil.copyfile(source, target)
                target.chmod(source.stat().st_mode & 0o7777)
    app_hash = re.search(r"^CDHash=([0-9a-f]{40})$", description, re.M).group(1)
    licenses = metadata / "licenses"
    licenses.mkdir()
    for source, target in (("libslirp-v4.9.5/LICENSE", "libslirp-LICENSE"),
                           ("glib-2.88.3/COPYING", "GLib-COPYING"),
                           ("libslirp-v4.9.5/subprojects/proxy-libintl-0.5/COPYING", "proxy-libintl-COPYING")):
        shutil.copyfile(args.network_upstream / source, licenses / target)
    (metadata / "THIRD-PARTY.txt").write_text(
        "This App statically links libslirp 4.9.5 (BSD), GLib 2.88.3 (LGPL-2.1-or-later) "
        "and proxy-libintl 0.5 (LGPL). Copyright and license notices are in licenses/. "
        "The same Release includes corresponding sources and App relink inputs. "
        "You may modify these libraries and relink this App for your own use.\n")
    pins = []
    for root, prefix in ((app_path, APP), (runtime_path, RUNTIME), (full13_path,FULL13)):
        for path in sorted(root.rglob("*")):
            if path.is_symlink():
                assert prefix==FULL13
                continue
            if path.is_file():
                pins.append(dict(path=prefix + "/" + str(path.relative_to(root)),
                                 bytes=path.stat().st_size, sha256=digest(path),
                                 mode=path.stat().st_mode & 0o7777))
    (metadata / "files.sha256").write_text("".join(p["sha256"] + "  " + p["path"] + "\n" for p in pins))
    trust = [(app_hash, APP + "/" + info["CFBundleExecutable"])]
    trust += [(row["cdhash"], RUNTIME + "/" + row["path"]) for row in manifest["files"] if row["kind"] == "mach-o"]
    host_cd=run('codesign','-d','--verbose=4',app_path/'VZHostCompat.dylib').stderr.decode()
    trust.append((re.search(r'^CDHash=([0-9a-f]{40})$',host_cd,re.M).group(1),APP+'/VZHostCompat.dylib'))
    trust.extend((row['cdhash'],FULL13+'/'+row['path']) for row in json.loads((args.complete13_candidate.parent/'trust-images-v1.json').read_bytes()))
    trust=list({h:(h,path) for h,path in trust}.values())
    (metadata / "trustcache.txt").write_text("".join(h + " " + path + "\n" for h, path in trust))
    pin_by_path={row["path"]:row for row in pins}
    for cd,path in trust:
        actual=run("codesign","-d","--verbose=4",stage/path.lstrip("/")).stderr.decode()
        assert re.search(r"^CDHash=([0-9a-f]{40})$",actual,re.M).group(1)==cd
    (metadata/"trustcache-v2.txt").write_text("".join(cd+" "+pin_by_path[path]["sha256"]+" "+path+"\n" for cd,path in trust))
    release = dict(formatVersion=1, version="2.0.0beta5", build="1005", packageVersion="1005",
                   macOS27DeviceTestedBuilds=["20B101"], experimentalDopamineOSRange="15.0-16.3.1", nativeContextVersionRequired="0x206879700000000e", diagnosticExportIncludesOwnCrashes=True, targetDeviceFamilies=["M1 iPad", "M2 iPad", "iPhone14Pro", "iPhone14ProMax"], hostDeviceMatrixAcceptanceComplete=False,
                   package=info["CFBundleIdentifier"], backend="complete macOS 13 or complete independent macOS 27 CPU/VMM/Virtualization/PVG",
                   complete13ManifestSHA256=full13["manifestSHA256"],complete13Files=106,
                   backendChoices=["13.2.1","27"],persistentHibernate=True,hibernateBackgroundSave=True,hibernateRestoreAfterAppDeath=True,portableCacheAdmission=True,dopamineCanonicalTool=True,nativeTrustAddFallback=True,perVMProMotion=True,foregroundLockPause=True,unlockAutoResumeOptIn=True,sshLiveSettings=True,sshCustomPort=True,sshHostIPv4IPv6=True,sshScopes=["loopback","LAN","Internet"],
                   appCDHash=app_hash, files=pins, nativeNetworkTest=proof,
                   limitations=["Experimental admission covers target M1/M2 iPads and A16 iPhone 14 Pro/Pro Max on Dopamine iOS/iPadOS 15 through 16.3.1. App sources compile for iOS15 and runtime loader floors are adjusted; only M2 iPadOS16.1.1 has device acceptance. Other builds may fail a genuine CPU ABI check, lack a host symbol, or crash. Export Diagnostics locally and report the exact build and reproduction steps.","Occasional GUI stutter and icon-service crashes remain under investigation for beta5.",
                                "Persistent Hibernate has actual same-build background save, process death, relaunch and anonymous-RAM continuity acceptance on M2 for App274/Runtime174. The final Beta5 package test is tracked separately; locked devices pause without writing a locked Keychain snapshot.",
                                "Clean restore-image installation, full27 GUI Metal BC override and native host video encoding acceleration are deferred. Microphone capture has a bounded nonzero-sample test; sustained capture/playback and physical speaker output remain unaccepted.",
                                "GPU24 BC upload/view cases, basic WebGPU/f16/indirect compute and static Metal stitching have bounded execution tests. Mesh/ray-tracing/dynamic libraries and unrestricted Safari feature parity are not implemented.",
                                "Guest internet networking uses IPv4 NAT; host SSH forwarding supports IPv4 and IPv6. Bridged networking is deferred.",
                                "Audio output path tested; physical speaker audibility not verified."])
    (output / "release-manifest.json").write_text(json.dumps(release, indent=2) + "\n")
    control = output / "control"
    control.mkdir()
    size = (sum(p.stat().st_size for p in stage.rglob("*") if p.is_file()) + 1023) // 1024
    (control / "control").write_text(
        "Package: com.mac.virtual.independent27\nName: VirtualMac 2.0.0beta5\nVersion: 1005\n"
        "Architecture: iphoneos-arm64\nMaintainer: liukaixiang817\nSection: Utilities\nPriority: optional\n"
        f"Installed-Size: {size}\nDepends: firmware (>= 15.0), firmware (<< 16.3.2)\n"
        "Description: Complete macOS 13 and macOS 27 backends with independent CPU, VMM and graphics.\n"
        " Tested on jailbroken M2 iPadOS 16.1.1 with a macOS Tahoe guest.\n"
        " Native IPv4 NAT, sound playback, gestures, ProMotion and lock pause are included.\n"
        " Shut down the guest normally and close the App before package changes.\n")
    for name, body in (("preinst", GUARD), ("prerm", GUARD), ("postinst", POSTINST)):
        (control / name).write_text(body)
        (control / name).chmod(0o755)
        run("/bin/sh", "-n", control / name)
    data_paths = []
    for root in (app_path, runtime_path, full13_path, metadata):
        data_paths.extend([root, *sorted(root.rglob("*"))])
    epoch = 1792533600
    deb = output / "VirtualMac_2.0.0beta5_1005.deb"
    helper().write_deb(deb, archive(sorted(control.iterdir()), control, epoch),
                       archive(data_paths, stage, epoch), epoch)
    (output / "SHA256SUMS").write_text(digest(deb) + "  " + deb.name + "\n")
    print(json.dumps(dict(deb=str(deb), bytes=deb.stat().st_size, sha256=digest(deb),
                          appCDHash=app_hash, runtimeFiles=len(manifest["files"]), appCodeUnchanged=True)))


if __name__ == "__main__":
    main()
