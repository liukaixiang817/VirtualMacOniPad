#!/usr/bin/env python3
"""Publish the Beta 7 App over the tested radio and media Debian payload."""

import argparse
import importlib.util
import json
from pathlib import Path
import plistlib
import shutil
import tempfile

helper = Path(__file__).with_name("package-independent27-radio100.py")
spec = importlib.util.spec_from_file_location("radio_package", helper)
prior = importlib.util.module_from_spec(spec)
spec.loader.exec_module(prior)

VERSION = "1007"
DISPLAY_VERSION = "2.0.0beta7"
INPUT_VERSION = "1006-2+radio100.media108"
INPUT_SHA = "37a44c51c9d691dab281c29086c61ae68fb86384927ab9fe15c4608cf1dc65a9"
APP_FILES = ("VirtualMacIndependent27", "Info.plist", "_CodeSignature/CodeResources")
INSTALLER_VERSION = "2:1.2.4+617.1f873e57cc"
INSTALLER_SHA = "d8765adda6257fa7712aeae126c7992c952f151519375b0224520ecfea50a078"
DEVELOPMENT_ACTIONS = (
    "radio-guest-unlock", "radio-guest-click", "radio-review-install",
    "radio-review-keys", "radio-guest-screen", "radio-crash-disk-readonly",
    "radio-acceptance-mouse-gatt-probe", "diagnostic-ssh-enable", "guest-gui-diagnostic",
    "frame-timing", "display-native-iosurface",
)


def verify_app(app):
    info = plistlib.loads((app / "Info.plist").read_bytes())
    assert info["CFBundleIdentifier"] == prior.PACKAGE and info["CFBundleExecutable"] == APP_FILES[0]
    assert info["CFBundleVersion"] == VERSION and info["CFBundleShortVersionString"] == DISPLAY_VERSION
    assert "VM27SharedRadioDevelopmentRevision" not in info
    executable = app / APP_FILES[0]
    data = executable.read_bytes()
    assert all(action.encode() + b"\0" not in data for action in DEVELOPMENT_ACTIONS)
    for capability in ("AutomaticRadioInstallationV1", "BuiltInCameraDevice",
                       "VM27AttachSharedRadiosToVMV1", "Microphone Input", "virtualmac-camera-daemon"):
        assert capability.encode() in data, capability
    prior.run("codesign", "--verify", "--strict", "--deep", app)
    return prior.sha(executable), prior.cdhash(executable)


def replace_package_app(stage, source):
    app = stage / prior.APP
    files = {p.relative_to(app).as_posix() for p in app.rglob("*") if p.is_file()}
    assert files == {p.relative_to(source).as_posix() for p in source.rglob("*") if p.is_file()}
    for relative in files:
        current, updated = app / relative, source / relative
        assert not current.is_symlink() and not updated.is_symlink()
        if relative in APP_FILES:
            shutil.copyfile(updated, current)
        else:
            assert prior.sha(current) == prior.sha(updated), relative
    signature = verify_app(app)

    metadata = stage / prior.METADATA
    paths = {"/" + prior.APP + "/" + p for p in APP_FILES}
    files_sha = metadata / "files.sha256"
    pins = {}
    for line in files_sha.read_text().splitlines():
        digest, file = line.split(None, 1)
        actual = prior.sha(stage / file[1:])
        assert file in paths or actual == digest, file
        pins[file] = actual
    assert paths.issubset(pins)
    files_sha.write_text("".join(f"{digest}  {file}\n" for file, digest in sorted(pins.items())))
    trust_file = metadata / "trustcache-v2.txt"
    trust = []
    for line in trust_file.read_text().splitlines():
        cdhash, digest, file = line.split(None, 2)
        if file == "/" + prior.APP + "/" + APP_FILES[0]:
            digest, cdhash = signature
        assert pins[file] == digest
        trust.append((cdhash, digest, file))
    assert sum(file == "/" + prior.APP + "/" + APP_FILES[0] for _, _, file in trust) == 1
    trust_file.write_text("".join(" ".join(entry) + "\n" for entry in trust))
    (metadata / "trustcache.txt").write_text("".join(f"{cd} {file}\n" for cd, _, file in trust))
    return pins, signature


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--tested-deb", required=True, type=Path)
    parser.add_argument("--app", required=True, type=Path)
    parser.add_argument("--installer-deb", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args()
    base, app, installer = (p.resolve(strict=True) for p in (args.tested_deb, args.app, args.installer_deb))
    assert prior.sha(base) == INPUT_SHA and prior.sha(installer) == INSTALLER_SHA
    assert prior.run("dpkg-deb", "--field", installer, "Version").decode().strip() == INSTALLER_VERSION
    prior.run("dpkg", "--compare-versions", INPUT_VERSION, "lt", VERSION)
    output = args.output.resolve()
    output.mkdir(parents=True, exist_ok=True)
    destination = output / f"VirtualMac_{DISPLAY_VERSION}_{VERSION}.deb"
    assert not destination.exists()

    with tempfile.TemporaryDirectory(prefix="virtualmac-beta7-package-") as temporary:
        scratch = Path(temporary)
        stage = scratch / "stage"
        prior.run("dpkg-deb", "--raw-extract", base, stage)
        old_catalog = prior.radio_catalog(stage / prior.APP)
        pins, signature = replace_package_app(stage, app)
        controls = stage / "DEBIAN"
        control = controls / "control"
        record = prior.replace_once(control.read_text(), f"Version: {INPUT_VERSION}\n", f"Version: {VERSION}\n")
        record = prior.replace_once(record, "Name: VirtualMac 2.0.0beta6-r2\n", f"Name: VirtualMac {DISPLAY_VERSION}\n")
        record = prior.replace_once(record, "Description: ", f"Recommends: com.mac.virtual (= {INSTALLER_VERSION})\nDescription: ")
        record = prior.replace_once(record,
            " App 108 integrates Wi-Fi, Bluetooth, camera and audio for new macOS 15, 26 and 27 guests.\n",
            " Native Wi-Fi, Bluetooth discovery, camera and audio for new macOS 15, 26 and 27 guests.\n"
            " Creating guests from official restore images uses the Virtual Mac 1.2.4 installation helper.\n")
        paths = sorted(p for p in stage.rglob("*") if controls not in (p, *p.parents))
        size = sum(p.stat().st_size for p in paths if p.is_file() and not p.is_symlink())
        current_size = next(line for line in record.splitlines() if line.startswith("Installed-Size: "))
        record = prior.replace_once(record, current_size + "\n", f"Installed-Size: {(size + 1023) // 1024}\n")
        control.write_text(record)
        postinst = controls / "postinst"
        postinst.write_text(postinst.read_text().replace("1006-2+radio100", VERSION).replace("beta6-r2", "beta7"))
        result = scratch / destination.name
        writer = prior.load_helper("build-virtualmac2-deb.py").write_deb
        writer(result, prior.archive(controls, sorted(controls.iterdir())), prior.archive(stage, paths), prior.EPOCH)
        unpacked = scratch / "verified"
        prior.run("dpkg-deb", "--raw-extract", result, unpacked)
        assert prior.run("dpkg-deb", "--field", result, "Version").decode().strip() == VERSION
        for name, digest in pins.items():
            path = unpacked / name[1:]
            assert prior.sha(path) == digest
            assert path.stat().st_mode & 0o7777 == (stage / name[1:]).stat().st_mode & 0o7777
        assert prior.radio_catalog(unpacked / prior.APP) == old_catalog
        assert verify_app(unpacked / prior.APP) == signature
        partial = destination.with_suffix(".deb.partial")
        assert not partial.exists()
        shutil.copyfile(result, partial)
        partial.replace(destination)

    sums = prior.sha(destination)
    (output / "SHA256SUMS").write_text(f"{sums}  {destination.name}\n")
    manifest = {
        "package": prior.PACKAGE, "version": VERSION, "sha256": sums,
        "appExecutableSHA256": signature[0], "appCDHash": signature[1],
        "testedInputDebSHA256": INPUT_SHA, "automaticGuestPackages": old_catalog,
        "officialNewGuestInstaller": {"package": "com.mac.virtual", "version": INSTALLER_VERSION,
                                      "upstreamRelease": "1.2.4", "debSHA256": INSTALLER_SHA},
        "verifiedUnchangedDataOutsideApp": True,
        "verifiedUnchangedSignedAppResources": True,
        "developmentURLActionsRemoved": True,
        "testedHost": {"model": "iPad14,6", "iPadOS": "16.1.1", "build": "20B101"},
    }
    (output / "release-manifest.json").write_text(json.dumps(manifest, indent=2) + "\n")
    print(destination)
    print(sums)


if __name__ == "__main__":
    main()
