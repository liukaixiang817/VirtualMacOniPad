#!/usr/bin/env python3
"""Build a rootless package from the exact, accepted media App and radio release."""
import argparse
import importlib.util
import json
from pathlib import Path
import plistlib
import re
import shutil
import tarfile
import tempfile

prior_path = Path(__file__).with_name("package-independent27-radio100.py")
spec = importlib.util.spec_from_file_location("radio_package", prior_path)
prior = importlib.util.module_from_spec(spec)
spec.loader.exec_module(prior)

ROOT = prior.ROOT
DIAGNOSTICS = prior.DIAGNOSTICS
VERSION = prior.VERSION + ".media108"
APP_SHA = "06821aac23738f66ec1636ad3cde2a46f737e8504be102aba464891f0819375d"
BASE_SHA = "bc071e1cfd7b7f536e1133b19fb5df7a1561532470c49fb582475d3ff8c280d9"
BUILDS = {15: "24G90", 26: "25G83", 27: "26A5416b"}
VERIFICATION_ROUND = {15: 1, 26: 1, 27: 2}


def accepted_guests():
    accepted = {}
    identities = set()
    for major, build in BUILDS.items():
        round_number = VERIFICATION_ROUND[major]
        folder = DIAGNOSTICS / f"fresh-repair{major}-app108-media-r{round_number}-20261118"
        proof = folder / "full-fresh-media108-acceptance.json"
        evidence = prior.read_json(proof)
        assert evidence["requiredChecksPassed"] and evidence["officialBlankInstall"]
        assert evidence["guestBuild"] == build and evidence["appSHA256"] == APP_SHA
        identity = evidence["machineIdentifierSHA256"]
        assert re.fullmatch(r"[a-f0-9]{64}", identity) and identity not in identities
        identities.add(identity)
        assert evidence["sameRadioAuthorizationAutomaticallyProvisionedCamera"]
        assert evidence["cameraProfiles"] == [480, 720, 1080]
        assert evidence["guestSpeakerAcousticallyVerified"] and evidence["guestMicrophoneAcousticallyVerified"]
        assert evidence["twoPhysicalWiFiAssociationsVerified"] and evidence["bluetoothDiscoveryNoPairing"]
        assert evidence["firstInstallAndColdRadioPassed"]
        if round_number == 2:
            assert evidence["setupReachedHandoffWithoutRecoveryRestart"]
        for name, digest in evidence["evidenceSHA256"].items():
            file = (folder / name).resolve(strict=True)
            assert file.is_relative_to(folder) and prior.sha(file) == digest
        accepted[build] = prior.sha(proof)
    return accepted


def check_camera(app):
    media = app / "Camera"
    config = plistlib.loads((media / "Manifest.plist").read_bytes())
    daemon = media / "virtualmac-camera-daemon"
    job = media / "com.virtualmac.camera-v1.plist"
    assert prior.sha(daemon) == config["ProgramSHA256"] and prior.sha(job) == config["JobSHA256"]
    assert plistlib.loads(job.read_bytes())["Label"] == "com.virtualmac.camera-v1"
    prior.run("codesign", "--verify", "--strict", daemon)
    return config


def include_camera_daemon_source(metadata, launch_job):
    """Include the corresponding source for the separate UVC guest daemon."""
    vz = ROOT / "VirtualMac/vz"
    camera = vz / "camera"
    guest = camera / "guest"
    destination = metadata / "camera-source"
    destination.mkdir()
    sources = [
        guest / name for name in ("COPYING", "VM27GuestCamera.m", "VM27CameraUSBHost.m",
                                  "VM27CameraUSBHost.h", "usb_camera.c", "usb_camera.h")
    ] + [
        camera / "VM27CameraWire.c", camera / "VM27CameraWire.h",
        vz / "shared/VM27CameraFrame.h", vz / "shared/VM27CameraFrame.m",
        vz / "shared-radio/guest/VM27RadioFirstBootPolicyV1.h",
        launch_job,
    ]
    for source in sources:
        shutil.copyfile(source, destination / source.name)
        (destination / source.name).chmod(0o644)
    shutil.copyfile(ROOT / "LICENSE", destination / "VirtualMac-LICENSE")
    build = destination / "build.sh"
    build.write_text("""#!/bin/sh
set -eu
cd "$(dirname "$0")"
xcrun --sdk macosx clang -arch arm64 -mmacosx-version-min=15.0 \\
    -fobjc-arc -O2 -Wall -Wextra -Werror -I . \\
    VM27GuestCamera.m VM27CameraUSBHost.m usb_camera.c VM27CameraFrame.m VM27CameraWire.c \\
    -framework Foundation -framework IOUSBHost -framework CoreImage -framework ImageIO \\
    -framework CoreMedia -framework CoreVideo -framework CoreGraphics -o virtualmac-camera-daemon
codesign --force --sign - --timestamp=none virtualmac-camera-daemon
codesign --verify --strict virtualmac-camera-daemon
""")
    build.chmod(0o755)
    return destination


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, default=ROOT / "artifacts/2.0.0beta6-r2-media108")
    args = parser.parse_args()
    proof = accepted_guests()
    candidate_dir = DIAGNOSTICS / "app-new26-v108-camera-audio"
    app_archive = candidate_dir / "app-v108.tar"
    app_record = prior.read_json(candidate_dir / "audio-candidate-verification.json")
    assert app_record["binarySHA256"] == APP_SHA and prior.sha(app_archive) == app_record["archiveSHA256"]
    base = ROOT / f"artifacts/2.0.0beta6-r2-radio100/VirtualMac_2.0.0beta6-r2_{prior.VERSION}.deb"
    assert prior.sha(base) == BASE_SHA
    prior.run("dpkg", "--compare-versions", prior.VERSION, "lt", VERSION)
    output = args.output.resolve()
    output.mkdir(parents=True, exist_ok=True)
    destination = output / f"VirtualMac_2.0.0beta6-r2_{VERSION}.deb"
    assert not destination.exists()

    with tempfile.TemporaryDirectory(prefix="virtualmac-media-deb-") as temp:
        scratch = Path(temp)
        stage = scratch / "stage"
        prior.run("dpkg-deb", "--raw-extract", base, stage)
        control = stage / "DEBIAN"
        metadata = stage / prior.METADATA
        app = stage / prior.APP
        original = plistlib.loads((app / "Info.plist").read_bytes())
        shutil.rmtree(app)
        with tarfile.open(app_archive) as source:
            assert all(entry.name.split("/")[0] == app.name for entry in source.getmembers())
            source.extractall(app.parent, filter="data")

        settings = plistlib.loads((app / "Info.plist").read_bytes())
        for key in ("CFBundleIdentifier", "CFBundleExecutable", "CFBundleVersion", "CFBundleShortVersionString"):
            assert settings[key] == original[key]
        app_bin = app / settings["CFBundleExecutable"]
        assert prior.sha(app_bin) == APP_SHA
        prior.run("codesign", "--verify", "--deep", "--strict", app)
        automatic = prior.radio_catalog(app)
        camera = check_camera(app)
        camera_source = include_camera_daemon_source(metadata, app / "Camera/com.virtualmac.camera-v1.plist")
        app_prefix = "/" + prior.APP + "/"
        files_list = metadata / "files.sha256"
        pins = {}
        for row in files_list.read_text().splitlines():
            digest, name = row.split(None, 1)
            if not name.startswith(app_prefix):
                assert prior.sha(stage / name[1:]) == digest
                pins[name] = digest
        for file in app.rglob("*"):
            if file.is_file() and not file.is_symlink():
                pins["/" + str(file.relative_to(stage))] = prior.sha(file)
        for file in camera_source.iterdir():
            pins["/" + str(file.relative_to(stage))] = prior.sha(file)
        files_list.write_text("".join(f"{digest}  {name}\n" for name, digest in sorted(pins.items())))

        trust_list = metadata / "trustcache-v2.txt"
        trust = []
        for row in trust_list.read_text().splitlines():
            cd, original_digest, name = row.split(None, 2)
            digest = pins[name]
            if digest != original_digest:
                assert name == app_prefix + app_bin.name
                cd = prior.cdhash(stage / name[1:])
                assert cd == app_record["cdhash"]
            trust.append((cd, digest, name))
        trust_list.write_text("".join(" ".join(entry) + "\n" for entry in trust))
        (metadata / "trustcache.txt").write_text("".join(f"{cd} {name}\n" for cd, _, name in trust))

        control_path = control / "control"
        entry = prior.replace_once(control_path.read_text(), f"Version: {prior.VERSION}\n", f"Version: {VERSION}\n")
        payload = sorted(file for file in stage.rglob("*") if control not in (file, *file.parents))
        total = sum(file.stat().st_size for file in payload if file.is_file() and not file.is_symlink())
        entry = re.sub(r"(?m)^Installed-Size: \d+$", f"Installed-Size: {(total+1023)//1024}", entry)
        entry = prior.replace_once(
            entry,
            " App 100 automatic Wi-Fi and Bluetooth for macOS 15, 26 and 27.\n",
            " App 108 integrates Wi-Fi, Bluetooth, camera and audio for new macOS 15, 26 and 27 guests.\n",
        )
        control_path.write_text(entry)

        candidate = scratch / destination.name
        writer = prior.load_helper("build-virtualmac2-deb.py").write_deb
        writer(candidate, prior.archive(control, sorted(control.iterdir())), prior.archive(stage, payload), prior.EPOCH)
        checked = scratch / "verified"
        prior.run("dpkg-deb", "--raw-extract", candidate, checked)
        fields = prior.run("dpkg-deb", "--field", candidate, "Package", "Version", "Architecture").decode().splitlines()
        assert fields == [f"Package: {prior.PACKAGE}", f"Version: {VERSION}", "Architecture: iphoneos-arm64"]
        for name, digest in pins.items():
            file = checked / name[1:]
            assert prior.sha(file) == digest and file.stat().st_mode & 0o777 == (stage / name[1:]).stat().st_mode & 0o777
        prior.run("codesign", "--verify", "--deep", "--strict", checked / prior.APP)
        assert check_camera(checked / prior.APP) == camera
        assert prior.radio_catalog(checked / prior.APP) == automatic

        partial = destination.with_suffix(".deb.partial")
        assert not partial.exists()
        shutil.copyfile(candidate, partial)
        partial.replace(destination)

    digest = prior.sha(destination)
    report = {"package": prior.PACKAGE, "version": VERSION, "sha256": digest,
              "appExecutableSHA256": APP_SHA, "baseDebSHA256": BASE_SHA,
              "guestAcceptanceSHA256": proof, "automaticGuestPackages": automatic,
              "guestCameraResources": camera, "packagedPayloadVerified": True,
              "testedDevice": {"model": "iPad14,6", "iPadOS": "16.1.1", "build": "20B101"}}
    (output / "release-manifest.json").write_text(json.dumps(report, indent=2) + "\n")
    (output / "SHA256SUMS").write_text(f"{digest}  {destination.name}\n")
    print(destination)
    print(digest)


if __name__ == "__main__":
    main()
