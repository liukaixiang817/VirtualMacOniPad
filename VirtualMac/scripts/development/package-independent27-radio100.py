#!/usr/bin/env python3
"""Package the verified App 100 radio update on the released dual-backend runtime."""

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
ROOT = HERE.parents[2]
DIAGNOSTICS = ROOT / "DeviceDiagnostics/2026-11-15-macos26-firstboot-v1"
SUITE = DIAGNOSTICS / "repair-setup-resume100-20261118"
RELEASE = ROOT / "artifacts/2.0.0beta6-r2"
BASE_SHA = "d7b54411ee1281160bcbfa53d7682c507d3b5cf0cc1d744a5805163ab85027ad"
PACKAGE = "com.mac.virtual.independent27"
VERSION = "1006-2+radio100"
APP = "var/jb/Applications/VirtualMacIndependent27.app"
RUNTIME27 = "private/var/mobile/Library/VirtualMacIndependent27Runtime-v1"
RUNTIME13 = "private/var/mobile/Library/VirtualMacFull13Runtime-v1"
METADATA = "var/jb/usr/share/virtualmac-independent27"
TWEAK = "var/jb/usr/lib/TweakInject/VM27GestureGuard"
EPOCH = 1794963600
RADIO_JOBS = (
    ("owned-wifi", "independent", "root-owned-wifi-v60-recent-native-bss/virtualmac-owned-wifi-v1"),
    ("exclusive-bluetooth", "exclusive", "bluetooth-host-ready-candidate-v1/exclusive-broker-v1"),
)

HOST_GUARD = """
if [ "$(sysctl -n hw.machine)" != iPad14,6 ] || [ "$(sysctl -n kern.osversion)" != 20B101 ]; then
    echo 'The included radio services require iPad14,6 with iPadOS build 20B101.' >&2
    exit 1
fi
"""
RADIO_GUARD = """
vm27_launchctl=/var/jb/bin/launchctl
test -x "$vm27_launchctl"
vm27_radio_program_matches() {
    while read -r key equals value; do
        if [ "$key" = program ] && [ "$equals" = = ] && [ "$value" = "$2" ]; then
            return 0
        fi
    done <<VM27_RADIO_JOB
$1
VM27_RADIO_JOB
    echo "Unexpected program for the VirtualMac radio service $2." >&2
    return 1
}
"""
PREPARE = """
vm27_radio_reload=
vm27_radio_prepare() {
    if record=$("$vm27_launchctl" print "system/$1" 2>/dev/null); then
        vm27_radio_program_matches "$record" "$2" || return 1
        test -f "$2" && test ! -L "$2" || return 1
        current=$(sha256sum "$2") || return 1
        if [ "${current%% *}" != "$3" ]; then
            vm27_radio_reload="$vm27_radio_reload $1"
        fi
    fi
}
"""
REGISTER = """
phase=register-radio-services
radio_log_dir=/var/root/VM27ExclusiveBluetooth-v1
test ! -L "$radio_log_dir"
if [ ! -e "$radio_log_dir" ]; then
    mkdir -m 0700 "$radio_log_dir"
fi
test -d "$radio_log_dir"
vm27_radio_register() {
    test -x "$2" && test ! -L "$2" && test -f "$3" && test ! -L "$3" || return 1
    if ! record=$("$vm27_launchctl" print "system/$1" 2>/dev/null); then
        "$vm27_launchctl" bootstrap system "$3" || return 1
        record=$("$vm27_launchctl" print "system/$1") || return 1
    fi
    vm27_radio_program_matches "$record" "$2"
}
"""
STOP = """
vm27_radio_stop() {
    if record=$("$vm27_launchctl" print "system/$1" 2>/dev/null); then
        vm27_radio_program_matches "$record" "$2" || return 1
        "$vm27_launchctl" bootout "system/$1"
    fi
}
"""


def run(*arguments):
    return subprocess.check_output(arguments)


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def read_json(path):
    return json.loads(path.read_text())


def load_helper(name):
    spec = importlib.util.spec_from_file_location(Path(name).stem, HERE / name)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def archive(root, paths):
    buffer = io.BytesIO()
    with tarfile.open(fileobj=buffer, mode="w", format=tarfile.GNU_FORMAT) as tar:
        for path in paths:
            relative = str(path.relative_to(root))
            entry = tar.gettarinfo(str(path), "./" + relative)
            mobile = relative.startswith((APP, RUNTIME27, RUNTIME13))
            entry.uid = entry.gid = 501 if mobile else 0
            entry.uname = entry.gname = "mobile" if mobile else "root"
            entry.mtime = EPOCH
            if entry.isfile():
                with path.open("rb") as stream:
                    tar.addfile(entry, stream)
            else:
                tar.addfile(entry)
    return lzma.compress(buffer.getvalue(), preset=6)


def cdhash(path):
    output = subprocess.check_output(["ldid", "-h", path], stderr=subprocess.STDOUT, text=True)
    return re.search(r"^CDHash=([a-f0-9]{40})$", output, re.M).group(1)


def replace_once(text, old, new):
    if text.count(old) != 1:
        raise ValueError(f"Expected one release-script insertion point: {old!r}")
    return text.replace(old, new)


def install_scripts(control, jobs):
    def calls(function, extra):
        return "\n".join(f"{function} {j['label']} /{j['binary']} {extra(j)}".rstrip() for j in jobs)

    preinst = control / "preinst"
    prepare = calls("vm27_radio_prepare", lambda j: j["sha256"])
    preinst.write_text(preinst.read_text() + HOST_GUARD + RADIO_GUARD + PREPARE +
                       prepare + '\nfor label in $vm27_radio_reload; do\n'
                       '    "$vm27_launchctl" bootout "system/$label"\ndone\n')

    postinst = control / "postinst"
    body = postinst.read_text().replace("revision=1006-2", "revision=" + VERSION)
    allowed = "|".join("/" + j["binary"] for j in jobs)
    body = replace_once(body, "/var/jb/usr/lib/TweakInject/VM27GestureGuard.dylib) ;;",
                        "/var/jb/usr/lib/TweakInject/VM27GestureGuard.dylib|" + allowed + ") ;;")
    register = calls("vm27_radio_register", lambda j: "/" + j["descriptor"])
    postinst.write_text(replace_once(body, "\nphase=register-app\n",
        "\n" + HOST_GUARD + RADIO_GUARD + REGISTER + register + "\nphase=register-app\n"))

    prerm = control / "prerm"
    stop = calls("vm27_radio_stop", lambda j: "")
    prerm.write_text(prerm.read_text() + '\ncase "${1:-}" in\nremove|deconfigure)\n' +
                     RADIO_GUARD + STOP + stop + '\n;;\nesac\n')
    for script in (preinst, postinst, prerm):
        script.chmod(0o755)
        run("/bin/sh", "-n", script)


def radio_catalog(app):
    resources = app / "SharedRadio"
    automatic = plistlib.loads((resources / "Catalog.plist").read_bytes())["AutomaticPackages"]
    assert set(automatic) == {"24G90", "25G83", "26A5416b"}
    for build, row in automatic.items():
        bundle = resources / ("Automatic" + build)
        installer = bundle / row["Installer"]
        tarball = bundle / row["Archive"]
        assert row["ResourceDirectory"] == bundle.name and row["CombinedInstallation"]
        assert sha(installer) == row["InstallerSHA256"]
        assert sha(tarball) == row["ArchiveSHA256"]
        with tarfile.open(tarball) as inner:
            digest = hashlib.sha256(inner.extractfile("Package/Package.plist").read()).hexdigest()
            assert digest == row["ManifestSHA256"]
            assert "Package/VM27SharedRadioNativeV1.kext/Contents/MacOS/VM27SharedRadioNativeV1" in inner.getnames()
            assert "Package/Bluetooth/exclusive-guest-relay-v1" in inner.getnames()
    return automatic


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, default=ROOT / "artifacts/2.0.0beta6-r2-radio100")
    args = parser.parse_args()
    base_deb = RELEASE / "VirtualMac_2.0.0beta6-r2_1006-2.deb"
    app_tar = DIAGNOSTICS / "app-new26-v100/app-v100.tar"
    baseline = read_json(RELEASE / "release-manifest.json")
    audit = read_json(SUITE / "final-preservation-audit.json")
    comparison = read_json(SUITE / "deb-packaging-device-baseline.json")
    signed_app = read_json(SUITE / "app100-archive-reverified.json")
    deploy = read_json(DIAGNOSTICS / "app-new26-v100/deployment.json")
    frozen = audit["frozenBinaryAndResourceSHA256"]
    assert audit["preservationAuditPassed"] and audit["allThreeFreshTestsFinished"]
    assert comparison["deviceHeaders"][:2] == ["iPad14,6", "20B101"]
    assert comparison["matched"] == comparison["knownBaselineRuntimeRegularFiles"]
    assert sha(base_deb) == BASE_SHA and sha(app_tar) == signed_app["archiveSHA256"]
    check_code = load_helper("verify-macho-code-directory.py").check

    args.output.mkdir(exist_ok=True, parents=True)
    destination = args.output / f"VirtualMac_2.0.0beta6-r2_{VERSION}.deb"
    assert not destination.exists()
    with tempfile.TemporaryDirectory(prefix="virtualmac-radio-deb-") as temporary:
        work = Path(temporary)
        stage = work / "stage"
        run("dpkg-deb", "--raw-extract", base_deb, stage)
        app = stage / APP
        original_info = plistlib.loads((app / "Info.plist").read_bytes())
        shutil.rmtree(app)
        with tarfile.open(app_tar) as source:
            assert all(entry.name.split("/")[0] == app.name for entry in source.getmembers())
            source.extractall(app.parent, filter="data")
        info = plistlib.loads((app / "Info.plist").read_bytes())
        for key in ("CFBundleIdentifier", "CFBundleExecutable", "CFBundleVersion", "CFBundleShortVersionString"):
            assert info[key] == original_info[key]
        app_binary = app / info["CFBundleExecutable"]
        app_digest = sha(app_binary)
        assert app_digest == signed_app["archiveBinarySHA256"] == frozen["/" + APP + "/" + app_binary.name]
        run("codesign", "--verify", "--deep", "--strict", app)
        automatic = radio_catalog(app)

        jobs = []
        for name, directory, input_path in RADIO_JOBS:
            label = f"com.virtualmac.{name}-v1"
            binary = DIAGNOSTICS / input_path
            executable = f"var/jb/usr/local/libexec/virtualmac-{name}-v1"
            descriptor = f"var/jb/Library/LaunchDaemons/{label}.plist"
            source = ROOT / "VirtualMac/vz/shared-radio" / directory / f"{label}.plist"
            digest = sha(binary)
            assert digest == frozen["/" + executable]
            assert f'{sha(source)}  /{descriptor}' in comparison["radioJobDescriptorSHA256"][label]
            parsed = plistlib.loads(source.read_bytes())
            assert parsed["Label"] == label and parsed["ProgramArguments"] == ["/" + executable]
            assert parsed["UserName"] == "root" and parsed["RunAtLoad"]
            for item, path, mode in ((binary, executable, 0o755), (source, descriptor, 0o644)):
                target = stage / path
                target.parent.mkdir(exist_ok=True, parents=True)
                shutil.copyfile(item, target)
                target.chmod(mode)
            code_hash = cdhash(stage / executable)
            assert code_hash in {row["cdhash"] for row in check_code((stage / executable).read_bytes())}
            jobs.append({"label": label, "binary": executable, "descriptor": descriptor,
                         "sha256": digest, "cdhash": code_hash})

        roots = [stage / name for name in (APP, RUNTIME27, RUNTIME13, METADATA)]
        extra = [stage / (TWEAK + suffix) for suffix in (".dylib", ".plist")]
        extra.extend(stage / item for j in jobs for item in (j["binary"], j["descriptor"]))
        files = [path for root in roots[:3] for path in root.rglob("*") if path.is_file() and not path.is_symlink()]
        pins = {"/" + str(path.relative_to(stage)): sha(path) for path in sorted(files + extra)}
        assert all(pins[row["path"]] == row["sha256"] for row in baseline["files"] if not row["path"].startswith("/" + APP + "/"))
        assert all(pins[name] == digest for name, digest in frozen.items())
        metadata = stage / METADATA
        (metadata / "files.sha256").write_text("".join(f"{digest}  {name}\n" for name, digest in pins.items()))
        trust = []
        for line in (metadata / "trustcache-v2.txt").read_text().splitlines():
            original_cdhash, original_sha, name = line.split()
            digest = pins[name]
            trust.append((original_cdhash if digest == original_sha else cdhash(stage / name[1:]), digest, name))
        trust.extend((j["cdhash"], j["sha256"], "/" + j["binary"]) for j in jobs)
        (metadata / "trustcache-v2.txt").write_text("".join(" ".join(row) + "\n" for row in trust))
        (metadata / "trustcache.txt").write_text("".join(f"{cd} {name}\n" for cd, _, name in trust))

        control = stage / "DEBIAN"
        install_scripts(control, jobs)
        control_file = control / "control"
        control_text = replace_once(control_file.read_text(), "Version: 1006-2\n", "Version: " + VERSION + "\n")
        payload = [path for root in roots for path in [root, *sorted(root.rglob("*"))]] + extra
        size = sum(path.stat().st_size for path in payload if path.is_file() and not path.is_symlink())
        control_text = re.sub(r"(?m)^Installed-Size: \d+$", f"Installed-Size: {(size + 1023) // 1024}", control_text)
        control_file.write_text(control_text + " App 100 automatic Wi-Fi and Bluetooth for macOS 15, 26 and 27.\n"
                                " Radio support is for jailbroken iPad14,6 / iPadOS 16.1.1 (20B101).\n")
        candidate = work / destination.name
        write_deb = load_helper("build-virtualmac2-deb.py").write_deb
        write_deb(candidate, archive(control, sorted(control.iterdir())), archive(stage, payload), EPOCH)

        checked = work / "verified"
        run("dpkg-deb", "--raw-extract", candidate, checked)
        assert run("dpkg-deb", "--field", candidate, "Package", "Version", "Architecture").decode().splitlines() == [
            f"Package: {PACKAGE}", f"Version: {VERSION}", "Architecture: iphoneos-arm64"]
        for name, digest in pins.items():
            path = checked / name[1:]
            assert not path.is_symlink() and sha(path) == digest
            assert path.stat().st_mode & 0o777 == (stage / name[1:]).stat().st_mode & 0o777
        run("codesign", "--verify", "--deep", "--strict", checked / APP)
        assert radio_catalog(checked / APP) == automatic
        assert cdhash(checked / APP / app_binary.name) == deploy["cdhash"]
        for job in jobs:
            path = checked / job["binary"]
            assert cdhash(path) == job["cdhash"]
            assert job["cdhash"] in {row["cdhash"] for row in check_code(path.read_bytes())}
        partial = destination.with_suffix(".deb.partial")
        assert not partial.exists()
        shutil.copyfile(candidate, partial)
        partial.replace(destination)

    manifest = {"package": PACKAGE, "version": VERSION, "sha256": sha(destination),
                "baseDebSHA256": BASE_SHA, "appArchiveSHA256": sha(app_tar), "appExecutableSHA256": app_digest,
                "testedDevice": {"model": "iPad14,6", "iPadOS": "16.1.1", "build": "20B101"},
                "automaticGuestPackages": automatic, "hostRadioServices": jobs,
                "verifiedRegularFileCount": len(pins), "payloadMatchesTestedDevice": True,
                "extractedDebVerified": True, "debInstalledOnDeviceInThisRun": False}
    (args.output / "release-manifest.json").write_text(json.dumps(manifest, indent=2) + "\n")
    (args.output / "SHA256SUMS").write_text(f'{manifest["sha256"]}  {destination.name}\n')
    print(destination)
    print(manifest["sha256"])


if __name__ == "__main__":
    main()
