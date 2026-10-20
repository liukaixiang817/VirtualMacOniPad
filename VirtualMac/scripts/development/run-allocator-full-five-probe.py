#!/usr/bin/env python3
"""Verify locally or explicitly stage/run only two pinned private allocator files."""
import argparse
import hashlib
import importlib.util
import io
import json
from pathlib import Path
import plistlib
import re
import shlex
import subprocess
import sys
import tarfile

sys.dont_write_bytecode = True
ROOT = Path(__file__).resolve().parents[3]
DEVICE = "/var/root/VirtualMac2/testing/allocator-full-five-v1"
PATH_VALUE = "/var/jb/usr/bin:/var/jb/bin:/usr/bin:/bin:/usr/sbin:/sbin"
RIGHTS = {"com.apple.private.amfi.can-execute-cdhash": True,
          "com.apple.private.security.no-sandbox": True,
          "com.apple.private.security.no-container": True,
          "get-task-allow": True, "platform-application": True}
PREFIX = "PATH=" + PATH_VALUE + "; export PATH\nset -eu\n"
GUARD = r"""process_list=$(/bin/ps -axo pid=,comm=) || exit 8
[ -n "$process_list" ] || exit 8
process_state=$(printf '%s\n' "$process_list" | awk '
/\/VirtualMachine[.]xpc\/Contents\/MacOS\/com[.]apple[.]Virtualization[.]VirtualMachine$/ { active=1 }
/ParavirtualizedGraphicsGPUTask/ { active=1 }
/\/VirtualMac(2)?[.]app\/VirtualMac$/ { active=1 }
END { print active ? "ACTIVE" : "OFF" }') || exit 8
[ "$process_state" = OFF ] || { printf 'ABORT_APP_VMM_OR_GPU_RUNNING\n' >&2; exit 8; }
"""


def sha(data):
    return hashlib.sha256(data).hexdigest()


def need(ok, message):
    if not ok:
        raise ValueError(message)


def verify(candidate, expected):
    need(re.fullmatch("[a-f0-9]{64}", expected) is not None, "literal candidate manifest hash required")
    manifest_raw = (candidate / "manifest.json").read_bytes()
    need(sha(manifest_raw) == expected, "candidate manifest changed")
    manifest = json.loads(manifest_raw)
    need(manifest.get("deviceExecuted") is False and manifest.get("deviceDirectory") == DEVICE, "candidate scope")
    seen = set()
    for row in manifest["files"]:
        relative = Path(row["path"])
        p = candidate / relative
        need(not relative.is_absolute() and ".." not in relative.parts and str(relative) not in seen and
             not p.is_symlink() and p.is_file() and p.resolve().is_relative_to(candidate.resolve()), "safe manifest path")
        seen.add(str(relative))
        raw = p.read_bytes()
        need(len(raw) == row["bytes"] and sha(raw) == row["sha256"], "candidate bytes changed: " + str(relative))
    actual = {str(p.relative_to(candidate)) for p in candidate.rglob("*") if p.is_file() and p.name != "manifest.json"}
    need(actual == seen and all(not p.is_symlink() for p in candidate.rglob("*")), "exact closed candidate file set")
    report = json.loads((candidate / "build-result.json").read_text())
    need(report["deviceExecuted"] is False and report["localMacAllocationFixturePassed"] is True, "local build proof")
    ios = report["files"]["ios"]
    need(ios["entitlements"] == RIGHTS and len(ios["strongImportRows"]) == 5 and
         all("weak" not in line.lower() and "from VM27AllocatorProvider" in line
             for line in ios["strongImportRows"]), "exact process rights and strong imports")
    deployment = []
    for role, name in (("probe", "allocator-full-five-probe"), ("provider", "VM27AllocatorProvider.dylib")):
        data = ios[role]
        path = candidate / "ios" / name
        raw = path.read_bytes()
        need(len(raw) == data["bytes"] and sha(raw) == data["sha256"], "exact deployment file")
        subprocess.run(["codesign", "--verify", "--strict", str(path)], capture_output=True, check=True)
        sig = subprocess.run(["codesign", "-d", "--verbose=4", str(path)], capture_output=True, check=True)
        need(("CDHash=" + data["cdhash"]).encode() in sig.stderr.splitlines(), "exact code hash")
        ent = subprocess.run(["codesign", "-d", "--entitlements", ":-", str(path)], capture_output=True, check=True).stdout
        need((plistlib.loads(ent) if ent else {}) == (RIGHTS if role == "probe" else {}), "exact signed entitlements")
        deployment.append(dict(name=name, path=str(path), bytes=data["bytes"], sha256=data["sha256"], cdhash=data["cdhash"]))
    return manifest, report, deployment


def file_pins(rows):
    text = ""
    for row in rows:
        path = shlex.quote(DEVICE + "/" + row["name"])
        text += "[ -f " + path + " ] && [ ! -L " + path + " ]\n"
        text += "[ \"$(wc -c < " + path + " | tr -d '[:space:]')\" = " + str(row["bytes"]) + " ]\n"
        text += "[ \"$(sha256sum " + path + " | cut -d ' ' -f1)\" = " + row["sha256"] + " ]\n"
        text += "[ \"$(ldid -h " + path + " 2>&1 | sed -n 's/^CDHash=//p')\" = " + row["cdhash"] + " ]\n"
    return text


def scripts(rows):
    folder = shlex.quote(DEVICE)
    pins = file_pins(rows)
    stage = PREFIX + GUARD + "umask 077\n[ ! -e " + folder + " ] && [ ! -L " + folder + " ]\n"
    stage += "mkdir -m700 " + folder + "\ntar -xf - -C " + folder + "\n" + pins
    for row in rows:
        stage += "jbctl trustcache add " + row["cdhash"] + " >&2\n"
    stage += "printf 'EXACT_PRIVATE_FULL_FIVE_STAGED\\n'\n"
    child = "printf 'ACTUAL_ENV_BEGIN\\n' >&2\nenv >&2\nprintf 'ACTUAL_ENV_END\\n' >&2\n"
    child += shlex.join([DEVICE + "/allocator-full-five-probe", "--library",
                       DEVICE + "/VM27AllocatorProvider.dylib"]) + " &\nnative_pid=$!\n"
    child += "printf 'ACTUAL_NATIVE_STARTED pid=%s\\n' \"$native_pid\" >&2\n"
    child += "set +e\nwait \"$native_pid\"\nnative_exit=$?\nset -e\n"
    child += "printf 'ACTUAL_NATIVE_WAIT pid=%s exit=%s completed=1\\n' \"$native_pid\" \"$native_exit\" >&2\n"
    child += "exit \"$native_exit\"\n"
    execute = PREFIX + pins + GUARD + "umask 077\nset -C\nexec 3>" + folder + "/native.stdout\n"
    execute += "exec 4>" + folder + "/native.stderr\nset +e\n"
    execute += shlex.join(["timeout", "-k", "1", "20", "env", "-i", "PATH=" + PATH_VALUE,
                          "/var/jb/bin/sh", "-c", child]) + " >&3 2>&4\n"
    execute += "outer_exit=$?\nset -e\ncat " + folder + "/native.stdout\ncat " + folder + "/native.stderr >&2\n"
    execute += "exit \"$outer_exit\"\n"
    return {"stage": stage, "execute": execute}


def parse_wait(err, exit_code):
    need(len(err) <= 65536, "native stderr bound")
    text = err.decode("ascii", errors="strict")
    match = re.fullmatch(r"ACTUAL_ENV_BEGIN\n((?:[^\n]+\n)*)ACTUAL_ENV_END\n"
        r"ACTUAL_NATIVE_STARTED pid=([1-9][0-9]*)\n"
        r"ACTUAL_NATIVE_WAIT pid=\2 exit=([0-9]{1,3}) completed=1\n", text)
    need(match is not None and int(match[3]) == exit_code, "direct native child wait")
    env = {}
    for line in match[1].splitlines():
        need(re.fullmatch(r"(PATH|PWD)=[ -~]*", line) is not None, "only clean PATH/PWD environment")
        k, value = line.split("=", 1)
        need(k not in env, "unique environment key")
        env[k] = value
    need(env.get("PATH") == PATH_VALUE, "exact rootless PATH")
    return int(match[2]), int(match[3]), env


def execute(candidate, digest, output):
    manifest, report, rows = verify(candidate, digest)
    need(not output.exists() and not output.resolve().is_relative_to(candidate.resolve()), "fresh result outside candidate")
    output.mkdir(parents=True, exist_ok=False)
    cmds = scripts(rows)
    for name, script in cmds.items():
        (output / (name + ".sh")).write_text(script)
    # Root alone chooses --run. Local verification never imports remote or contacts iPad.
    sys.path.insert(0, str(ROOT / "DeviceDiagnostics/2026-10-02-ssh-steam-repair"))
    import remote
    payload = io.BytesIO()
    with tarfile.open(fileobj=payload, mode="w") as archive:
        for row in rows:
            data = Path(row["path"]).read_bytes()
            need(sha(data) == row["sha256"], "payload pin")
            entry = tarfile.TarInfo(row["name"])
            entry.uid = entry.gid = 0; entry.mode = 0o700; entry.size = len(data)
            archive.addfile(entry, io.BytesIO(data))
    staged = remote.run(cmds["stage"], device="ipad", root=True, input_bytes=payload.getvalue(), timeout=30)
    (output / "stage.stdout").write_bytes(staged.stdout); (output / "stage.stderr").write_bytes(staged.stderr)
    (output / "stage.exit").write_text(str(staged.returncode) + "\n")
    need(staged.returncode == 0 and staged.stdout == b"EXACT_PRIVATE_FULL_FIVE_STAGED\n", "exact private staging required")
    result = dict(passed=False, manifestSHA256=digest, frozenFilesVerified=len(manifest["files"]),
                  deviceDirectory=DEVICE, deploymentFiles=rows, productionModified=False, full27VMMProved=False)
    try:
        run = remote.run(cmds["execute"], device="ipad", root=True, timeout=27)
        raw, err, code = run.stdout, run.stderr, run.returncode
    except subprocess.TimeoutExpired as exc:
        raw, err, code = exc.stdout or b"", exc.stderr or b"", 124
    (output / "native.stdout").write_bytes(raw); (output / "native.stderr").write_bytes(err)
    (output / "native.exit").write_text(str(code) + "\n")
    result.update(transportExit=code, stdoutSHA256=sha(raw), stderrSHA256=sha(err))
    try:
        pid, native_exit, environment = parse_wait(err, code)
        result.update(actualPID=pid, nativeExit=native_exit, nativeWaitCompleted=True, actualEnvironment=environment)
        # The frozen validator is bound by the candidate closure, not whatever is currently in the repo.
        spec = importlib.util.spec_from_file_location("allocator_five_validator", candidate / "source/validate-modern-allocator-full-five.py")
        validator = importlib.util.module_from_spec(spec); spec.loader.exec_module(validator)
        checked = validator.validate(raw, native_exit, "ios", report["files"]["ios"]["provider"]["sha256"], pid,
                                     report["files"]["ios"]["provider"])
        post = PREFIX + file_pins(rows) + GUARD + "if kill -0 " + str(pid) + " 2>/dev/null; then exit 7; fi\n"
        post += "printf 'PRIVATE_ALLOCATOR_EXACT_CHILD_ABSENT\\n'\n"
        (output / "post.sh").write_text(post)
        after = remote.run(post, device="ipad", root=True, timeout=15)
        (output / "post.stdout").write_bytes(after.stdout); (output / "post.stderr").write_bytes(after.stderr)
        (output / "post.exit").write_text(str(after.returncode) + "\n")
        need(after.returncode == 0 and after.stdout == b"PRIVATE_ALLOCATOR_EXACT_CHILD_ABSENT\n" and not after.stderr,
             "post exact file hashes and child absent")
        result.update(passed=True, validation=checked, nativeChildAbsent=True)
    except (ValueError, UnicodeError, KeyError, subprocess.TimeoutExpired) as failure:
        result["strictFailure"] = str(failure)
    (output / "result.json").write_text(json.dumps(result, indent=2) + "\n")
    print(json.dumps(result, indent=2))
    return 0 if result["passed"] else 83


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--candidate", type=Path, required=True)
    p.add_argument("--manifest-sha", required=True)
    mode = p.add_mutually_exclusive_group(required=True)
    mode.add_argument("--verify-local", action="store_true")
    mode.add_argument("--prepare", type=Path, help="Write planned shell scripts only; no device access")
    mode.add_argument("--run", action="store_true")
    p.add_argument("--output", type=Path)
    a = p.parse_args()
    if a.run:
        need(a.output is not None, "fresh actual output required")
        return execute(a.candidate, a.manifest_sha, a.output)
    manifest, _, rows = verify(a.candidate, a.manifest_sha)
    if a.prepare:
        a.prepare.mkdir(parents=True, exist_ok=False)
        for name, script in scripts(rows).items():
            path = a.prepare / (name + ".sh")
            path.write_text(script)
            subprocess.run(["/bin/sh", "-n", str(path)], check=True)
    print(json.dumps(dict(frozenFilesVerified=len(manifest["files"]), exactSignedDeploymentFiles=2,
                         deviceContacted=False, deviceExecuted=False), indent=2))
    return 0


if __name__ == "__main__":
    sys.exit(main())
