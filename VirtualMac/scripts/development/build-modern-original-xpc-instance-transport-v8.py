#!/usr/bin/env python3
"""Separate v8 actual bundle title registration fixture; local-only execution."""
from pathlib import Path
import hashlib
import importlib.util
import json
import os
import plistlib
import re
import shutil
import subprocess
import sys
sys.dont_write_bytecode = True
ROOT = Path(__file__).resolve().parents[2]
N = ROOT.parent / "DeviceDiagnostics/2026-10-08-full-macos27-cpu-vmm"
FROZEN = N / "xpc-approved-code-v1/build-v3"
BASE_V6 = N / "xpc-original-instance-transport-v1/build-v6"
RIGHTS = {"platform-application": True, "com.apple.private.security.no-container": True,
    "com.apple.private.security.no-sandbox": True, "com.apple.private.amfi.can-execute-cdhash": True,
    "com.apple.private.virtualization.plugin": True, "com.apple.private.virtualization": True}
sha = lambda p: hashlib.sha256(p.read_bytes()).hexdigest()


def main(output):
    assert sha(BASE_V6 / "freeze.json") == "e3ffac4cf1f882385bc98a7273b975b1f9b2071766c907511314bd554835d2e6"
    for row in json.loads((BASE_V6 / "freeze.json").read_text())["files"]:
        p = BASE_V6 / row["path"]; assert p.stat().st_size == row["bytes"] and sha(p) == row["sha256"]
    out = Path(output).resolve(); out.mkdir(mode=0o700, parents=True, exist_ok=False)
    source = out / "source"; source.mkdir()
    for p in (Path(__file__), BASE_V6 / "source/modern_xpc_private_consumer.h", BASE_V6 / "source/modern_xpc_private_endpoint.h", BASE_V6 / "source/modern_xpc_bundle_registry.h",
              BASE_V6 / "source/modern_xpc_approved_code.h", BASE_V6 / "source/modern_xpc_lwcr_policy.h", ROOT / "scripts/tests/test-modern-original-xpc-instance-transport-v8.c", ROOT / "vz/host/modern_xpc_original_instance_transport_v8.c", ROOT / "vz/host/modern_xpc_original_instance_transport_v8.h", ROOT / "vz/host/modern_xpc_original_instance_transport_v8.md", ROOT / "scripts/tests/read-modern-original-xpc-instance-registration-v8-mac.py", ROOT / "scripts/tests/test-modern-v8-registration-channel.inc", N / "vmm-client-registration-bridge-development-v1/source/vm27_client_registration_v1.h", ROOT / "scripts/tests/validate-modern-original-xpc-instance-transport-v8.py") :
        shutil.copyfile(p, source / p.name)
    pins = BASE_V6 / "source/modern_xpc_original_instance_pins.h"
    shutil.copyfile(pins, source / pins.name)
    spec = importlib.util.spec_from_file_location("base", ROOT / "scripts/development/build-modern-xpc-lwcr-policy.py")
    B = importlib.util.module_from_spec(spec); spec.loader.exec_module(B)
    bridgeBuild = N / "vmm-client-registration-bridge-development-v1"
    assert sha(bridgeBuild / "freeze.json") == "19e5b79c0881644f476f2eacf6d72226e5e0d0f528c97f883ba2d98b93568604"
    for pin in json.loads((bridgeBuild / "freeze.json").read_text())["files"]:
        p = bridgeBuild / pin["path"]; assert p.stat().st_size == pin["bytes"] and sha(p) == pin["sha256"]
    bridgeRows = json.loads((bridgeBuild / "candidate.json").read_text())["files"]
    infoPlist = source / "VM27RegistrationV8-Info.plist"
    infoPlist.write_bytes(plistlib.dumps({"CFBundleIdentifier": "com.virtualmac.diagnostics.registration-v8", "CFBundleExecutable": "original-xpc-instance-transport-v8-probe", "CFBundlePackageType": "APPL", "CFBundleName": "VM27RegistrationV8", "CFBundleDisplayName": "VM27 Owned Registration v8"}))
    candidates, processes = [], []
    def run(label, argv, expectedExit=0):
        env = {k: v for k, v in os.environ.items() if not k.startswith("DYLD_")}
        child = subprocess.Popen(argv, stdout=subprocess.PIPE, stderr=subprocess.PIPE, env=env)
        try: stdout, stderr = child.communicate(timeout=25)
        except subprocess.TimeoutExpired: child.kill(); child.communicate(); raise
        (out / (label + ".argv.json")).write_text(json.dumps(argv, indent=2) + "\n")
        (out / (label + ".stdout")).write_bytes(stdout); (out / (label + ".stderr")).write_bytes(stderr)
        processes.append({"label": label, "directChildPID": child.pid, "observedWaitExit": child.returncode, "reaped": True, "expectedExit": expectedExit})
        assert child.returncode == expectedExit, (label, child.returncode, stdout.decode(errors="replace")[-7000:], stderr.decode(errors="replace")[-7000:])
        return stdout, stderr
    def sign(role, p, rights, label):
        if role == "ios": B.target16(p)
        ent = p.parent / (p.name + ".entitlements"); ent.write_bytes(plistlib.dumps(rights))
        run(label + "-sign", ["codesign", "--force", "--sign", "-", "--timestamp=none", "--identifier", "com.virtualmac.diagnostics.original-xpc-instance-registration-v8." + p.name, "--entitlements", str(ent), str(p)])
        run(label + "-strict", ["codesign", "--verify", "--strict", str(p)])
        run(label + "-validate", ["xcrun", "dyld_info", "-validate_only", str(p)])
        _, desc = run(label + "-signature", ["codesign", "-dvvv", str(p)])
        return {"role": role, "name": p.name, "path": str(p), "bytes": p.stat().st_size, "sha256": sha(p), "UUID": B.uuid(p.read_bytes()), "CDHash": re.search(rb"CDHash=([a-f0-9]{40})", desc)[1].decode(), "entitlements": rights}
    nativeRuns = []; metadataRuns = []
    for role, sdk, target in (("macos", "macosx", "arm64e-apple-macos13"), ("ios", "iphoneos", "arm64e-apple-ios16.1")):
        folder = out / role; folder.mkdir(); previous = {}
        for name in ("VM27ApprovedCode.dylib", "VM27LWCRPolicy.dylib", "VM27BundleRegistry.dylib", "VM27PrivateEndpoint.dylib", "VM27PrivateConsumer.dylib"):
            if name == "VM27PrivateConsumer.dylib": previousBuild = N / "xpc-owned-service-launch-v1/build-v3"
            elif name == "VM27BundleRegistry.dylib": previousBuild = N / "xpc-bundle-registry-v1/build-v4"
            elif name == "VM27PrivateEndpoint.dylib": previousBuild = N / "xpc-private-child-launch-v1/xpc-build-v4"
            else: previousBuild = FROZEN
            imported = json.loads((previousBuild / "candidate.json").read_text())
            original = next(r for r in imported["candidates"] if r["role"] == role and r["name"] == name)
            p = folder / name; shutil.copyfile(original["path"], p); assert sha(p) == original["sha256"]
            r = dict(original); r.update({"path": str(p), "source": original["path"], "unchanged": True}); candidates.append(r); previous[name] = r
        original = next(r for r in bridgeRows if r["platform"] == ("mac" if role == "macos" else "ios") and r["role"] == "provider")
        p = folder / "VM27ClientRegistration.dylib"; shutil.copyfile(original["path"], p); assert sha(p) == original["sha256"]
        r = dict(original); r.update({"role": role, "name": p.name, "path": str(p), "source": original["path"], "unchanged": True}); candidates.append(r); previous[p.name] = r
        sdkPath = run(role + "-sdk", ["xcrun", "--sdk", sdk, "--show-sdk-path"])[0].decode().strip()
        base = ["xcrun", "clang", "-target", target, "-isysroot", sdkPath, "-fptrauth-abi-version=0", "-std=c11", "-DVM27_ENABLE_DIAGNOSTIC_ENDPOINT_FAILURE=1", "-fblocks", "-O2", "-Wall", "-Wextra", "-Werror", "-Wno-deprecated-declarations", "-I", str(source), "-Wl,-no_adhoc_codesign"]
        consumer = folder / "VM27PrivateConsumer.dylib"
        transport = folder / "VM27OriginalV8Transport.dylib"
        run(role + "-transport-compile", base + [str(source / "modern_xpc_original_instance_transport_v8.c"), str(consumer), str(folder / "VM27ApprovedCode.dylib"), str(folder / "VM27ClientRegistration.dylib"), "-framework", "Security", "-framework", "CoreFoundation", "-dynamiclib", "-Wl,-install_name,@rpath/VM27OriginalV8Transport.dylib", "-Wl,-current_version,1.0", "-Wl,-compatibility_version,1.0", "-o", str(transport)])
        transportRow = sign(role, transport, {}, role + "-transport")
        candidates.append(transportRow); previous[transport.name] = transportRow
        macros = []
        for key, name in (("TRANSPORT", transport.name), ("CONSUMER", consumer.name), ("REGISTRY", "VM27BundleRegistry.dylib"), ("ENDPOINT", "VM27PrivateEndpoint.dylib"), ("APPROVED", "VM27ApprovedCode.dylib"), ("POLICY", "VM27LWCRPolicy.dylib"), ("CLIENT_REGISTRATION", "VM27ClientRegistration.dylib")):
            row = previous[name]; macros += ['#define VM27_' + key + '_SHA256 "' + row["sha256"] + '"', '#define VM27_' + key + '_BYTES ' + str(row["bytes"]) + 'ULL', '#define VM27_' + key + '_UUID "' + row["UUID"] + '"']
        (folder / "modern_xpc_factory_pins.h").write_text("\n".join(macros) + "\n")
        probe = folder / "original-xpc-instance-transport-v8-probe"
        runtimePath = "/var/root/VirtualMac2/testing/original-xpc-instance-registration-v8" if role == "ios" else str(folder)
        run(role + "-probe-compile", base + ["-I", str(folder), str(source / "test-modern-original-xpc-instance-transport-v8.c")] + [str(transport)] + [str(folder / n) for n in previous if n != transport.name] + ["-framework", "Security", "-framework", "CoreFoundation", "-Wl,-rpath,@executable_path", "-Wl,-rpath," + runtimePath, "-o", str(probe)])
        row = sign(role, probe, RIGHTS if role == "ios" else {}, role + "-probe")
        app = folder / "VM27RegistrationV8.app"; app.mkdir()
        if role == "macos":
            contents = app / "Contents"; contents.mkdir(); executableFolder = contents / "MacOS"; executableFolder.mkdir(); shutil.copyfile(infoPlist, contents / "Info.plist")
        else:
            executableFolder = app; shutil.copyfile(infoPlist, app / "Info.plist")
        bundledProbe = executableFolder / probe.name; shutil.copyfile(probe, bundledProbe); bundledProbe.chmod(0o700)
        assert sha(bundledProbe) == row["sha256"]
        row.update({"path": str(bundledProbe), "unbundledSignedPath": str(probe), "actualMainBundleInfoPlist": str(contents / "Info.plist" if role == "macos" else app / "Info.plist"), "InfoPlistSHA256": sha(infoPlist)})
        candidates.append(row)
        run(role + "-transport-imports", ["xcrun", "dyld_info", "-imports", str(transport)])
        run(role + "-transport-exports", ["xcrun", "dyld_info", "-exports", str(transport)])
        run(role + "-consumer-imports", ["xcrun", "dyld_info", "-imports", str(consumer)])
        run(role + "-probe-imports", ["xcrun", "dyld_info", "-imports", str(probe)])
        if role == "macos":
            wrongApp = folder / "VM27RegistrationV8WrongType.app"; wrongContents = wrongApp / "Contents"; wrongExecutable = wrongContents / "MacOS"; wrongExecutable.mkdir(parents=True)
            wrongMetadata = plistlib.loads(infoPlist.read_bytes()); wrongMetadata["CFBundleDisplayName"] = 42
            (wrongContents / "Info.plist").write_bytes(plistlib.dumps(wrongMetadata))
            wrongProbe = wrongExecutable / probe.name; shutil.copyfile(probe, wrongProbe); wrongProbe.chmod(0o700); assert sha(wrongProbe) == row["sha256"]
            metadataRuns = [("missing-main-bundle", [str(probe), row["sha256"], str(row["bytes"]), row["CDHash"], "normal"]), ("wrong-type-main-bundle", [str(wrongProbe), row["sha256"], str(row["bytes"]), row["CDHash"], "normal"])]
            nativeRuns = [[str(bundledProbe), row["sha256"], str(row["bytes"]), row["CDHash"], variant] for variant in ("normal", "deny-handshake", "timeout-handshake", "deny-instance", "timeout-instance", "registration-channel-only")]
    for command in nativeRuns:
        run("macos-" + command[-1] + "-native", command)
    for label, command in metadataRuns:
        run("macos-" + label + "-native", command, expectedExit=78)
    result = {"candidates": candidates, "sourceSHA256": {p.name: sha(p) for p in source.iterdir()}, "processes": processes,
        "deviceOperations": False, "iOSExecuted": False, "originalVMMExecuted": False, "completeBundleRegistration": False,
        "systemModified": False, "bootstrapChanges": 0, "launchdRegistrations": 0, "MacNativePositiveCovered": False, "MacActualRegistryComponentPositiveCovered": True, "actualMainBundleMetadataRequired": True, "MacNativeStrictDenialCovered": True, "originalVMWireProtocolExecuted": False}
    (out / "candidate.json").write_text(json.dumps(result, indent=2) + "\n")
    ios = {r["name"]: r for r in candidates if r["role"] == "ios"}
    probeRow = ios["original-xpc-instance-transport-v8-probe"]
    orderedNames = [probeRow["name"], "VM27OriginalV8Transport.dylib", "VM27PrivateConsumer.dylib", "VM27BundleRegistry.dylib", "VM27PrivateEndpoint.dylib", "VM27ApprovedCode.dylib", "VM27LWCRPolicy.dylib", "VM27ClientRegistration.dylib"]
    package = []
    for name in orderedNames:
        row = ios[name]; relative = "VM27RegistrationV8.app/" + name if name == probeRow["name"] else name
        package.append({"bundleRelativePath": relative, "sourcePath": row["path"], "bytes": row["bytes"], "sha256": row["sha256"], "UUID": row["UUID"], "CDHash": row["CDHash"], "runtimeMode": "0700" if name == probeRow["name"] else "0600"})
    metadata = Path(probeRow["actualMainBundleInfoPlist"])
    package.append({"bundleRelativePath": "VM27RegistrationV8.app/Info.plist", "sourcePath": str(metadata), "bytes": metadata.stat().st_size, "sha256": sha(metadata), "runtimeMode": "0600"})
    orderedDigest = hashlib.sha256()
    for row in package: orderedDigest.update(Path(row["sourcePath"]).read_bytes())
    readerName = "read-modern-original-xpc-instance-registration-v8-mac.py"
    manifest = {"schema": "VM27 owned IPC registration v8 bounded diagnostic readiness v1", "candidateSHA256": sha(out / "candidate.json"),
        "readyForBoundedOwnIPCDeviceDiagnostic": True, "functionalReady": False, "iOSExecuted": False, "originalVMMExecuted": False, "full27Backend": False,
        "fixedPrivateRuntimeRoot": "/var/root/VirtualMac2/testing/original-xpc-instance-registration-v8", "runtimeRootMustInitiallyBeAbsent": True,
        "runtimeDirectoryOwner": 0, "runtimeDirectoryMode": "0700", "runtimeFileOwner": 0, "ordinaryFileLinkCount": 1, "symlinksAllowed": False,
        "orderedPackageFiles": package, "orderedPackageSHA256": orderedDigest.hexdigest(), "orderedPackageSHA256Algorithm": "SHA256 of complete file bytes concatenated in orderedPackageFiles order",
        "flat7Libraries": [r["bundleRelativePath"] for r in package if r["bundleRelativePath"].endswith(".dylib")],
        "exactArgvByMode": {mode: ["VM27RegistrationV8.app/" + probeRow["name"], probeRow["sha256"], str(probeRow["bytes"]), probeRow["CDHash"], mode] for mode in ("normal", "deny-handshake", "timeout-handshake", "deny-instance", "timeout-instance")},
        "limits": {"CPUHardSeconds": 5, "CPUSoftSeconds": 5, "CPUActuallyCheckedBeforeSpawn": True, "parentAndChildAlarmSeconds": 15, "normalChildReapPollingSeconds": 2,
            "ownedTimeoutCleanup": "SIGKILL only actual posix_spawn-owned unreaped PID after real WNOHANG zero result, then actual wait/reap; preserves failure"},
        "parser": {"relativePath": "source/" + readerName, "sha256": sha(source / readerName), "builtinsOnly": True,
            "orderedAPIs": [{"name": "native_transcript", "parameters": ["buildPath", "stdoutPath", "macos", "variant", "actualParentPID", "observedWaitExit"]},
                {"name": "component_transcript", "parameters": ["buildPath", "stdoutPath", "actualParentPID", "observedWaitExit"]},
                {"name": "metadata_control", "parameters": ["buildPath", "label", "actualPID", "observedWaitExit"]}],
            "parse_native_ios": None, "nativeIOSDiagnosticClassification": "unknown until real saved receipt and separate strict native IOS reader review"},
        "actualMacScope": {"typedFactoryPositive": False, "typedRegistrationPositive": False, "oneShotPositive": False, "originalHandlerPositive": False,
            "typedFactoryNativeBooleanFalseStatus": 13, "separateRawRegistryActualPositive": True, "rawRegistrySuccessDoesNotAuthorizeTypedHandler": True},
        "pendingNativeIOSNormalSuccessRequired": {"actualMainBundleTitleCopies": 1, "authenticatedRegistrationCommits": 1, "authenticatedInstanceBindings": 1,
            "ownedDiagnosticHandlerCalls": 1, "wireReplies": 65, "acceptedDiagnosticMessages": 64, "wrongNonceDiagnosticMessagesRefused": 1, "actualChildExit": 0,
            "actualChildReapedAndAbsent": True, "ownedReferencesAndFinalInvalidDrained": True, "nativePluginBooleanTrueRequired": True},
        "dynamicFixture": {"createdByCLIAtRuntimeOnly": True, "mkdtempTemplate": "/tmp/VM27-OwnedFactory-XXXXXX", "actualOwnerMatchesEffectiveUID": True,
            "directoryMode": "0700", "staticDirectories": ["Owned.bundle", "Owned.bundle/Contents", "Owned.bundle/Contents/XPCServices", "Owned.bundle/Contents/XPCServices/One.xpc", "Owned.bundle/Contents/XPCServices/One.xpc/Contents", "Owned.bundle/Contents/XPCServices/One.xpc/Contents/MacOS"],
            "files": [{"relativePath": "Owned.bundle/Contents/Info.plist", "mode": "0600", "createdByFrozenFixtureSource": True},
                {"relativePath": "Owned.bundle/Contents/XPCServices/One.xpc/Contents/Info.plist", "mode": "0600", "actualMainBundleDisplayName": "VM27 Owned Registration v8"},
                {"relativePath": "Owned.bundle/Contents/XPCServices/One.xpc/Contents/MacOS/ServiceExec", "mode": "0700", "byteExactCopyOfCLI": True, "sha256": probeRow["sha256"]}],
            "normalCleanup": "after actual owned child reap remove only the 3 fixture files, then 6 fixture subdirectories and its unique root; assert root absent", "predeploymentFiles": False},
        "nativeCPUProbeCalls": 0, "nativeVMCalls": 0, "nativeGPUCalls": 0, "systemBootstrapChanges": 0, "launchdRegistrations": 0}
    (out / "diagnostic-readiness.json").write_text(json.dumps(manifest, indent=2) + "\n")
    print(json.dumps({"output": str(out), "candidateSHA256": sha(out / "candidate.json"), "diagnosticReadinessSHA256": sha(out / "diagnostic-readiness.json"), "orderedPackageSHA256": manifest["orderedPackageSHA256"], "iOSBuiltOnlyFiles": 8, "actualMacRuns": 8}, indent=2))


if __name__ == "__main__":
    assert len(sys.argv) == 2
    main(sys.argv[1])
