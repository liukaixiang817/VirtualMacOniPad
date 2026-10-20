#!/usr/bin/env python3
"""Freeze real HOST compiler evidence; this script never executes target code."""
from pathlib import Path
import datetime
import hashlib
import json
import re
import struct

R = Path(__file__).resolve().parents[3]
N = R / "DeviceDiagnostics/2026-10-08-full-macos27-cpu-vmm"
RAW = N / "mac27-native-sandbox-compiler-readonly-v1-attempt1"
BASE = N / "mac27-vmm-sandbox-compile-only-host-v1-attempt1"
IMPORT = N / "mac27-vmm-sandbox-import-dir-compile-only-host-v1-attempt1"
OUT = N / "mac27-genuine-sandbox-compiler-host-audit-v1-attempt1"


def pin(path):
    data = path.read_bytes()
    return {"path": str(path), "bytes": len(data), "sha256": hashlib.sha256(data).hexdigest()}


def write(name, data):
    (OUT / name).write_text(json.dumps(data, indent=2) + "\n")


def main():
    OUT.mkdir()
    binary = (RAW / "libsandbox.1.dylib").read_bytes()
    assert len(binary) == 616179
    assert hashlib.sha256(binary).hexdigest() == "4fe3124ad9134a9cf076436aac3c3d9714c35957fc60f7ec73432d7063100e37"
    for directory, case, code in [(BASE, "run", 0), (IMPORT, "empty-root", 6), (IMPORT, "owned-genuine-closure", 0)]:
        assert (directory / (case + ".exit")).read_text().strip() == str(code)
        assert not (directory / (case + ".stderr")).read_bytes()
        stdout = (directory / (case + ".stdout")).read_text()
        assert "compile_uuid=648b6ec9b80a3673ac47f6f7806bb158" in stdout
        assert "compile_calls=1" in stdout
        if code == 0:
            assert "profile_builtin=(null)\nprofile_size=13696\nprofile_data_nonnull=1" in stdout
            assert "policy_apply_calls=0" in stdout
        else:
            assert 'compile_error=unable to open "system.sb": not found' in stdout
    blob = (BASE / "compiled-profile.bin").read_bytes()
    assert blob == (IMPORT / "owned-genuine-closure.compiled-profile.bin").read_bytes()
    assert len(blob) == 13696 and hashlib.sha256(blob).hexdigest() == "2b7ad4d1be09203d49af1dafa560dfdb9b3ddcd5953c7ee061713a5fb34e898b"
    names = json.loads((RAW / "builtin-operation-names-210.json").read_text())
    for row in names:
        fileoff = 442368 + 0x1e06d1970 - 0x1e06d07b0 + row["index"] * 8
        pointer = struct.unpack_from("<Q", binary, fileoff)[0]
        assert pointer == int(row["stringVA"], 16)
        offset = pointer - 0x184e62000
        assert binary[offset:binary.index(0, offset)].decode() == row["name"]
    assert len(names) == 210 and names[204]["name"] == "default-message-filter"
    code_points = {
        "policy_operation_count_204": (0x184e63104, "82198052"),
        "serializer_operation_count_204": (0x184e79f20, "88198052"),
        "serializer_operation_count_header_plus4": (0x184e79f24, "e8930239"),
        "get_name_limit_210": (0x184e8f43c, "1f490371"),
        "get_name_table_adrp": (0x184e8f444, "09c22dd0"),
        "get_name_table_add": (0x184e8f448, "29c12591"),
        "get_name_index_load": (0x184e8f44c, "217968f8"),
        "compile_loads_genuine_import_prelude": (0x184e64070, "21e42991"),
    }
    for _, (address, expected) in code_points.items():
        assert binary[address - 0x184e62000:address - 0x184e62000 + 4].hex() == expected
    lines = (RAW / "libsandbox.text.llvm.txt").read_text().splitlines()
    spans = [(0x184e63100, 0x184e63114), (0x184e63f84, 0x184e64010),
             (0x184e6406c, 0x184e64084), (0x184e8c6dc, 0x184e8c768),
             (0x184e8f438, 0x184e8f454), (0x184e79e18, 0x184e7a100),
             (0x184e62eac, 0x184e62eec), (0x184e8259c, 0x184e825cc)]
    evidence = [{"startVA": hex(start), "endVAExclusive": hex(end),
                 "rawBytesSHA256": hashlib.sha256(binary[start-0x184e62000:end-0x184e62000]).hexdigest(),
                 "actualLLVMDisassembly": [line for line in lines if re.match(r"[0-9a-f]+:", line) and start <= int(line.split(":")[0], 16) < end]}
                for start, end in spans]
    write("focused-real-code.json", evidence)
    prelude_start = 0x36a79
    prelude_end = binary.index(0, prelude_start)
    prelude = binary[prelude_start:prelude_end]
    assert b'(param "IMPORT_DIR")' in prelude and b'*default-import-search-paths*' in prelude
    assert b'(define (import path)' in prelude and b'(split-string (param "IMPORT_DIR") ":")' in prelude
    imports = json.loads((RAW / "captured-current-libsystem-import-routes.json").read_text())
    assert imports["importEntries"] == 184 and imports["nativeResolvedEntries"] == 167 and imports["genuineMatchEntries"] == 6
    profile = Path("/System/Library/Frameworks/Virtualization.framework/Versions/A/XPCServices/com.apple.Virtualization.VirtualMachine.xpc/Contents/Resources/com.apple.Virtualization.VirtualMachine.sb")
    profiles = [profile, Path("/System/Library/Sandbox/Profiles/system.sb"), Path("/System/Library/Sandbox/Profiles/dyld-support.sb")]
    expected = [(32301, "59e239c49d6fefab06e56faeb284929853c7457f84b1b54faabd30857d7d1504"),
                (12041, "180a0356611b5de7a7db84b800ed47a1d2f15ec884d0fb960445366ededac7c8"),
                (3152, "bdfc2354c683c8fb95a39e63fbc8610e9739b0256c89ab880564edefbe73a5ce")]
    for path, (size, digest) in zip(profiles, expected):
        actual = pin(path)
        assert actual["bytes"] == size and actual["sha256"] == digest
    sources = [Path(__file__).resolve(), R / "VirtualMac/scripts/development/mac27_vmm_sandbox_compile_only_host_v1.c",
               R / "VirtualMac/scripts/development/mac27_vmm_sandbox_import_dir_compile_only_host_v1.c"]
    for path in sources[1:]:
        assert not re.search(rb"\b(?:sandbox_apply|sandbox_init|sandbox_init_with_parameters)\s*\(", path.read_bytes())
    report = {
        "schema": "Genuine same-version Mac27 sandbox compiler actual HOST audit v1",
        "recordedUTC": datetime.datetime.now(datetime.timezone.utc).isoformat(),
        "actualHostVersion": {"productVersion": "27.0.1", "build": "26A434", "compilerUUID": "648b6ec9b80a3673ac47f6f7806bb158", "compilerBase": "0x184e62000"},
        "scope": {"HOSTOnly": True, "deviceOperations": 0, "sandboxApplyLookups": 0, "sandboxApplyCalls": 0,
                  "sandboxInitLookups": 0, "sandboxInitCalls": 0, "iPadKernelCompatibilityVerified": False,
                  "nativeVMMMainOrFlagsModified": False},
        "actualNativeHostCompile": {"oneCompileCallPerRun": True, "cpuLimitSeconds": 10, "outerTimeoutSeconds": 20,
            "systemPathNullParametersExit": 0, "emptyOwnedImportRootExit": 6,
            "emptyOwnedImportRootRealError": 'unable to open "system.sb": not found',
            "ownedGenuineImportClosureExit": 0, "compiledBytes": len(blob), "compiledSHA256": hashlib.sha256(blob).hexdigest(),
            "compiledPrefix64Hex": blob[:64].hex(), "wholeBytesEqualAfterImportRelocation": True},
        "profileObjectABI": {"LP64SpanBytes": 24, "builtinSlotOffset": 0, "dataSlotOffset": 8, "sizeSlotOffset": 16,
            "actualBuiltinNull": True, "actualDataNonnull": True, "actualSize": 13696,
            "boundary": "The 24-byte envelope agrees with current iPad consumer span; serialized bytecode target compatibility is a separate requirement."},
        "trueCompiledTarget": {"operationBaseHardcoded": 0, "policyOperationCountHardcoded": 204,
            "operationNamesBuiltinCount": 210, "operationNamesBuiltinVA": "0x1e06d1970", "operationInfoBuiltinVA": "0x1e06db1d0",
            "messageFilterOperationIndices": [204, 205, 206, 207, 208, 209],
            "serializedHeader": {"spanBytes": 16, "offset0Width2": {"value": 0x6002, "meaning": "Feature flags assembled by explicit conditional bitwise OR, not a proved version number."},
                "offset2Width2": {"value": 228, "meaning": "Instruction count; checked by genuine too-many-instructions error branch."},
                "offset4Width1": {"value": 204, "meaning": "Hardcoded normal operation count."}},
            "kernelOperationTableDynamicallyQueriedByObservedTargetConstruction": False,
            "observedSysctlQueries": ["security.mac.sandbox.root_translation_enabled", "security.mac.sandbox.sandcastle.enabled"],
            "conclusion": "Running the unchanged compiler on iPad retains these genuine Mac27 built-in operation indices. Compile-only success on iPad would not establish that its older kernel accepts this bytecode."},
        "genuineImportProgram": {"embeddedPreludeVA": "0x184e98a79", "embeddedPreludeBytes": len(prelude), "embeddedPreludeSHA256": hashlib.sha256(prelude).hexdigest(),
            "loadedAtCompileCoreVA": "0x184e6406c", "paramName": "IMPORT_DIR", "separator": ":",
            "defaults": ["/System/Library/Sandbox/Profiles", "/usr/share/sandbox"],
            "relativeImportsUseExplicitSearchDirectories": True, "absoluteImportsLoadDirectly": True,
            "actualProfileImportClosure": [{**pin(path), "imports": [name.decode() for name in re.findall(rb'\(import\s+"([^"]+)"', path.read_bytes())]} for path in profiles],
            "ownedClosureResolvesWithoutSystemWrites": True,
            "futureAdapterBoundary": "Any internally added IMPORT_DIR parameter must be explicitly scoped to sealed owned resources; original Main flags=3 and caller NULL parameters remain real and unchanged."},
        "actualDependencies": {"compiler": ["/usr/lib/libMatch.1.dylib", "/usr/lib/libSystem.B.dylib"],
            "Match": ["/usr/lib/libSystem.B.dylib"], "nlistImports": 184, "compilerImports": 164, "MatchImports": 20,
            "capturedNativeLibSystemRoutes": 167, "genuineMac27MatchOrdinalEntries": 6,
            "capturedTreeUnresolvedEntries": imports["unresolvedCapturedTreeEntries"], "uncapturedLibSystemReexports": imports["uncapturedReexportPaths"],
            "fullNativeDependencyClosureVerified": False,
            "boundary": "These are actual nlist/export and captured native reexport routes, not proof of reconstructed optimized stubs/GOT or standalone loading."},
        "remainingRequiredWork": ["Reconstruct genuine cache-optimized stubs/GOT/branches and verify standalone two-library loading.",
            "Close strong imports explicitly; do not replace them with fabricated success.",
            "Only after reconstruction, run bounded owned iPad compile-only with sealed genuine resources.",
            "Establish kernel bytecode feature/operation-index compatibility before any apply attempt."],
        "APIPrimarySource": "https://raw.githubusercontent.com/WebKit/WebKit/main/Source/WTF/wtf/spi/darwin/SandboxSPI.h",
        "evidence": {"targetCode": pin(OUT / "focused-real-code.json"), "operationNames": pin(RAW / "builtin-operation-names-210.json"),
            "actualImports": pin(RAW / "captured-current-libsystem-import-routes.json"), "importRootResults": pin(IMPORT / "result.json")},
        "findings": []}
    write("report.json", report)
    files = sources + profiles + [Path("/System/Library/CoreServices/SystemVersion.plist"),
            N / "current-native-header-export-index-v3/index.json"]
    for directory in [RAW, BASE, IMPORT, OUT]:
        files.extend(path for path in directory.rglob("*") if path.is_file() and path.name != "freeze.json")
    files = sorted(set(files), key=str)
    write("freeze.json", {"schema": "Genuine Mac27 compiler HOST audit source/evidence freeze v1", "deviceOperations": 0,
          "sandboxApplyCalls": 0, "files": [pin(path) for path in files]})
    print(json.dumps({"report": pin(OUT / "report.json"), "freeze": pin(OUT / "freeze.json")}, indent=2))


if __name__ == "__main__":
    main()
