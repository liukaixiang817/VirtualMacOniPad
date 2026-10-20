#!/usr/bin/env python3
"""Build a new scoped ownership provider; no execution, installation or trust changes."""
import argparse
import hashlib
import json
import pathlib
import subprocess


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=pathlib.Path, required=True)
    args = parser.parse_args()
    output = args.output.resolve()
    if output.exists():
        parser.error("output must not already exist")
    output.mkdir(parents=True)
    project = pathlib.Path(__file__).resolve().parents[2]
    source = project / "vz/host/modern_swift_cvw_ownership_compat.cpp"
    header = source.with_suffix(".h")
    exports = ["VM27CVWOwnershipQuery", "swift_cvw_destroy", "swift_cvw_initWithCopy",
               "swift_cvw_assignWithCopy", "swift_cvw_assignWithTake",
               "swift_cvw_initializeBufferWithCopyOfBuffer"]
    records = []
    for sdk_name, target, role in [("iphoneos", "arm64e-apple-ios16.1", "ios"),
                                   ("macosx", "arm64e-apple-macos27.0", "mac")]:
        sdk = subprocess.check_output(["xcrun", "--sdk", sdk_name, "--show-sdk-path"], text=True).strip()
        library = output / ("VM27SwiftCVWOwnership-" + role + ".dylib")
        command = ["xcrun", "clang++", "-target", target, "-isysroot", sdk,
                   "-O2", "-std=c++17", "-fno-exceptions", "-fno-rtti", "-Wall", "-Wextra", "-Werror",
                   "-fno-typed-cxx-new-delete", "-fno-typed-memory-operations", "-dynamiclib", str(source),
                   "-L" + sdk + "/usr/lib/swift", "-lswiftCore",
                   "-Wl,-install_name,@rpath/VM27SwiftCVWOwnership.dylib", "-o", str(library)]
        command += ["-Wl,-exported_symbol,_" + name for name in exports]
        for label, argv in [(role + "-compile", command),
                            (role + "-sign", ["codesign", "--force", "--sign", "-", "--timestamp=none", str(library)]),
                            (role + "-strict", ["codesign", "--verify", "--strict", str(library)]),
                            (role + "-dyld", ["xcrun", "dyld_info", "-validate_only", str(library)]),
                            (role + "-imports", ["xcrun", "dyld_info", "-imports", str(library)]),
                            (role + "-exports", ["nm", "-gU", str(library)]),
                            (role + "-signature", ["codesign", "-d", "--verbose=4", str(library)]),
                            (role + "-header", ["otool", "-hv", str(library)])]:
            result = subprocess.run(argv, capture_output=True, text=True)
            records.append(dict(label=label, argv=argv, exitCode=result.returncode,
                                stdout=result.stdout, stderr=result.stderr))
            (output / "commands.json").write_text(json.dumps(records, indent=2) + "\n")
            if result.returncode:
                raise SystemExit("failed " + label + ": " + result.stderr)
        actual = sorted(line.split()[-1].lstrip("_") for line in records[-3]["stdout"].splitlines())
        if actual != sorted(exports):
            raise SystemExit("unexpected exports: " + repr(actual))
    manifest = dict(schemaVersion=1, source=[dict(path=str(p.relative_to(project)),
                      sha256=hashlib.sha256(p.read_bytes()).hexdigest()) for p in [source, header]],
                    files=[dict(name=p.name, bytes=p.stat().st_size,
                         sha256=hashlib.sha256(p.read_bytes()).hexdigest()) for p in output.glob("*.dylib")],
                    exports=exports, completeCVWInterpreter=False, compatibilityOverrideRegistry=False,
                    supportedGenuineType="VZ27 CachingOptions only", systemModified=False,
                    nativeExecution=False, deviceOperations=False)
    (output / "manifest.json").write_text(json.dumps(manifest, indent=2) + "\n")
    print(json.dumps(manifest, indent=2))


if __name__ == "__main__":
    main()
