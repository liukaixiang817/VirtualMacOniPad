#!/usr/bin/env python3
"""Build the tested private absolute-path loader, without deploying an App."""
import argparse
import hashlib
import json
from pathlib import Path
import re
import subprocess


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("output", type=Path, help="A new, nonexisting build directory")
    args = parser.parse_args()
    output = args.output.absolute()
    if output.exists() or output.is_symlink():
        parser.error("output must be a new directory")
    source = Path(__file__).resolve().parents[2] / "vz/host/scoped_softlinking.c"
    sources = []
    for path in (source, source.with_suffix(".h")):
        assert not path.is_symlink()
        data = path.read_bytes()
        sources.append(dict(path=str(path), bytes=len(data), sha256=hashlib.sha256(data).hexdigest()))
    output.mkdir(parents=True)

    def run(label, argv):
        completed = subprocess.run(list(map(str, argv)), capture_output=True, timeout=60)
        (output / (label + ".stdout")).write_bytes(completed.stdout)
        (output / (label + ".stderr")).write_bytes(completed.stderr)
        assert completed.returncode == 0, (label, completed.stderr.decode(errors="replace"))
        return completed

    sdk = run("sdk", ["xcrun", "--sdk", "iphoneos", "--show-sdk-path"]).stdout.decode().strip()
    library = output / "VM27ScopedSoftLinking.dylib"
    run("build", ["xcrun", "clang", "-target", "arm64e-apple-ios16.0", "-isysroot", sdk,
                  "-O2", "-Wall", "-Wextra", "-Werror", "-Wl,-no_fixup_chains",
                  "-dynamiclib", source, "-Wl,-install_name,@loader_path/VM27ScopedSoftLinking.dylib",
                  "-Wl,-exported_symbol,__sl_dlopen", "-o", library])
    run("sign", ["codesign", "--force", "--sign", "-", "--timestamp=none",
                 "--generate-entitlement-der", library])
    run("strict", ["codesign", "--verify", "--strict", library])
    signature = run("signature", ["codesign", "-dv", "--verbose=4", library]).stderr
    rights = run("entitlements", ["codesign", "-d", "--entitlements", ":-", library]).stdout
    assert not rights
    exports = run("exports", ["xcrun", "nm", "-gU", library]).stdout.decode()
    assert re.findall(r"\s(_\S+)\s*$", exports, re.M) == ["__sl_dlopen"]
    loads = run("loads", ["xcrun", "otool", "-l", library]).stdout.decode()
    assert "__interpose" not in loads and "__mod_init_func" not in loads
    imports = run("imports", ["xcrun", "dyld_info", "-imports", library]).stdout.decode()
    assert "Hypervisor" not in imports and "Virtualization" not in imports
    run("dyld", ["xcrun", "dyld_info", "-validate_only", library])
    data = library.read_bytes()
    result = dict(scope="Private loader with tested absolute path-list contract", sources=sources,
                  path=str(library), bytes=len(data), sha256=hashlib.sha256(data).hexdigest(),
                  cdhash=re.search(rb"CDHash=([0-9a-f]{40})", signature)[1].decode(),
                  exports=["__sl_dlopen"], entitlements={}, deviceExecuted=False,
                  relativePathCallerPCSemanticsProven=False, originalOSLogBehaviorImplemented=False,
                  originalVZConsumerIntegrated=False, productionAppModified=False, full27Backend=False)
    (output / "candidate.json").write_text(json.dumps(result, indent=2) + "\n")
    print(json.dumps(result, indent=2))


if __name__ == "__main__":
    main()
