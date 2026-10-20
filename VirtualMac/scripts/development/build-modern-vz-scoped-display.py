#!/usr/bin/env python3
"""Build the two tested private display exports, without installing an App."""
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
    root = Path(__file__).resolve().parents[2]
    source = root / "vz/host/vm27_scoped_display_routes.m"
    header = source.with_suffix(".h")
    sources = []
    for path, expected in [(source, "99e88029a89e621c6b668683db9ff1d4e5cc2419f019cce69816c2fa506fed12"),
                           (header, "1f42123ef762cccef0609e21f3952d21c279f6afbbb6919ef32788a09847e09e")]:
        assert not path.is_symlink()
        data = path.read_bytes()
        assert hashlib.sha256(data).hexdigest() == expected
        sources.append(dict(path=str(path), bytes=len(data), sha256=expected))
    output.mkdir(parents=True)

    def run(label, argv):
        completed = subprocess.run(list(map(str, argv)), capture_output=True, timeout=60)
        (output / (label + ".stdout")).write_bytes(completed.stdout)
        (output / (label + ".stderr")).write_bytes(completed.stderr)
        assert completed.returncode == 0, (label, completed.stderr.decode(errors="replace"))
        return completed

    sdk = run("sdk", ["xcrun", "--sdk", "iphoneos", "--show-sdk-path"]).stdout.decode().strip()
    library = output / "VM27ScopedDisplayRoutes.dylib"
    run("build", ["xcrun", "clang", "-target", "arm64e-apple-ios16.0", "-isysroot", sdk,
                  "-fobjc-arc", "-Wall", "-Wextra", "-Werror", "-O2",
                  "-framework", "Foundation", "-framework", "CoreFoundation",
                  "-Wl,-no_fixup_chains", "-dynamiclib", source,
                  "-Wl,-install_name,@rpath/VM27ScopedDisplayRoutes.dylib",
                  "-Wl,-exported_symbol,_SLMainDisplayID",
                  "-Wl,-exported_symbol,_SLSCopyDisplayInfoDictionary", "-o", library])
    run("sign", ["codesign", "--force", "--sign", "-", "--timestamp=none",
                 "--generate-entitlement-der", library])
    run("strict", ["codesign", "--verify", "--strict", library])
    signature = run("signature", ["codesign", "-dv", "--verbose=4", library]).stderr
    rights = run("entitlements", ["codesign", "-d", "--entitlements", ":-", library]).stdout
    assert not rights  # The provider receives no executable-only launch entitlements.
    exports = run("exports", ["xcrun", "nm", "-gU", library]).stdout.decode()
    names = re.findall(r"\s(_\S+)\s*$", exports, re.M)
    assert sorted(names) == ["_SLMainDisplayID", "_SLSCopyDisplayInfoDictionary"]
    imports = run("imports", ["xcrun", "dyld_info", "-imports", library]).stdout.decode()
    assert "IOMobileFramebuffer" not in imports and "Hypervisor" not in imports
    loads = run("loads", ["xcrun", "otool", "-l", library]).stdout.decode()
    assert "__interpose" not in loads
    run("dyld", ["xcrun", "dyld_info", "-validate_only", library])
    data = library.read_bytes()
    result = dict(scope="Two limited app-private VZ display routes", sources=sources,
                  path=str(library), bytes=len(data), sha256=hashlib.sha256(data).hexdigest(),
                  cdhash=re.search(rb"CDHash=([0-9a-f]{40})", signature)[1].decode(),
                  exports=sorted(names), entitlements={}, deviceExecuted=False,
                  productionAppModified=False, fullSkyLight=False, full27Backend=False)
    (output / "candidate.json").write_text(json.dumps(result, indent=2) + "\n")
    print(json.dumps(result, indent=2))


if __name__ == "__main__":
    main()
