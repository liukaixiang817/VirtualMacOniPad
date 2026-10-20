#!/usr/bin/env python3
"""HOST-only fixed Normal29 preparation; genuine future receipts are required.

The frozen Source11 producer owns every actual initialization, freshness and
readonly provenance check. This wrapper does not dispatch any device action.
"""
import hashlib,pathlib,subprocess,sys
sys.dont_write_bytecode=True
R=pathlib.Path(__file__).resolve().parents[3]
B=R/'VirtualMac/scripts/development'
N=R/'DeviceDiagnostics/2026-10-08-full-macos27-cpu-vmm'
INIT=N/'independent27-child-error-reason-device-v21-attempt1'
READ=N/'independent27-app39-guest-current-readonly-v1-attempt1'
OUTPUT=N/'independent27-app39-normal-guest-lifecycle-v29-attempt1'
PRODUCER=B/'prepare-independent27-normal-guest-lifecycle-v11.py'
SOURCE_SHA='6fefec059f5978cbb2a55cdde059f6fdb9c37f573474a193b1e39810d1279e1c'

def main():
    if hashlib.sha256(PRODUCER.read_bytes()).hexdigest()!=SOURCE_SHA:
        raise ValueError('immutable actual Source11 producer required')
    actual=(INIT/'candidate.json',INIT/'device-receipts/launch/receipt.json',
        INIT/'device-receipts/post/receipt.json',READ/'receipt.json',READ/'configuration.json')
    if not all(p.is_file() and not p.is_symlink() for p in actual):
        raise ValueError('true same V21 launch/post and fresh App39 readonly facts are not available')
    if OUTPUT.exists():raise ValueError('Normal29 output must be fresh; no replay')
    subprocess.run([sys.executable,str(PRODUCER),'--initializer-candidate',str(actual[0]),
        '--initializer-launch',str(actual[1]),'--initializer-post',str(actual[2]),
        '--guest-readonly',str(actual[3]),'--guest-configuration',str(actual[4]),
        '--prior-normal-preflight-failure',str(N/'independent27-uikit-filter-recovery-normal-guest-lifecycle-v2-attempt1/device-receipts/preflight/receipt.json'),
        '--no-before-screenshot-input-free-boot','--output',str(OUTPUT)],check=True)

if __name__=='__main__':main()
