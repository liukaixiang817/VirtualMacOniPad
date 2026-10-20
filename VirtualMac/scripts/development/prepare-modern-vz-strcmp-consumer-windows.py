#!/usr/bin/env python3
"""Bounded offline instruction windows of true original VZ strcmp callers."""
import argparse
import hashlib
import json
import pathlib
import struct
import sys
import capstone

sys.dont_write_bytecode=True
from vz_import_addend_image import segments
R=pathlib.Path(__file__).resolve().parents[3]
N=R/'DeviceDiagnostics/2026-10-08-full-macos27-cpu-vmm'
RAW=R/'DeviceDiagnostics/2026-10-02-virtualmac-2.0/Tahoe3/integrity-audit/modern-compiler/virtualization27-stack-audit-v1/raw/Virtualization'


def pin(p):
    b=p.read_bytes();return dict(path=str(p.resolve()),bytes=len(b),sha256=hashlib.sha256(b).hexdigest())


def main():
    ap=argparse.ArgumentParser(description=__doc__);ap.add_argument('--contract',required=True,type=pathlib.Path);ap.add_argument('--expected-contract-sha256',required=True);ap.add_argument('--output',required=True,type=pathlib.Path);args=ap.parse_args()
    assert pin(args.contract)['sha256']==args.expected_contract_sha256
    contract=json.loads(args.contract.read_text());raw=RAW.read_bytes();assert pin(RAW)['sha256']=='ec4bbc11af44a0c04a56269397274c90265a51568fe50e4e94123dd5eaa82f04'
    text=next(g for g in segments(raw) if g['name']=='__TEXT')
    code=next(q for q in text['sections'] if q['name']=='__text');md=capstone.Cs(capstone.CS_ARCH_ARM64,capstone.CS_MODE_ARM)
    rows=[]
    for proof in contract['strcmpResolverContract']['originalBranches']:
        assert proof['kind']=='originalVZExternalBranchInstruction';pc=proof['originalInstructionPC']
        assert code['address']+32<=pc and pc+44<=code['address']+code['size']
        start=pc-32;off=code['fileoff']+start-code['address'];window=raw[off:off+76]
        instructions=[dict(pc=i.address,word=hex(struct.unpack('<I',i.bytes)[0]),mnemonic=i.mnemonic,operands=i.op_str) for i in md.disasm(window,start)]
        at=next(i for i in instructions if i['pc']==pc);assert at['mnemonic']=='bl' and at['word']==proof['rawInstructionWord']
        assert int(at['operands'].lstrip('#'),16)==proof['branchTarget']
        following=[i for i in instructions if i['pc']>pc];first=following[0]
        direct=(first['mnemonic'] in ('cbz','cbnz') and first['operands'].startswith('w0,')) or (first['mnemonic']=='cmp' and first['operands']=='w0, #0')
        rows.append(dict(originalPC=pc,branchWord=at['word'],branchTarget=proof['branchTarget'],originalTrueText=True,firstResultUseIsZeroTest=direct,instructions=instructions))
    result=dict(originalCallCount=len(rows),firstResultUseZeroTestCount=sum(r['firstResultUseIsZeroTest'] for r in rows),boundedWindowsOnly=True,fullControlFlowOrLifetimesProven=False,publicTypedSignature='int(const char*,const char*)',returnIsForwardedWithoutNormalization=True,callers=rows,originalVZConsumerExecuted=False,actualVZCalls=0,full27=False,deviceOperations=0,systemModified=False)
    out=args.output.resolve();assert out.is_relative_to(N) and not out.exists();out.mkdir(parents=True)
    (out/'windows.json').write_text(json.dumps(result,indent=2)+'\n');(out/'inputs.json').write_text(json.dumps([pin(p) for p in (args.contract,RAW,pathlib.Path(__file__).resolve(),pathlib.Path(__file__).with_name('vz_import_addend_image.py'))],indent=2)+'\n')
    print(json.dumps({k:v for k,v in result.items() if k!='callers'}))


if __name__=='__main__':main()
