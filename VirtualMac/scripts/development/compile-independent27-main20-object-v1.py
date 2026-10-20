#!/usr/bin/env python3
"""Compile only Main20 with the actual original App30 Main command; HOST only."""
import argparse,copy,hashlib,json,pathlib,subprocess,sys
sys.dont_write_bytecode=True
R=pathlib.Path(__file__).resolve().parents[3];N=R/'DeviceDiagnostics/2026-10-08-full-macos27-cpu-vmm'
OLD=N/'independent27-actual-app-future-persistent-ssh-v30-attempt1/candidate.json'
SOURCE=N/'independent27-app-url-display-ssh-deferred-source-v20-attempt1/candidate.json'
def pin(p):
 p=pathlib.Path(p).resolve();x=p.read_bytes();return dict(path=str(p),bytes=len(x),sha256=hashlib.sha256(x).hexdigest())
def exact(r):
 p=pathlib.Path(r['path']);assert pin(p)=={k:r[k]for k in('path','bytes','sha256')};return p
def save(p,x):p.write_text(json.dumps(x,indent=2)+'\n')
def main():
 ap=argparse.ArgumentParser();ap.add_argument('--output',type=pathlib.Path,required=True);a=ap.parse_args()
 assert pin(OLD)['sha256']=='284e18663eb180a196798e2a3f18f2978cb52f5289e7498c542d104715525900'
 assert pin(SOURCE)['sha256']=='f48792d215f5e2f9caa2a8a06f4acaec88ae184ec144af74dff8494b670c40e2'
 old=json.loads(OLD.read_bytes());source=json.loads(SOURCE.read_bytes());exact(source['source'])
 assert source['baselineMain19']==old['sourceCandidate'] and source['baselineMain19Source']==old['sourceFiles'][0]
 closure=old['actualIncludeClosure']
 for row in closure:exact(row)
 command=next(c for c in old['commands']if c['label']=='compile-0');assert command['exit']==0
 output=a.output.resolve();assert output.parent==N and not output.exists();output.mkdir(mode=0o700)
 obj=output/'main20.ios.o';argv=copy.deepcopy(command['argv'])
 for oldpath,newpath in ((old['sourceFiles'][0]['path'],source['source']['path']),(old['objects'][0]['path'],str(obj))):
  assert argv.count(oldpath)==1;argv[argv.index(oldpath)]=newpath
 result=subprocess.run(argv,capture_output=True,timeout=90);(output/'compile.stdout').write_bytes(result.stdout);(output/'compile.stderr').write_bytes(result.stderr)
 receipt=output/'compile-command.json';save(receipt,dict(argv=argv,exit=result.returncode,stdout=pin(output/'compile.stdout'),stderr=pin(output/'compile.stderr')))
 if result.returncode:save(output/'failure.json',dict(command=pin(receipt),deviceOperations=0));raise SystemExit(result.returncode)
 candidate=dict(schema='Actual Main20 sole iOS compile from unchanged App30 Main compiler arguments',sourceCandidate=pin(SOURCE),source=source['source'],sourceDiff=source['sourceDiff'],object=pin(obj),actualCompile=pin(receipt),actualCompileExit=0,baselineCompiledAppCandidate=pin(OLD),baselineMain19Object=old['objects'][0],actualIncludeClosure=closure,actualIOSMainCompiled=True,actualAppLinked=False,codeSigned=False,deviceOperations=0)
 save(output/'candidate.json',candidate)
 rows=[pin(p)for p in output.iterdir()if p.is_file()]+[pin(__file__),pin(OLD),pin(OLD.parent/'commands.json'),pin(SOURCE),pin(SOURCE.parent/'freeze.json'),source['source'],source['sourceDiff'],*closure]
 save(output/'freeze.json',dict(files=list({r['path']:r for r in rows}.values()),deviceOperations=0,codeSigningOperations=0));print(json.dumps(dict(candidate=pin(output/'candidate.json'),object=pin(obj),freeze=pin(output/'freeze.json'))))
if __name__=='__main__':main()
