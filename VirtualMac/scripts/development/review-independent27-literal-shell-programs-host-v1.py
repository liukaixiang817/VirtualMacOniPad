#!/usr/bin/env python3
"""HOST-only exact binding and literal shell syntax report by the actual reviewing agent.

No shell program is executed. The shell receives only -n; device execution and
Root's product/scope review remain separate actions.
"""
import argparse,hashlib,json,pathlib,shlex,subprocess,sys
sys.dont_write_bytecode=True
R=pathlib.Path(__file__).resolve().parents[3]
N=R/'DeviceDiagnostics/2026-10-08-full-macos27-cpu-vmm'
def need(v,why):
 if not v:raise ValueError(why)
def pin(p):
 p=pathlib.Path(p).resolve();d=p.read_bytes();return dict(path=str(p),bytes=len(d),sha256=hashlib.sha256(d).hexdigest())
def exact(row):
 need(pin(row['path'])=={k:row[k]for k in ('path','bytes','sha256')},'exact actual input '+row['path']);return pathlib.Path(row['path'])
def main():
 ap=argparse.ArgumentParser();ap.add_argument('--candidate',type=pathlib.Path,required=True);ap.add_argument('--kind',choices=('readonly','normal'),required=True);ap.add_argument('--report',type=pathlib.Path,required=True);a=ap.parse_args()
 cp=a.candidate.resolve();need(cp.parent.parent==N,'concrete packet in diagnostics');v=json.loads(cp.read_bytes());freeze=cp.parent/'freeze.json';rows=json.loads(freeze.read_bytes())['files'];need(any(row==pin(cp)for row in rows),'actual candidate frozen')
 for row in rows:exact(row)
 programs=[];findings=[]
 def collect(label,program):
  data=program.encode();done=subprocess.run(['/bin/sh','-n'],input=data,capture_output=True,timeout=10)
  programs.append(dict(label=label,bytes=len(data),sha256=hashlib.sha256(data).hexdigest(),exit=done.returncode))
  if done.returncode:findings.append(dict(label=label,error=done.stderr.decode(errors='replace')))
  lexer=shlex.shlex(program,posix=True,punctuation_chars=True);lexer.whitespace_split=True;lexer.commenters='#';tokens=list(lexer)
  for i,token in enumerate(tokens):
   if token in ('sh','/bin/sh','/var/jb/bin/sh') and i+2<len(tokens) and tokens[i+1]=='-c':
    child=tokens[i+2]
    if child.startswith('$') and '\n' not in child:continue
    collect(label+'-sh-c',child)
   if token.startswith('OWN_EXACT_CLEANUP_V4='):
    child=token.split('=',1)[1]
    need(child and '\n'in child,'literal actual owned-cleanup assignment')
    collect(label+'-cleanup',child)
 if a.kind=='readonly':collect('read-root',exact(v['script']).read_text())
 else:
  need(list(v['actions'])==['preflight','start','observe','stop','post'],'actual normal lifecycle actions')
  for label,row in v['actions'].items():collect(label,exact(row).read_text())
 expected=2 if a.kind=='readonly'else 13
 if len(programs)!=expected:findings.append(dict(error='unexpected actual literal program count',expected=expected,actual=len(programs)))
 report=dict(schema='Actual agent HOST concrete bindings and literal shell syntax review',reviewer='/root/runtime_diagnostic_pack',reviewKind='HOST exact frozen inputs and literal syntax only',reviewTool=pin(__file__),findings=findings,actualPrograms=programs,actualAllSyntaxZero=not findings,rootReviewClaimed=False,rootActualSourceDeltaReviewed=False,deviceOperations=0,passed=not findings)
 report['readonlyPacketCandidate'if a.kind=='readonly'else'controllerPacketCandidate']=pin(cp)
 report['initializerCandidate']=v['initializerCandidate']
 if a.kind=='readonly':report['actualInitializerLogGeneration']=v['actualInitializerLogGeneration']
 else:
  report['actualInitializerPost']=v['initializerPost'];report['actualGuestReadonly']=v['freshGuestReadonly'];report['actualGuestConfiguration']=v['freshGuestConfiguration'];report['inheritedSource12Runner3WholeUnchanged']=v['controller']['sha256']=='206e8798f14b2532ae44ed26167cbbb5b3906ac8da2a1b3bb7ca3a223198c2b8'and v['builder']['sha256']=='0641f970de7a550cde290601a79bb766a15dbc42c1fdf733c6ffc31e313efdd9'
 target=a.report.resolve();need(target.parent==cp.parent and not target.exists(),'fresh report belongs to this packet')
 with target.open('x')as f:f.write(json.dumps(report,indent=2,ensure_ascii=False)+'\n')
 print(json.dumps(dict(report=pin(target),programs=len(programs),findings=findings,deviceOperations=0)));need(not findings,'actual shell syntax report has findings')
if __name__=='__main__':main()
