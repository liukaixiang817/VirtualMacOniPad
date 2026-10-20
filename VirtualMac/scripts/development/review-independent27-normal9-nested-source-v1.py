#!/usr/bin/env python3
"""Independent actual nested syntax check. Builds only HOST syntax artifacts from historical real facts."""
import ast,hashlib,importlib.util,json,pathlib,shlex,subprocess,sys,types
sys.dont_write_bytecode=True
R=pathlib.Path(__file__).resolve().parents[3];N=R/'DeviceDiagnostics/2026-10-08-full-macos27-cpu-vmm';B=R/'VirtualMac/scripts/development';sys.path.insert(0,str(B))
def pin(p):
 p=pathlib.Path(p).resolve();b=p.read_bytes();return dict(path=str(p),bytes=len(b),sha256=hashlib.sha256(b).hexdigest())
def exact(r):
 assert pin(r['path'])=={k:r[k]for k in ('path','bytes','sha256')},r['path'];return pathlib.Path(r['path'])
def load(p,n):
 sp=importlib.util.spec_from_file_location(n,p);m=importlib.util.module_from_spec(sp);sp.loader.exec_module(m);return m
def words(t):
 lex=shlex.shlex(t,posix=True,punctuation_chars=True);lex.whitespace_split=True;lex.commenters='';return list(lex)
def pure_scripts(src,c):
 builder=load(src,'normal9_independent_pure');fn=next(x for x in ast.parse(src.read_text()).body if isinstance(x,ast.FunctionDef)and x.name=='prepare')
 stop=next(i for i,n in enumerate(fn.body)if isinstance(n,ast.For)and isinstance(n.iter,ast.Call)and isinstance(n.iter.func,ast.Attribute)and isinstance(n.iter.func.value,ast.Name)and n.iter.func.value.id=='scripts'and n.iter.func.attr=='items')
 fn.body=fn.body[:stop]+[ast.Return(value=ast.Name(id='scripts',ctx=ast.Load()))];fn.name='pure_syntax_scripts';module=ast.fix_missing_locations(ast.Module(body=[fn],type_ignores=[]));ns=dict(builder.__dict__)
 ns['secrets']=types.SimpleNamespace(token_hex=lambda count:c['sessionNonce']if count==32 else None);exec(compile(module,str(src)+':no-writes-construction','exec'),ns)
 dummy=N/'normal9-independent-syntax-no-packet';assert not dummy.exists()
 args=types.SimpleNamespace(initializer_candidate=pathlib.Path(c['initializerCandidate']['path']),initializer_launch=pathlib.Path(c['initializerLaunch']['path']),initializer_post=pathlib.Path(c['initializerPost']['path']),guest_readonly=pathlib.Path(c['freshGuestReadonly']['path']),guest_configuration=pathlib.Path(c['freshGuestConfiguration']['path']),prior_normal_preflight_failure=pathlib.Path(c['priorNormalPreflightFailure']['path']),output=dummy,no_before_screenshot_input_free_boot=True,foreground_screenshot_receipt=None,before_screenshot_review_failure=None,historical_foreground_screenshot_receipt=None)
 result=ns['pure_syntax_scripts'](args);assert not dummy.exists();return result
def parse_all(scripts,o):
 def get_assignment(source):
  w=words(source);found=[x.split('=',1)[1]for x in w if x.startswith('OWN_EXACT_CLEANUP_V4=')]
  for i in range(len(w)-2):
   if w[i]in ('/var/jb/bin/sh','/bin/sh')and w[i+1]=='-c'and not w[i+2].startswith('$'):found+=get_assignment(w[i+2])
  return found
 cleanup=get_assignment(scripts['start']);assert len(cleanup)==1
 records=[]
 def parse(label,source,depth=0):
  assert depth<=5 and len(records)<32 and len(source.encode())<262144
  p=o/(str(len(records))+'-'+label+'.sh');p.write_text(source)
  r=subprocess.run(['/bin/sh','-n'],input=source.encode(),capture_output=True,timeout=5);assert r.returncode==0,(label,r.stderr.decode())
  records.append(dict(label=label,depth=depth,source=pin(p),exit=r.returncode));w=words(source)
  for i in range(len(w)-2):
   if w[i]not in ('/var/jb/bin/sh','/bin/sh')or w[i+1]!='-c':continue
   command=w[i+2]
   if command=='$OWN_EXACT_CLEANUP_V4':command=cleanup[0];name='dynamic-owned-cleanup'
   else:assert not command.startswith('$');name='literal-sh-c'
   parse(label+'-'+name,command,depth+1)
 for action,source in scripts.items():parse(action,source)
 assert len(records)==15;return records
def main():
 cp=N/'independent27-normal-nested-syntax-source-v9-attempt2/candidate.json';c=json.loads(cp.read_bytes())
 assert pin(cp)['sha256']=='d0030f54b91b3ae67f559452f59a711825f3c5ce089193352668e7d755b3218f'
 for r in json.loads((cp.parent/'freeze.json').read_bytes())['files']:exact(r)
 old=json.loads(exact(c['baseSourceCandidate']).read_bytes());src=exact(c['builder']);oldsrc=exact(old['builder'])
 assert src.read_text()==oldsrc.read_text().replace("}'''\n\n\nWALL_FUNCTIONS_V4", "}\n'''\n\n\nWALL_FUNCTIONS_V4",1).replace('packet v8\'', 'packet v9\'')
 assert c['runner']==old['runner']
 actualcp=exact(c['actualFailedNormalCandidate']);actual=json.loads(actualcp.read_bytes());failure=json.loads(exact(c['actualFailedStart']).read_bytes());post=json.loads(exact(c['actualIndependentPost']).read_bytes());assert failure['transportExit']==2 and post['transportExit']==0
 scripts=pure_scripts(src,actual)
 o=N/'independent27-normal9-inner-parser-source-independent-peer-v1-attempt1';o.mkdir(mode=0o700);records=parse_all(scripts,o)
 oldfinding=N/'normal-v8-actual-inner-shell-independent-finding-v1-attempt1/review.json';priorSource=N/'independent27-normal-v8-explicit-live-source-independent-peer-v1-attempt1/review.json'
 report=dict(schema='NormalV9 actual nested-shell parser finite source independent peer v1',sourceCandidate=pin(cp),sourceFreeze=pin(cp.parent/'freeze.json'),builder=c['builder'],runner=c['runner'],baseSourceCandidate=c['baseSourceCandidate'],priorFiniteBehaviorPeer=pin(priorSource),actualResidualParserFinding=pin(oldfinding),actualFailedNormalCandidate=c['actualFailedNormalCandidate'],actualFailedStart2=c['actualFailedStart'],actualIndependentPost0=c['actualIndependentPost'],onlyExecutingDeltaLOGFunctionTrailingNewline=True,runner3WholeUnchanged=True,actualIndependentSyntaxTreeNodes=records,allFiveOuterAndActualInnerProgramsParsed=True,actualNestedCloseCleanupAndACKArgumentsSeparatelyParsed=True,independentParserUsesDefaultPunctuationAndDisabledComments=True,syntaxChecksOnlyNoScriptExecution=True,historicalRealFactsUsedOnlyForHOSTSyntaxArtifacts=True,concretePacketGenerated=False,requiresNewActualFreshFactsAndConcretePeerBeforeDispatch=True,old18GateAnd3PipeModelsNotRerun=True,deviceOperations=0,guestBootDisplayInputSSHProven=False,findings=[],passed=True,finiteLocalScopePassed=True)
 rp=o/'review.json';rp.write_text(json.dumps(report,indent=2)+'\n');rows=[pin(__file__),pin(cp),pin(cp.parent/'freeze.json'),c['builder'],c['runner'],c['baseSourceCandidate'],pin(oldsrc),pin(actualcp),c['actualFailedStart'],c['actualFailedStartStderr'],c['actualIndependentPost'],pin(oldfinding),pin(priorSource),pin(rp)]+[x['source']for x in records]
 fp=o/'freeze.json';fp.write_text(json.dumps(dict(files=list({r['path']:r for r in rows}.values()),deviceOperations=0),indent=2)+'\n');print(json.dumps(dict(review=pin(rp),freeze=pin(fp),findings=[])))
if __name__=='__main__':main()
