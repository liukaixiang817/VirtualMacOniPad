#!/usr/bin/env python3
"""Finite exact fatal diagnostic regex delta; no device, no repeated gate/pipe models."""
import ast,hashlib,importlib.util,json,pathlib,subprocess,sys
sys.dont_write_bytecode=True
R=pathlib.Path(__file__).resolve().parents[3];N=R/'DeviceDiagnostics/2026-10-08-full-macos27-cpu-vmm';B=R/'VirtualMac/scripts/development';sys.path.insert(0,str(B))
def pin(p):
 p=pathlib.Path(p).resolve();b=p.read_bytes();return dict(path=str(p),bytes=len(b),sha256=hashlib.sha256(b).hexdigest())
def exact(r):
 assert pin(r['path'])=={k:r[k]for k in ('path','bytes','sha256')};return pathlib.Path(r['path'])
def load(p,n):
 sp=importlib.util.spec_from_file_location(n,p);m=importlib.util.module_from_spec(sp);sp.loader.exec_module(m);return m
def funcs(t):return {n.name:ast.dump(n,include_attributes=False)for n in ast.parse(t).body if isinstance(n,ast.FunctionDef)}
def main():
 cp=N/'independent27-normal-metal-ctor-fatal-source-v10-attempt1/candidate.json';c=json.loads(cp.read_bytes());assert pin(cp)['sha256']=='5cdc09fb12213570432bdf63d44016069c6eda9154604f598276f05cc3623185'
 for r in json.loads((cp.parent/'freeze.json').read_bytes())['files']:exact(r)
 src=exact(c['source']);oldsrc=exact(c['oldFrozenSource']);text=src.read_text();old=oldsrc.read_text();nf,of=funcs(text),funcs(old)
 assert all(nf[k]==of[k]for k in nf if k!='prepare')
 oldline="           r'^\\[VirtualMac\\] (Configuration failed:|Validation failed:|Virtual Mac start failed:|Virtual Mac stopped:)')"
 newline="           r'^\\[VirtualMac\\] (Configuration failed:|Validation failed:|Virtual Mac start failed:|Virtual Mac stopped:)|'\n           r'^\\[Independent27DisplayCtorV3\\] failed=(super-init|native-default-device|native-command-queue) nil=1([[:space:]]|$)')"
 assert text==old.replace(oldline,newline,1).replace("packet v9',", "packet v10',")
 m=load(src,'normal10_actual_regex_source');om=load(oldsrc,'normal9_accepted_source');assert m.LOG_FUNCTIONS==om.LOG_FUNCTIONS and m.WALL_FUNCTIONS_V4==om.WALL_FUNCTIONS_V4 and m.LOG_FUNCTIONS.endswith('}\n')
 assert c['runnerV3']['sha256']=='206e8798f14b2532ae44ed26167cbbb5b3906ac8da2a1b3bb7ca3a223198c2b8';exact(c['runnerV3'])
 checks=c['actualHostGrepChecks'];assert len(checks)==11 and all(x['expectedGrepExit']==x['actualGrepExit']for x in checks)
 assert {x['label']:x['actualGrepExit']for x in checks if x['actualGrepExit']==0}=={'actual-super-return-nil':0,'actual-native-default-return-nil':0,'actual-native-queue-return-nil':0,'old-vm-stop-preserved':0}
 display=exact(c['actualConstructorSource']).read_text();assert 'failed=super-init nil=1 pid=%d'in display and '!_device?"native-default-device":"native-command-queue"'in display
 actualRegexShell='set -eu\n'+m.log_functions()+'\ntrap finish_normal EXIT\ntrap - EXIT\n'
 assert subprocess.run(['/bin/sh','-n'],input=actualRegexShell.encode(),capture_output=True).returncode==0
 priorp=N/'independent27-normal9-inner-parser-source-independent-peer-v1-attempt1/review.json';prior=json.loads(priorp.read_bytes());assert prior['findings']==[]and prior['builder']==c['oldFrozenSource']and prior['runner']==c['runnerV3']
 o=N/'independent27-normal10-ctor-fatal-source-independent-peer-v1-attempt1';o.mkdir(mode=0o700);report=dict(schema='Normal10 exact fatal constructor regex finite source independent peer',sourceCandidate=pin(cp),sourceFreeze=pin(cp.parent/'freeze.json'),builder=c['source'],runner=c['runnerV3'],priorNestedParserPeer=pin(priorp),actualDisplaySource=c['actualConstructorSource'],onlyExecutableDeltaExactThreeCtorNilFatalPatterns=True,onlyMetadataDeltaSchema10=True,allFunctionsWholeUnchangedExceptPrepareSchema=True,LOGAndWallFunctionsWholeUnchangedWithRequiredTrailingNewline=True,runner3WholeUnchanged=True,actualGrepResults11InheritedVerified=True,validStagesFramesNil0Nil10OtherAPIAndEmbeddedTextNotFatal=True,actualCtorFailureStringsMatchRegex=True,actualChangedRegexQuotedLogFunctionsAndTrapSyntaxPassed=True,original90Host45LateExplicitOfferACKOwnerCleanupAndNestedParserContractInherited=True,old18GateAndThreePipeAndFiveLiveModelsNotRerun=True,deviceOperations=0,concretePacketGenerated=False,requiresFutureActualFreshFactsAndConcretePacketPeer=True,guestBootDisplayInputSSHProven=False,findings=[],passed=True,finiteLocalScopePassed=True)
 rp=o/'review.json';rp.write_text(json.dumps(report,indent=2)+'\n');rows=[pin(__file__),pin(cp),pin(cp.parent/'freeze.json'),c['source'],c['oldFrozenSource'],c['runnerV3'],c['actualConstructorSource'],pin(priorp),pin(rp)]
 fp=o/'freeze.json';fp.write_text(json.dumps(dict(files=rows,deviceOperations=0),indent=2)+'\n');print(json.dumps(dict(review=pin(rp),freeze=pin(fp),findings=[])))
if __name__=='__main__':main()
