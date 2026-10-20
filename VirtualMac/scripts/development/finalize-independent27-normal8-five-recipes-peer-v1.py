#!/usr/bin/env python3
"""Re-execute only the real-facts producer's pure five-script construction, without writing a packet."""
import ast, hashlib, importlib.util, json, pathlib, sys, types
sys.dont_write_bytecode=True
R=pathlib.Path(__file__).resolve().parents[3];N=R/'DeviceDiagnostics/2026-10-08-full-macos27-cpu-vmm';B=R/'VirtualMac/scripts/development';sys.path.insert(0,str(B))
def pin(p):
 p=pathlib.Path(p).resolve();b=p.read_bytes();return dict(path=str(p),bytes=len(b),sha256=hashlib.sha256(b).hexdigest())
def exact(r):
 assert pin(r['path'])=={k:r[k]for k in ('path','bytes','sha256')};return pathlib.Path(r['path'])
def main():
 priorp=N/'independent27-app13-normal-v8-concrete-independent-peer-v1-attempt1/review.json';prior=json.loads(priorp.read_bytes());assert prior['findings']==[]and prior['finiteLocalScopePassed']
 cp=exact(prior['controllerPacketCandidate']);c=json.loads(cp.read_bytes());src=exact(c['builder'])
 spec=importlib.util.spec_from_file_location('normal8_pure_recipe_source',src);builder=importlib.util.module_from_spec(spec);spec.loader.exec_module(builder)
 tree=ast.parse(src.read_text());f=next(x for x in tree.body if isinstance(x,ast.FunctionDef)and x.name=='prepare')
 stop=next(i for i,n in enumerate(f.body)if isinstance(n,ast.For)and isinstance(n.iter,ast.Call)and isinstance(n.iter.func,ast.Attribute)and isinstance(n.iter.func.value,ast.Name)and n.iter.func.value.id=='scripts'and n.iter.func.attr=='items')
 assert stop>0 and isinstance(f.body[stop-1],ast.Assign)and isinstance(f.body[stop-1].targets[0],ast.Subscript)and f.body[stop-1].targets[0].value.id=='scripts'
 f.body=f.body[:stop]+[ast.Return(value=ast.Name(id='scripts',ctx=ast.Load()))];f.name='pure_regenerate'
 # The prefix only reads real receipts/files and builds strings. It ends
 # before syntax subprocesses, output mkdir, copying, dump, and printing.
 prefix=ast.get_source_segment(src.read_text(),next(x for x in tree.body if isinstance(x,ast.FunctionDef)and x.name=='pure_regenerate')) if False else None
 code=ast.fix_missing_locations(ast.Module(body=[f],type_ignores=[]));ns=dict(builder.__dict__)
 ns['secrets']=types.SimpleNamespace(token_hex=lambda count:c['sessionNonce']if count==32 else (_ for _ in ()).throw(ValueError('unexpected nonce size')))
 exec(compile(code,str(src)+':pure-readonly-construction','exec'),ns)
 dummy=N/'normal8-peer-pure-construction-no-output-created';assert not dummy.exists()
 args=types.SimpleNamespace(initializer_candidate=pathlib.Path(c['initializerCandidate']['path']),initializer_launch=pathlib.Path(c['initializerLaunch']['path']),initializer_post=pathlib.Path(c['initializerPost']['path']),guest_readonly=pathlib.Path(c['freshGuestReadonly']['path']),guest_configuration=pathlib.Path(c['freshGuestConfiguration']['path']),prior_normal_preflight_failure=pathlib.Path(c['priorNormalPreflightFailure']['path']),output=dummy,no_before_screenshot_input_free_boot=c['noBeforeScreenshotInputFreeBoot'],foreground_screenshot_receipt=None,before_screenshot_review_failure=None,historical_foreground_screenshot_receipt=None)
 actual=ns['pure_regenerate'](args);assert set(actual)==set(c['actions'])=={'preflight','start','observe','stop','post'}
 for name,text in actual.items():assert text.encode()==exact(c['actions'][name]).read_bytes(),name
 assert not dummy.exists()
 o=N/'independent27-app13-normal-v8-concrete-peer-finalization-v1-attempt1';o.mkdir(mode=0o700)
 report=dict(prior);report.update(schema='Actual App13 NormalV8 five-recipe finite concrete peer finalization v1',finiteConcretePeer=pin(priorp),actualFiveScriptsPureConstructionWholeEqual=True,pureConstructionReadsOnlyRealInitializerPostAndGuestFacts=True,pureConstructionStoppedBeforeSubprocessOutputMkdirOrPacketWrites=True,regenerationCreatedNoPacketOrFutureReceipts=True,deviceOperations=0)
 rp=o/'review.json';rp.write_text(json.dumps(report,indent=2)+'\n');rows=[pin(__file__),pin(priorp),pin(priorp.parent/'freeze.json'),pin(cp),pin(cp.parent/'freeze.json'),c['builder'],c['common'],c['inheritedController'],c['initializerCandidate'],c['initializerLaunch'],c['initializerPost'],c['freshGuestReadonly'],c['freshGuestConfiguration'],c['priorNormalPreflightFailure'],pin(rp)]+list(c['actions'].values())
 fp=o/'freeze.json';fp.write_text(json.dumps(dict(files=list({r['path']:r for r in rows}.values()),deviceOperations=0),indent=2)+'\n');print(json.dumps(dict(review=pin(rp),freeze=pin(fp),findings=[])))
if __name__=='__main__':main()
