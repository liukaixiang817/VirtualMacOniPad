#!/usr/bin/env python3
"""Build and run the real host dispatch scheduler; compile inert iOS objects."""
import argparse
import hashlib
import json
from pathlib import Path
import subprocess

def pin(path):
    p=Path(path).resolve();data=p.read_bytes()
    return {'path':str(p),'bytes':len(data),'sha256':hashlib.sha256(data).hexdigest()}

def run(out,name,args):
    r=subprocess.run(args,stdout=subprocess.PIPE,stderr=subprocess.PIPE,timeout=45)
    (out/(name+'.stdout')).write_bytes(r.stdout)
    (out/(name+'.stderr')).write_bytes(r.stderr)
    receipt={'argv':args,'returncode':r.returncode,'stdout':pin(out/(name+'.stdout')),
             'stderr':pin(out/(name+'.stderr'))}
    (out/(name+'.json')).write_text(json.dumps(receipt,indent=2)+'\n')
    if r.returncode:raise RuntimeError(f'{name}: {r.stderr.decode(errors="replace")}')
    return receipt,r.stdout

def main():
    p=argparse.ArgumentParser();p.add_argument('--out',type=Path,required=True);a=p.parse_args()
    out=a.out.resolve();out.mkdir(parents=True,exist_ok=False)
    source=Path(__file__).resolve().parent
    clang=subprocess.check_output(['xcrun','--find','clang'],text=True).strip()
    mac=subprocess.check_output(['xcrun','--sdk','macosx','--show-sdk-path'],text=True).strip()
    ios=subprocess.check_output(['xcrun','--sdk','iphoneos','--show-sdk-path'],text=True).strip()
    c=source/'modern_gic_deadline_scheduler_v1.c';test=source/'test-modern-gic-deadline-scheduler-v1.c'
    commands=[];models={};closures=set()
    common=['-std=c11','-Wall','-Wextra','-Werror','-O1','-g']
    for mode,extra in [('normal',[]),('san',['-fsanitize=address,undefined','-fno-omit-frame-pointer'])]:
        binary=out/('scheduler-'+mode)
        record,_=run(out,'build-'+mode,[clang,*common,'-isysroot',mac,*extra,str(c),str(test),'-o',str(binary)])
        commands.append(record)
        record,stdout=run(out,'run-'+mode,[str(binary)]);commands.append(record);models[mode]=json.loads(stdout)
    for arch in ['arm64','arm64e']:
        args=[clang,'-target',arch+'-apple-ios16.0','-isysroot',ios,*common,'-fvisibility=hidden']
        record,_=run(out,'ios-'+arch,[*args,'-c',str(c),'-o',str(out/(arch+'.o'))]);commands.append(record)
        record,stdout=run(out,'closure-'+arch,[*args,'-MM',str(c)]);commands.append(record)
        for name in stdout.decode().replace('\\\n',' ').split(':',1)[1].split():
            closures.add(str(Path(name).resolve()))
    if models['normal']!=models['san'] or not models['normal']['realDispatchTimersPassed']:
        raise RuntimeError('dispatch fixture mismatch')
    report={'schema':'independent27 actual host dispatch scheduler local v1','commands':commands,'models':models,
      'sourcePins':[pin(p) for p in sorted(closures|{str(test),str(Path(__file__).resolve())})],
      'realHostDispatchExecuted':True,'deviceExecuted':False,'native10Executed':False,
      'fullIndependent27GuestBoot':False}
    with (out/'candidate.json').open('x') as f:json.dump(report,f,indent=2);f.write('\n')
    print(json.dumps({'candidate':pin(out/'candidate.json'),'models':models},indent=2))

if __name__=='__main__':main()
