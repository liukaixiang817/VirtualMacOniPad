#!/usr/bin/env python3
"""Build app-private typed USB-unavailable provider; no device action."""
import argparse,hashlib,json,pathlib,subprocess,re
parser=argparse.ArgumentParser();parser.add_argument('--output',required=True);args=parser.parse_args()
root=pathlib.Path(__file__).resolve().parents[2];out=pathlib.Path(args.output).resolve();out.mkdir(parents=True,exist_ok=False)
source=root/'vz/host/modern_usbh_host_unavailable_compat.m';header=source.with_suffix('.h');logs=[];binaries=[]
for role,sdkname,target in [('ios','iphoneos','arm64e-apple-ios16.1'),('mac','macosx','arm64e-apple-macos27.0')]:
 sdk=subprocess.check_output(['xcrun','--sdk',sdkname,'--show-sdk-path'],text=True).strip();binary=out/('VM27USBUnavailable-'+role+'.dylib')
 commands=[['xcrun','clang','-target',target,'-isysroot',sdk,'-dynamiclib','-fobjc-arc','-fblocks','-O2','-Wall','-Wextra','-Werror','-framework','Foundation','-Wl,-install_name,@rpath/VM27USBUnavailable.dylib',str(source),'-o',str(binary)],['codesign','--force','--sign','-','--timestamp=none',str(binary)],['codesign','--verify','--strict',str(binary)],['codesign','-d','--verbose=4',str(binary)],['otool','-L',str(binary)],['nm','-gU',str(binary)]]
 for argv in commands:
  p=subprocess.run(argv,capture_output=True,text=True,timeout=60);logs.append({'argv':argv,'exit':p.returncode,'stdout':p.stdout,'stderr':p.stderr});(out/'commands.json').write_text(json.dumps(logs,indent=2)+'\n')
  if p.returncode:raise SystemExit(p.stderr)
 cd=re.search(r'CDHash=(\w+)',logs[-3]['stderr']).group(1)
 binaries.append({'role':role,'path':str(binary),'bytes':binary.stat().st_size,'sha256':hashlib.sha256(binary.read_bytes()).hexdigest(),'cdhash':cd})
manifest={'source':str(source),'sourceSHA256':hashlib.sha256(source.read_bytes()).hexdigest(),'header':str(header),'headerSHA256':hashlib.sha256(header.read_bytes()).hexdigest(),'binaries':binaries,'policy':'USB hardware unavailable; exact descriptor parsing independent of hardware','processRights':{},'deviceExecuted':False,'IOKitHardwareCalls':False,'routesStrongDependencies':False}
(out/'manifest.json').write_text(json.dumps(manifest,indent=2)+'\n');print(json.dumps(manifest,indent=2))
