#!/usr/bin/env python3
"""Compile only Main21's genuine VZ27 raw-FD attachment selection; never sign/run."""
import argparse, copy, difflib, hashlib, json, pathlib, plistlib, struct, subprocess, sys
sys.dont_write_bytecode = True
R = pathlib.Path(__file__).resolve().parents[3]
N = R / 'DeviceDiagnostics/2026-10-08-full-macos27-cpu-vmm'
OLD = N / 'independent27-app-url-display-ssh-deferred-source-v20-attempt2/candidate.json'
APP = N / 'independent27-actual-app-run-tail-trace-anchor-v54-attempt1/candidate.json'
RUNTIME = N / 'independent27-signed-runtime-public-run-sparse-clock-product-v43-attempt1/candidate.json'
CHILD_BASIS = N / 'original-simple-virtio-bdif-host-readonly-v2-attempt1/basis.json'

def pin(p):
    p = pathlib.Path(p).resolve(); b = p.read_bytes()
    return dict(path=str(p), bytes=len(b), sha256=hashlib.sha256(b).hexdigest())

def exact(row):
    p = pathlib.Path(row['path']); assert pin(p) == {k:row[k] for k in ('path','bytes','sha256')}
    return p

def save(p, v): p.write_text(json.dumps(v, indent=2) + '\n')

HELPER = '''/* Select the original VZ27 raw-file backend for this owned first-boot disk.
 * VZ27's private descriptor backendType 1 serializes to child backend 3;
 * that preserves RawDiskImageFormat and its real FD/thread-pool I/O path.
 * Caching and full synchronization keep their original default values. */
static id VZIndependent27RawDiskAttachmentV21(NSURL *url, NSError **error) {
    Class descriptorClass = (Class)CLS("_VZDiskImageDescriptor");
    Class diskClass = (Class)CLS("_VZDiskImage");
    Class attachmentClass = (Class)CLS("VZDiskImageStorageDeviceAttachment");
    NSString *expectedImage = [VZRuntimeRoot()
        stringByAppendingPathComponent:@"parent-flat/VZ27.dylib"];
    Class requiredClasses[] = { descriptorClass, diskClass, attachmentClass };
    for (unsigned i = 0; i < 3; ++i) {
        const char *actualImage = requiredClasses[i]
            ? class_getImageName(requiredClasses[i]) : NULL;
        if (!actualImage || ![expectedImage isEqualToString:
                [NSString stringWithUTF8String:actualImage]]) {
            if (error) *error = [NSError errorWithDomain:@"VirtualMac.Independent27Storage"
                code:ENODEV userInfo:@{NSLocalizedDescriptionKey:
                    @"The original macOS27 raw disk attachment classes are unavailable."}];
            return nil;
        }
    }
    if (!url.isFileURL || ![url.lastPathComponent isEqualToString:@"Disk.img"] ||
        !class_getInstanceMethod(descriptorClass, S("initWithURL:")) ||
        !class_getInstanceMethod(descriptorClass, S("setReadOnly:")) ||
        !class_getInstanceMethod(descriptorClass, S("setBackendType:")) ||
        !class_getInstanceMethod(descriptorClass, S("backendType")) ||
        !class_getInstanceMethod(descriptorClass, S("cachingMode")) ||
        !class_getInstanceMethod(descriptorClass, S("synchronizationMode")) ||
        !class_getInstanceMethod(diskClass, S("initWithDescriptor:error:")) ||
        !class_getClassMethod(attachmentClass,
            S("_diskImageStorageDeviceAttachmentWithDiskImage:"))) {
        if (error) *error = [NSError errorWithDomain:@"VirtualMac.Independent27Storage"
            code:ENOTSUP userInfo:@{NSLocalizedDescriptionKey:
                @"The original macOS27 raw disk attachment configuration is unavailable."}];
        return nil;
    }
    id descriptor = nil, disk = nil, attachment = nil;
    NSError *actualError = nil;
    @try {
        descriptor = ((id(*)(id, SEL, id))objc_msgSend)(
            m0((id)descriptorClass, "alloc"), S("initWithURL:"), url);
        if (descriptor) {
            ((void(*)(id, SEL, BOOL))objc_msgSend)(descriptor, S("setReadOnly:"), NO);
            ((void(*)(id, SEL, NSUInteger))objc_msgSend)(
                descriptor, S("setBackendType:"), 1);
            NSUInteger backend = ((NSUInteger(*)(id, SEL))objc_msgSend)(
                descriptor, S("backendType"));
            NSUInteger cache = ((NSUInteger(*)(id, SEL))objc_msgSend)(
                descriptor, S("cachingMode"));
            NSUInteger synchronization = ((NSUInteger(*)(id, SEL))objc_msgSend)(
                descriptor, S("synchronizationMode"));
            if (backend == 1 && cache == 0 && synchronization == 1) {
                disk = ((id(*)(id, SEL, id, NSError **))objc_msgSend)(
                    m0((id)diskClass, "alloc"), S("initWithDescriptor:error:"),
                    descriptor, &actualError);
                if (disk) {
                    /* The class factory returns autoreleased; match the old
                     * alloc/init attachment's +1 while it strongly owns disk. */
                    attachment = [((id(*)(id, SEL, id))objc_msgSend)(
                        (id)attachmentClass,
                        S("_diskImageStorageDeviceAttachmentWithDiskImage:"), disk) retain];
                    if (attachment)
                        printf("[Independent27StorageV21] original raw Disk.img attachment "
                               "backendType=1 childBackend=3 cache=0 synchronization=1 "
                               "rootRole=1 realIO=1\\n");
                }
            }
        }
    } @catch (NSException *exception) {
        actualError = [NSError errorWithDomain:@"VirtualMac.Independent27Storage"
            code:EIO userInfo:@{NSLocalizedDescriptionKey:
                exception.reason ?: @"The original macOS27 raw disk configuration raised an exception."}];
    } @finally {
        [disk release];
        [descriptor release];
    }
    if (!attachment && error)
        *error = actualError ?: [NSError errorWithDomain:@"VirtualMac.Independent27Storage"
            code:EIO userInfo:@{NSLocalizedDescriptionKey:
                @"The original macOS27 raw disk attachment could not be created."}];
    return attachment;
}

'''

def main():
    ap=argparse.ArgumentParser(); ap.add_argument('--output', required=True, type=pathlib.Path); args=ap.parse_args()
    assert pin(OLD)['sha256']=='176fbe12cbed9466e9da0a85b7e3935de4df0338b2e571f0f40366b1da0a9752'
    old=json.loads(OLD.read_bytes()); app=json.loads(APP.read_bytes()); runtime=json.loads(RUNTIME.read_bytes())
    original=exact(old['source']); assert pin(original)['sha256']=='ff43e200ffabd33ca944957a47385472cd97ea53dad9b76216e657bfe9729ad2'
    assert app['sourceFiles'][0]==old['source'] and app['sourceCandidate']==pin(OLD)
    assert app['actualRuntimeCandidate']==pin(RUNTIME) and len(app['objects'])==35
    for row in [*app['sourceFiles'], *app['objects'], *app['actualIncludeClosure'], *app.get('externalPrecompiledObjects',[])]: exact(row)
    child_basis=exact(pin(CHILD_BASIS)); assert pin(child_basis)['sha256']=='5ac8429855353fd117676016846f63e3f4b3ee4d4f744a91131f5059c154e14e'
    manifest=exact(runtime['manifest']); manifest_data=plistlib.loads(manifest.read_bytes())
    row=next(x for x in manifest_data['files'] if x['path']=='parent-flat/VZ27.dylib')
    parent=pathlib.Path(runtime['runtimeRoot'])/row['path']; parent_pin=pin(parent)
    assert parent_pin['sha256']==row['sha256']=='c043b0dd61d254534fbdf0ab6dbb706b0b0b50926560dcc80bdec3bc028714a0'
    assert struct.unpack_from('<5I',parent.read_bytes(),0x27ff94)==(0,3,1,1,2)
    before=original.read_text(); target='static id makeConfiguration(NSString *bundlePath, NSDictionary *options,\n'
    assert before.count(target)==1
    text=before.replace(target,HELPER+target,1)
    old_block='''    id attachment = ((id(*)(id, SEL, id, BOOL, NSError **))objc_msgSend)(
        m0(CLS("VZDiskImageStorageDeviceAttachment"), "alloc"),
        S("initWithURL:readOnly:error:"),
        fileURL([bundlePath stringByAppendingPathComponent:@"Disk.img"]),
        NO, error);'''
    new_block='''    id attachment = nil;
    if (VZIndependent27SourceRouteSelected()) {
        attachment = VZIndependent27RawDiskAttachmentV21(
            fileURL([bundlePath stringByAppendingPathComponent:@"Disk.img"]), error);
    } else {
        attachment = ((id(*)(id, SEL, id, BOOL, NSError **))objc_msgSend)(
            m0(CLS("VZDiskImageStorageDeviceAttachment"), "alloc"),
            S("initWithURL:readOnly:error:"),
            fileURL([bundlePath stringByAppendingPathComponent:@"Disk.img"]),
            NO, error);
    }'''
    assert text.count(old_block)==1; text=text.replace(old_block,new_block,1)
    output=args.output.resolve(); assert output.parent==N and not output.exists(); output.mkdir(mode=0o700)
    source=output/'VirtualMacApp.independent27.raw-fd-attachment-source-v21.m'; source.write_text(text)
    diff=output/'main20-to-main21.diff'; diff.write_text(''.join(difflib.unified_diff(before.splitlines(True),text.splitlines(True),fromfile=str(original),tofile=str(source))))
    windows=[]
    for name,a,b in [('descriptor-backend-setter',0x1a3014,0x1a3074),('disk-init-descriptor-backend',0x1a1748,0x1a17a8),('disk-backend-store',0x1a1250,0x1a1264),('attachment-backend-wire-map',0x1a68f0,0x1a6920),('attachment-strong-disk-autoreturn',0x1a6aa4,0x1a6b68)]:
        argv=['xcrun','llvm-objdump','-d','--no-show-raw-insn','--start-address='+hex(0x100000000+a),'--stop-address='+hex(0x100000000+b),str(parent)]
        q=subprocess.run(argv,capture_output=True,timeout=20); assert q.returncode==0
        p=output/(name+'.asm'); p.write_bytes(q.stdout); windows.append(pin(p))
    basis=output/'parent-raw-fd-configuration-basis.json'; save(basis,dict(actualRuntime=pin(RUNTIME),actualManifest=pin(manifest),actualParent=parent_pin,parentUUID=row['uuid'],originalChildBasis=pin(CHILD_BASIS),actualBoundedDisassembly=windows,parentBackendToChildWire=[0,3,1,1,2],selectedParentBackend=1,selectedChildBackend=3,descriptorSetterRVA='1a3014',diskPreservesBackendRVA='1a125c',attachmentStoresDiskStrongAt='1a6b28:objc_storeStrong',factoryReturnsAutoreleasedAt='1a6b64:objc_autoreleaseReturnValue',parentGetterWireMappingRVA='1a6904..1a6918',cacheAndSynchronizationDefaults=[0,1],ownership='factory +0 retained once to match original alloc/init +1; descriptor and disk temporaries released in finally',noRuntimeOrChildPatches=True))
    prior=app['main20ObjectCandidate']; compiled=json.loads(exact(prior).read_bytes()); compile_record=json.loads(exact(compiled['actualCompile']).read_bytes()); argv=copy.deepcopy(compile_record['argv'])
    assert argv.count(original.as_posix())==1 and argv.count(compiled['object']['path'])==1
    obj=output/'main21.ios.o'; argv[argv.index(str(original))]=str(source); argv[argv.index(compiled['object']['path'])]=str(obj)
    q=subprocess.run(argv,capture_output=True,timeout=90); so=output/'compile.stdout'; se=output/'compile.stderr'; so.write_bytes(q.stdout); se.write_bytes(q.stderr)
    actual_compile=output/'compile-command.json'; save(actual_compile,dict(argv=argv,exit=q.returncode,stdout=pin(so),stderr=pin(se)))
    assert q.returncode==0, q.stderr.decode(errors='replace')[-4000:]
    source_files=[pin(source),*app['sourceFiles'][1:]]; objects=[pin(obj),*app['objects'][1:]]
    contract=dict(onlyIndependent27OrdinaryRawDiskImgChanged=True,otherBackendPublicInitializationWholeUnchanged=True,parentOriginalDescriptorBackendType=1,actualChildEncodedBackend=3,cachingAutomatic0AndFullSynchronization1Preserved=True,rootStorageRole1Preserved=True,originalRawDiskImageFormatAndOwnedFDThreadPoolIOSelected=True,noDI2SuccessFabricated=True,noMacOS13Fallback=True,missingClassesOrMethodsOrActualInitializationErrorsRefuse=True,allThreeClassesMustBelongToActualVZ27Image=True,descriptorAndDiskReleasedOnEveryPath=True,originalFactoryStronglyOwnsDisk=True,autoreleasedFactoryResultRetainedToOriginalPlusOne=True,allOtherMain20CodeWholeUnchanged=True,main20URLDisplayAndSSHDeferralWholeUnchanged=True,noRuntimeOrChildMachineCodeChanged=True,actualGuestIOOrBootNotYetExecuted=True)
    result=dict(schema='Main21 original VZ27 raw-FD storage attachment source and sole actual iOS compilation',sourceCandidate=pin(OLD),baselineMain20=pin(OLD),source=pin(source),sourceDiff=pin(diff),object=pin(obj),actualCompile=pin(actual_compile),actualCompileExit=q.returncode,baselineCompiledAppCandidate=pin(APP),actualRuntimeCandidate=pin(RUNTIME),originalParentAndChildBasis=pin(basis),rawDiskThreadPoolAttachmentContract=contract,sourceFiles=source_files,objects=objects,actualInheritedWholeAppObjects=34,actualMainCompilations=1,actualIncludeClosure=app['actualIncludeClosure'],externalPrecompiledObjects=app.get('externalPrecompiledObjects',[]),runtime43AnchorWholeUnchanged=True,main20HistoricalDisplayAndSSHContract=old['urlDisplayPresentationContract'],sshRegistrationExplicitlyDeferredForFirstBasicGuestBoot=True,genuineSSHRegistrationRouteEnabled=False,applicationBinaryLinked=False,codeSigned=False,deviceOperations=0,actualGuestStarted=False,actualVisibleGuest=False,builder=pin(__file__))
    save(output/'candidate.json',result)
    files=[pin(p) for p in sorted(output.rglob('*')) if p.is_file()]
    files += [pin(__file__),pin(OLD),pin(APP),pin(RUNTIME),pin(manifest),parent_pin,pin(CHILD_BASIS),pin(original),prior,compiled['actualCompile'],*source_files,*objects,*app['actualIncludeClosure'],*app.get('externalPrecompiledObjects',[])]
    save(output/'freeze.json',dict(files=list({p['path']:p for p in files}.values()),deviceOperations=0,codeSigningOperations=0))
    print(json.dumps(dict(candidate=pin(output/'candidate.json'),freeze=pin(output/'freeze.json'),source=pin(source),object=pin(obj),actualCompilations=1,inheritedWholeObjects=34)))

if __name__=='__main__': main()
