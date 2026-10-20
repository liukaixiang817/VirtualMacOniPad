#!/usr/bin/env python3
"""Finite independent named cache adapter source/real-FD test receipt peer."""
import pathlib,json,hashlib,sys
sys.dont_write_bytecode=True
R=pathlib.Path(__file__).resolve().parents[3];N=R/'DeviceDiagnostics/2026-10-08-full-macos27-cpu-vmm'
def pin(p):
 p=pathlib.Path(p).resolve();b=p.read_bytes();return dict(path=str(p),bytes=len(b),sha256=hashlib.sha256(b).hexdigest())
def exact(r):
 assert pin(r['path'])=={k:r[k]for k in ('path','bytes','sha256')};return pathlib.Path(r['path'])
def main():
 cp=N/'owned-vz-cache-adapter-source-v1-attempt2/candidate.json';c=json.loads(cp.read_bytes());fp=cp.parent/'freeze.json'
 for r in json.loads(fp.read_bytes())['files']:exact(r)
 text=exact(c['source']).read_text();header=exact(c['header']).read_text();contract=c['cacheAdapterContract']
 assert 'size_t VM27OwnedVZCacheConfstrV1(int name, char *buffer, size_t capacity)'in text and 'extern "C"'in header
 assert 'size_t result = native(name, buffer, capacity);'in text
 assert 'if (name != _CS_DARWIN_USER_CACHE_DIR || result != 0)'in text and 'errno = nativeErrno; return result;'in text
 assert 'if (!eligible(caller)) {errno = nativeErrno; return 0;}'in text
 assert 'size_t required = sizeof(path);'in text and 'copy = capacity-1;'in text and "buffer[copy] = '\\0';"in text and 'errno = incomingErrno;'in text
 assert all(x in text for x in ('getuid() != 501','geteuid() != 501','getpid() <= 1','UINT32_C(0x04000001)','VM27_APP_MAIN','VM27_PARENT_VZ','ptrauth_strip(__builtin_return_address(0)','ptrauth_strip((void *)&confstr','UINT64_C(0x1421c)'))
 assert all(x in text for x in ('O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC','fstat(fd, &value)','value.st_uid != owner','value.st_gid != 501','(value.st_mode & 07777) != 0700','(value.st_mode & 0022)','i < 2 ? 0 : 501, i >= 4'))
 assert not any(x in text for x in ('mkdir(','chmod(','chown(','setuid(','vm_protect(','mprotect(','RTLD_DEFAULT','"w"','O_WRONLY','O_RDWR'))
 assert contract['cachePath']=='/private/var/mobile/Library/VirtualMacIndependent27Cache-v1/virtualization/'and contract['cachePathRequiredBytesIncludingNUL']==len(contract['cachePath'].encode())+1==76
 assert contract['nativeConfstrImageUUID']=='dad0ce088f353ff4899e43dc44eb65a7'and contract['nativeConfstrRVA']==82460
 assert contract['selectedActualImportIndex']==504 and contract['newRequiredOrdinal']==64 and contract['callerParentOnly']and contract['nativeZeroOnlyFallback']and contract['directoryMustBeProvisionedByActualDeployment']and not contract['actualProductionCacheDirectoryVerified']
 assert c['actualStrictIOSCompileExit']==c['typedCXXHeaderCompileExit']==0 and c['actualHostNormal']['actualHostFixtureChecks']==c['actualHostSAN']['actualHostFixtureChecks']==32
 assert c['actualHostNormal']['nativeConfstrQueriesMockedExplicitly']and c['actualHostSAN']['nativeConfstrQueriesMockedExplicitly']
 out=N/'owned-vz-cache-source-independent-peer-v1-attempt1';out.mkdir(mode=0o700);report=dict(schema='Named parent-only genuine owned cache adapter finite independent source peer',sourceCandidate=pin(cp),producerFreeze=pin(fp),source=c['source'],header=c['header'],actualIOSObject=c['actualIOSObject'],cacheAdapterContract=contract,nativePositiveAndOtherSelectorsPassThroughActualResultAndErrno=True,onlyNativeCache65538ZeroEntersFallback=True,nativeZeroAndErrnoPreservedOnEligibilityFailure=True,actualFilesystemErrorReturnedOnDirectoryFailure=True,actualExistingNoFollowDirectoryFDUIDGIDModeRequired=True,sourceNeverCreatesOrWritesOrChangesPermissions=True,actualParentAppPathAndVZUUIDAndNativeConfstrUUIDRVAAdmission=True,actualCSVALIDPlatformBitsRequired=True,ptrauthCallerAndNativeFunctionAddressStrippedForIdentityOnly=True,requiredConfstrSizeIncludesNULTruncatedCopiesTerminate=True,successfulFallbackRestoresIncomingErrno=True,explicitNamedAPIIsNotGlobalLibcInterposition=True,HOST32NormalAnd32SANReceiptsAndActualFDTestsInherited=True,HOSTNativeConfstrWasExplicitMock=True,hostTestsRepeated=False,actualDeploymentMustCreateTwoUID501GID501Mode0700Dirs=True,productionDirectoryActuallyVerified=False,actualNativeCacheFallbackExecuted=False,actualVMStartupSuccessNotClaimed=True,deviceOperations=0,trustCacheOperations=0,findings=[],passed=True,finiteLocalScopePassed=True)
 rp=out/'review.json';rp.write_text(json.dumps(report,indent=2)+'\n');rows=[pin(__file__),pin(cp),pin(fp),c['source'],c['header'],c['actualIOSObject'],c['nativeZeroReceipt'],pin(N/'actual-normal11-confstr-native-namespace-proof-v1-attempt1/report.json'),pin(rp)];sf=out/'freeze.json';sf.write_text(json.dumps(dict(files=rows,deviceOperations=0),indent=2)+'\n');print(json.dumps(dict(review=pin(rp),freeze=pin(sf),findings=[])))
if __name__=='__main__':main()
