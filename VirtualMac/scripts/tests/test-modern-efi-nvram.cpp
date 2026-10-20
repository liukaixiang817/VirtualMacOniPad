// Strong genuine27 EFI calls use only a unique owned 128 KiB NVRAM mapping.
// No production/guest NVRAM, system firmware, VM, HV or GPU is accessed.
#include <stddef.h>
#include <stdint.h>
#include "efi-probe-pins.h"
#include <CommonCrypto/CommonDigest.h>
#include <cerrno>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <dlfcn.h>
#include <fcntl.h>
#include <mach-o/dyld.h>
#include <mach-o/loader.h>
#include <ptrauth.h>
#include <sys/mman.h>
#include <sys/resource.h>
#include <sys/stat.h>
#include <unistd.h>

struct GUID { uint32_t a; uint16_t b,c; uint8_t d[8]; };
static_assert(sizeof(GUID)==16);
using EFIStatus=uint64_t;
extern "C" EFIStatus CreateEfiVariableStoreRuntimeFromMemory(void*,size_t);
extern "C" EFIStatus DestroyEfiVariableStoreRuntime();
extern "C" EFIStatus EfiVariableGetVariable(const char16_t*,const GUID*,uint32_t*,size_t*,void*);
extern "C" EFIStatus EfiVariableSetVariable(const char16_t*,const GUID*,uint32_t,size_t,const void*);
extern "C" EFIStatus EfiVariableGetNextVariableName(size_t*,char16_t*,GUID*);
extern "C" EFIStatus EfiVariableQueryVariableInfo(uint32_t,uint64_t*,uint64_t*,uint64_t*);
extern "C" uint32_t GetCurrentEfiVariableStoreRuntimeState();
static unsigned Checks=0,Failures=0,Calls=0,Creates=0,Destroys=0;
static constexpr size_t StoreBytes=0x20000;
static constexpr EFIStatus BufferTooSmall=0x8000000000000005ull,NotFound=0x800000000000000eull;
static constexpr GUID Vendor={0x88f5dd91,0x7565,0x4f32,{0x9e,0x11,0x6a,0x39,0x74,0x14,0x0b,0x28}};
static constexpr char16_t Name[]=u"VM27OwnedNVRAMProbe";
static void Need(bool ok,const char*name){++Checks;std::printf("{\"record\":\"check\",\"id\":%u,\"name\":\"%s\",\"passed\":%s}\n",Checks,name,ok?"true":"false");if(!ok){++Failures;_exit(1);}}
static EFIStatus Call(EFIStatus status,const char*name){++Calls;std::printf("{\"record\":\"efi-call\",\"name\":\"%s\",\"status\":\"0x%016llx\"}\n",name,(unsigned long long)status);return status;}
static bool File(const char*path,const char*expected,size_t bytes){
 int fd=open(path,O_RDONLY|O_NOFOLLOW|O_CLOEXEC);if(fd<0)return false;struct stat a={},b={};
 bool ok=!fstat(fd,&a)&&S_ISREG(a.st_mode)&&a.st_nlink==1&&a.st_uid==getuid()&&!(a.st_mode&0022)&&size_t(a.st_size)==bytes;
 CC_SHA256_CTX sha;unsigned char buf[4096],digest[32];size_t count=0;ok=ok&&CC_SHA256_Init(&sha);
 while(ok){ssize_t n=read(fd,buf,sizeof(buf));if(n<0&&errno==EINTR)continue;if(n<0){ok=false;break;}if(!n)break;
  if(size_t(n)>bytes-count){ok=false;break;}count+=size_t(n);ok=CC_SHA256_Update(&sha,buf,CC_LONG(n));}
 ok=ok&&count==bytes&&!fstat(fd,&b)&&a.st_dev==b.st_dev&&a.st_ino==b.st_ino&&a.st_size==b.st_size&&a.st_mode==b.st_mode&&a.st_mtimespec.tv_sec==b.st_mtimespec.tv_sec&&a.st_mtimespec.tv_nsec==b.st_mtimespec.tv_nsec;
 if(close(fd))ok=false;char hex[65]={};if(ok){ok=CC_SHA256_Final(digest,&sha);for(unsigned i=0;i<32;++i)std::snprintf(hex+2*i,3,"%02x",digest[i]);}
 std::printf("{\"record\":\"file\",\"path\":\"%s\",\"SHA256\":\"%s\",\"exact\":%s}\n",path,hex,ok&&!std::strcmp(hex,expected)?"true":"false");return ok&&!std::strcmp(hex,expected);
}
static bool UUID(const void*base,const unsigned char*expected=EfiUUID){auto*h=static_cast<const mach_header_64*>(base);if(!h||h->magic!=MH_MAGIC_64||h->ncmds>128||h->sizeofcmds>16384)return false;
 auto*p=reinterpret_cast<const unsigned char*>(h+1);unsigned at=0,count=0;bool exact=false;
 for(unsigned i=0;i<h->ncmds;++i){if(at>h->sizeofcmds||h->sizeofcmds-at<8)return false;load_command c;std::memcpy(&c,p+at,8);
  if(c.cmdsize<8||c.cmdsize&7||c.cmdsize>h->sizeofcmds-at)return false;if(c.cmd==LC_UUID){if(c.cmdsize!=24)return false;++count;exact=!std::memcmp(p+at+8,expected,16);}at+=c.cmdsize;}return count==1&&exact&&at==h->sizeofcmds;
}
static void LoadedModules(const char*phase){for(unsigned i=0;i<3;++i){const auto&m=Modules[i];void*handle=dlopen(m.path,RTLD_NOLOAD|RTLD_NOW|RTLD_LOCAL);Need(handle,"genuine EFI module already loaded by original loader");void*raw=dlsym(handle,"_ModuleEntryPoint");Dl_info d={};struct stat a={},b={};Need(raw&&dladdr(raw,&d)&&d.dli_fbase&&d.dli_fname&&!stat(d.dli_fname,&a)&&!stat(m.path,&b)&&a.st_ino==b.st_ino&&a.st_dev==b.st_dev&&UUID(d.dli_fbase,m.uuid),"genuine module function actual inode UUID");uintptr_t rva=reinterpret_cast<uintptr_t>(ptrauth_strip(raw,ptrauth_key_function_pointer))-reinterpret_cast<uintptr_t>(d.dli_fbase);Need(rva==m.rva,"genuine ModuleEntryPoint exact original RVA");std::printf("{\"record\":\"module\",\"phase\":\"%s\",\"entry\":%u,\"path\":\"%s\",\"RVA\":%llu,\"actualLoaded\":true}\n",phase,i,m.path,(unsigned long long)rva);Need(!dlclose(handle),"close only borrowed no-load diagnostic reference");}}
static void Identity(bool before){
 Need(File(EfiPath,EfiSHA,EfiBytes),before?"genuine EFI exact file before":"genuine EFI exact file after");Need(File(RTTIPath,RTTISHA,RTTIBytes),before?"typed RTTI exact file before":"typed RTTI exact file after");
 Need(File(SeedPath,SeedSHA,StoreBytes),before?"genuine Apple-created seed exact file before":"genuine Apple-created seed exact file after");
 for(const auto&m:Modules)Need(File(m.path,m.sha,m.bytes),before?"genuine EFI module exact file before":"genuine EFI module exact file after");
 void*f[]={reinterpret_cast<void*>(&CreateEfiVariableStoreRuntimeFromMemory),reinterpret_cast<void*>(&DestroyEfiVariableStoreRuntime),reinterpret_cast<void*>(&EfiVariableGetVariable),reinterpret_cast<void*>(&EfiVariableSetVariable),reinterpret_cast<void*>(&EfiVariableGetNextVariableName),reinterpret_cast<void*>(&EfiVariableQueryVariableInfo),reinterpret_cast<void*>(&GetCurrentEfiVariableStoreRuntimeState)};
 for(unsigned i=0;i<7;++i){void*raw=ptrauth_strip(f[i],ptrauth_key_function_pointer);Dl_info d={};Need(dladdr(raw,&d)&&d.dli_fbase&&d.dli_fname,"strong EFI function actual dladdr");struct stat a={},b={};Need(!stat(d.dli_fname,&a)&&!stat(EfiPath,&b)&&a.st_ino==b.st_ino&&a.st_dev==b.st_dev&&UUID(d.dli_fbase),"same genuine EFI file UUID/inode");Need(reinterpret_cast<uintptr_t>(raw)-reinterpret_cast<uintptr_t>(d.dli_fbase)==EfiRVAs[i],"strong EFI exact original RVA");
  std::printf("{\"record\":\"provider\",\"phase\":\"%s\",\"entry\":%u,\"UUID\":\"10a81345e6c23aab8a107c6cdf0b2a64\",\"RVA\":%llu,\"strongImport\":true}\n",before?"before":"after",i,(unsigned long long)EfiRVAs[i]);}
 unsigned forbidden=0;for(unsigned i=0;i<_dyld_image_count();++i){const char*n=_dyld_get_image_name(i);if(n&&(std::strstr(n,"Virtualization.framework")||std::strstr(n,"Hypervisor.framework")||std::strstr(n,"VirtualMachine.framework")||std::strstr(n,"ParavirtualizedGraphics.framework")))++forbidden;}Need(!forbidden,"no VM/HV/VMM/PVG images");
}
static void Roundtrip(const unsigned char*expected,size_t bytes){
 size_t size=0;uint32_t attr=0;Need(Call(EfiVariableGetVariable(Name,&Vendor,&attr,&size,nullptr),"Get(size query)")==BufferTooSmall&&size==bytes,"exact size query BUFFER_TOO_SMALL");
 unsigned char buffer[96];std::memset(buffer,0xa5,sizeof(buffer));size=bytes-1;Need(Call(EfiVariableGetVariable(Name,&Vendor,&attr,&size,buffer),"Get(undersized)")==BufferTooSmall&&size==bytes,"undersized status and required bytes");for(unsigned i=0;i<sizeof(buffer);++i)Need(buffer[i]==0xa5,"undersized buffer intact");
 size=sizeof(buffer);Need(Call(EfiVariableGetVariable(Name,&Vendor,&attr,&size,buffer),"Get(exact value)")==0&&attr==7&&size==bytes&&!std::memcmp(buffer,expected,bytes),"genuine persisted bytes and NV/BS/RT attributes");for(size_t i=bytes;i<sizeof(buffer);++i)Need(buffer[i]==0xa5,"read output trailing guard intact");
}
int main(int argc,char**argv){
 setbuf(stdout,nullptr);std::printf("{\"record\":\"start\",\"PID\":%d,\"UID\":%u,\"VMCalls\":0,\"GPUCalls\":0,\"productionNVRAM\":false}\n",getpid(),getuid());
 rlimit cpu={5,5},core={0,0};Need(!setrlimit(RLIMIT_CPU,&cpu)&&!setrlimit(RLIMIT_CORE,&core),"bounded CPU/core");alarm(15);Need(argc==3,"signed self hash and byte arguments");
#if defined(VM27_EFI_IOS)
 Need(getuid()==0&&geteuid()==0,"private Root diagnostic");
#endif
 char self[4096];uint32_t n=sizeof(self);Need(!_NSGetExecutablePath(self,&n),"actual self path");char*canonical=realpath(self,nullptr);Need(canonical,"canonical self path");Need(File(canonical,argv[1],std::strtoull(argv[2],nullptr,10)),"signed self exact bytes");std::free(canonical);Identity(true);
 char directory[4096];Need(std::snprintf(directory,sizeof(directory),"%s/owned-nvram.XXXXXX",WorkParent)>0&&mkdtemp(directory),"exclusive owned temporary directory");struct stat ds={};Need(!lstat(directory,&ds)&&S_ISDIR(ds.st_mode)&&ds.st_uid==getuid()&&!(ds.st_mode&0077),"private owned directory");
 char path[4096];Need(std::snprintf(path,sizeof(path),"%s/nvram.bin",directory)>0,"own NVRAM path");int fd=open(path,O_RDWR|O_CREAT|O_EXCL|O_NOFOLLOW|O_CLOEXEC,0600);Need(fd>=0&&!ftruncate(fd,StoreBytes),"exclusive owned 128 KiB backing file");void*memory=mmap(nullptr,StoreBytes,PROT_READ|PROT_WRITE,MAP_SHARED,fd,0);Need(memory!=MAP_FAILED,"map only owned backing file");
 int seed=open(SeedPath,O_RDONLY|O_NOFOLLOW|O_CLOEXEC);Need(seed>=0,"read only exact Apple-created own seed");size_t copied=0;while(copied<StoreBytes){ssize_t count=read(seed,static_cast<unsigned char*>(memory)+copied,StoreBytes-copied);if(count<0&&errno==EINTR)continue;Need(count>0,"complete seed copy to own mapping");copied+=size_t(count);}Need(!close(seed),"close seed reader");unsigned char digest[32];Need(CC_SHA256(memory,StoreBytes,digest)&&!std::memcmp(digest,SeedDigest,32),"copied seed SHA exact before genuine create");
 Need(Call(CreateEfiVariableStoreRuntimeFromMemory(memory,StoreBytes),"Create(memory)")==0,"genuine runtime created from own 128 KiB mapping");++Creates;
 LoadedModules("first-create");
 unsigned state=GetCurrentEfiVariableStoreRuntimeState();++Calls;std::printf("{\"record\":\"runtime-state\",\"value\":%u}\n",state);Need(state==1001,"genuine initial runtime state");
 uint64_t maximum=0,remaining=0,largest=0;Need(Call(EfiVariableQueryVariableInfo(7,&maximum,&remaining,&largest),"Query(storage)")==0&&maximum>=remaining&&remaining>96&&largest>=96,"genuine NV storage capacity");
 unsigned char first[29],second[57];for(unsigned i=0;i<sizeof(first);++i)first[i]=unsigned(13*i+7);for(unsigned i=0;i<sizeof(second);++i)second[i]=unsigned(17*i+3);
 Need(Call(EfiVariableSetVariable(Name,&Vendor,7,sizeof(first),first),"Set(initial)")==0,"set own vendor/name real payload");Roundtrip(first,sizeof(first));
 bool found=false;char16_t enumeration[256]={};GUID vendor={};for(unsigned i=0;i<128&&!found;++i){size_t size=sizeof(enumeration);EFIStatus status=Call(EfiVariableGetNextVariableName(&size,enumeration,&vendor),"GetNext(owned name)");if(status==NotFound)break;Need(status==0&&size<=sizeof(enumeration)&&!(size&1),"bounded enumeration status/name size");found=size==sizeof(Name)&&!std::memcmp(enumeration,Name,sizeof(Name))&&!std::memcmp(&vendor,&Vendor,sizeof(Vendor));}Need(found,"real enumeration finds own exact UTF16 name/GUID");
 Need(Call(EfiVariableSetVariable(Name,&Vendor,7,sizeof(second),second),"Set(replace)")==0,"replace owned variable with larger payload");Roundtrip(second,sizeof(second));
 Need(Call(DestroyEfiVariableStoreRuntime(),"Destroy(first)")==0,"destroy genuine runtime before unmap");++Destroys;Need(!msync(memory,StoreBytes,MS_SYNC)&&!fsync(fd)&&!munmap(memory,StoreBytes)&&!close(fd),"sync then unmap and close first raw file owner");
 fd=open(path,O_RDWR|O_NOFOLLOW|O_CLOEXEC);struct stat fs={};Need(fd>=0&&!fstat(fd,&fs)&&S_ISREG(fs.st_mode)&&fs.st_nlink==1&&fs.st_uid==getuid()&&fs.st_size==StoreBytes,"reopen same owned backing file");memory=mmap(nullptr,StoreBytes,PROT_READ|PROT_WRITE,MAP_SHARED,fd,0);Need(memory!=MAP_FAILED,"remap genuine persisted NVRAM");Need(Call(CreateEfiVariableStoreRuntimeFromMemory(memory,StoreBytes),"Create(reopened)")==0,"recreate genuine runtime over disk persisted file");++Creates;LoadedModules("second-create");Roundtrip(second,sizeof(second));
 Need(Call(EfiVariableSetVariable(Name,&Vendor,7,0,nullptr),"Set(delete)")==0,"delete only owned variable");size_t missing=0;Need(Call(EfiVariableGetVariable(Name,&Vendor,nullptr,&missing,nullptr),"Get(deleted)")==NotFound,"deleted owned variable reports NOT_FOUND");
 Need(Call(DestroyEfiVariableStoreRuntime(),"Destroy(second)")==0,"second genuine runtime destroyed");++Destroys;Need(!msync(memory,StoreBytes,MS_SYNC)&&!fsync(fd)&&!munmap(memory,StoreBytes)&&!close(fd),"sync unmap close second file owner");Need(!unlink(path)&&!rmdir(directory),"delete exclusive own temporary file and directory");Identity(false);alarm(0);
 std::printf("{\"record\":\"summary\",\"PID\":%d,\"checks\":%u,\"failures\":%u,\"EFICalls\":%u,\"creates\":%u,\"destroys\":%u,\"persistedRemap\":true,\"ownedVariableDeleted\":true,\"ownFilesRemoved\":true,\"VMCalls\":0,\"GPUCalls\":0,\"productionNVRAM\":false,\"fullEFIAPIContract\":false,\"full27Backend\":false}\n",getpid(),Checks,Failures,Calls,Creates,Destroys);return Failures?1:0;
}
