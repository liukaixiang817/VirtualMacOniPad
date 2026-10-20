// Read-only bounded system libc++abi RTTI/vtable/code collector. No calls to RTTI or exception APIs.
#include <CommonCrypto/CommonDigest.h>
#include <dlfcn.h>
#include <errno.h>
#include <inttypes.h>
#include <mach/mach.h>
#include <mach-o/loader.h>
#include <ptrauth.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/resource.h>
#include <unistd.h>

// iOS omits mach_vm.h despite exporting the genuine64-bit MIG routine.
extern kern_return_t mach_vm_read_overwrite(vm_map_read_t target,
    mach_vm_address_t address,mach_vm_size_t size,
    mach_vm_address_t data,mach_vm_size_t *copied);

struct image {
    uintptr_t base;
    uint64_t textVM, textBytes, sectionVM, sectionBytes;
    uint64_t linkVM, linkFile, linkBytes;
    uint32_t startsOffset, startsBytes;
    uint8_t uuid[16];
    int64_t slide;
    unsigned char starts[16384];
    bool startsRead;
    uint64_t dataVM[8],dataBytes[8];unsigned dataCount;
};
static void String(const char *s) {
    putchar('"');
    if(s) for(unsigned i=0;s[i] && i<4096;++i) {
        unsigned char c=(unsigned char)s[i];
        if(c=='"'||c=='\\') putchar('\\');
        if(c<32) printf("\\u%04x",c); else putchar(c);
    }
    putchar('"');
}
static void Hex(const void *p,size_t n) {
    const unsigned char *bytes=p;for(size_t i=0;i<n;++i) printf("%02x",bytes[i]);
}
static bool Read(const char *label,uintptr_t address,void *buffer,size_t bytes) {
    if(!address || !bytes || bytes>16384) return false;
    mach_vm_size_t copied=0;
    kern_return_t rc=mach_vm_read_overwrite(mach_task_self(),(mach_vm_address_t)address,
        (mach_vm_size_t)bytes,(mach_vm_address_t)(uintptr_t)buffer,&copied);
    printf("{\"record\":\"read\",\"label\":");String(label);
    printf(",\"address\":\"0x%" PRIxPTR "\",\"requested\":%zu,\"readRC\":%d,\"copied\":%llu,\"passed\":%s}\n",
        address,bytes,rc,(unsigned long long)copied,rc==KERN_SUCCESS&&copied==bytes?"true":"false");
    return rc==KERN_SUCCESS && copied==bytes;
}
static bool Image(uintptr_t base,struct image *out) {
    struct mach_header_64 h={0};
    if(!Read("libcxxabi-header",base,&h,sizeof(h))) return false;
    printf("{\"record\":\"header\",\"base\":\"0x%" PRIxPTR "\",\"magic\":%u,\"cpu\":%u,\"subtype\":%u,\"filetype\":%u,\"ncmds\":%u,\"sizeofcmds\":%u}\n",
        base,h.magic,(uint32_t)h.cputype,(uint32_t)h.cpusubtype,h.filetype,h.ncmds,h.sizeofcmds);
    if(h.magic!=MH_MAGIC_64 || (uint32_t)h.cputype!=0x100000c || h.filetype!=MH_DYLIB ||
        !h.ncmds || h.ncmds>256 || !h.sizeofcmds || h.sizeofcmds>16384) return false;
    unsigned char commands[16384];
    if(!Read("libcxxabi-load-commands",base+sizeof(h),commands,h.sizeofcmds)) return false;
    memset(out,0,sizeof(*out));out->base=base;unsigned at=0,uuidCount=0;
    for(unsigned i=0;i<h.ncmds;++i) {
        if(at>h.sizeofcmds || h.sizeofcmds-at<8) return false;
        struct load_command c;memcpy(&c,commands+at,8);
        if(c.cmdsize<8 || c.cmdsize&7 || c.cmdsize>h.sizeofcmds-at) return false;
        if(c.cmd==LC_UUID) {
            if(c.cmdsize!=24) return false;++uuidCount;memcpy(out->uuid,commands+at+8,16);
        } else if(c.cmd==LC_SEGMENT_64) {
            struct segment_command_64 s;
            if(c.cmdsize<sizeof(s)) return false;memcpy(&s,commands+at,sizeof(s));
            if(s.nsects>128 || c.cmdsize!=sizeof(s)+sizeof(struct section_64)*s.nsects) return false;
            if(!memcmp(s.segname,"__TEXT\0",7)) {
                if(!(s.initprot&VM_PROT_READ) || !(s.initprot&VM_PROT_EXECUTE) || s.initprot&VM_PROT_WRITE) return false;
                out->textVM=s.vmaddr;out->textBytes=s.vmsize;out->slide=(int64_t)base-(int64_t)s.vmaddr;
                for(unsigned j=0;j<s.nsects;++j) {
                    struct section_64 section;memcpy(&section,commands+at+sizeof(s)+j*sizeof(section),sizeof(section));
                    if(!memcmp(section.sectname,"__text\0",7)) {out->sectionVM=section.addr;out->sectionBytes=section.size;}
                }
            } else if((!memcmp(s.segname,"__DATA",6) || !memcmp(s.segname,"__AUTH",6)) && (s.initprot&VM_PROT_READ) && !(s.initprot&VM_PROT_EXECUTE)) {
                if(out->dataCount>=8) return false;out->dataVM[out->dataCount]=s.vmaddr;out->dataBytes[out->dataCount]=s.vmsize;++out->dataCount;
            } else if(!memcmp(s.segname,"__LINKEDIT\0",11)) {
                out->linkVM=s.vmaddr;out->linkFile=s.fileoff;out->linkBytes=s.filesize;
            }
        } else if(c.cmd==LC_FUNCTION_STARTS) {
            if(c.cmdsize!=16) return false;memcpy(&out->startsOffset,commands+at+8,8);
        } else if(c.cmd==LC_BUILD_VERSION) {
            struct build_version_command b;if(c.cmdsize<sizeof(b)) return false;memcpy(&b,commands+at,sizeof(b));
            printf("{\"record\":\"build\",\"platform\":%u,\"minOS\":%u,\"SDK\":%u}\n",b.platform,b.minos,b.sdk);
        }
        at+=c.cmdsize;
    }
    if(at!=h.sizeofcmds || uuidCount!=1 || !out->textBytes || !out->sectionBytes) return false;
    printf("{\"record\":\"image\",\"UUID\":\"");Hex(out->uuid,16);
    printf("\",\"slide\":%lld,\"textVM\":\"0x%llx\",\"textBytes\":%llu,\"functionStartsOffset\":%u,\"functionStartsBytes\":%u}\n",
        (long long)out->slide,(unsigned long long)out->textVM,(unsigned long long)out->textBytes,out->startsOffset,out->startsBytes);
    if(out->startsBytes && out->startsBytes<=sizeof(out->starts) && out->startsOffset>=out->linkFile &&
        out->startsOffset-out->linkFile<=out->linkBytes && out->startsBytes<=out->linkBytes-(out->startsOffset-out->linkFile)) {
        uintptr_t address=(uintptr_t)(out->slide+(int64_t)out->linkVM+out->startsOffset-out->linkFile);
        out->startsRead=Read("libcxxabi-function-starts",address,out->starts,out->startsBytes);
        if(out->startsRead) {unsigned char digest[32];CC_SHA256(out->starts,out->startsBytes,digest);
            printf("{\"record\":\"functionStarts\",\"bytes\":%u,\"SHA256\":\"",out->startsBytes);Hex(digest,32);puts("\"}");}
    }
    return true;
}
static bool Bounds(const struct image *im,uintptr_t address,uint64_t *start,uint64_t *end) {
    uint64_t target=(uint64_t)((int64_t)address-im->slide);
    if(target<im->sectionVM || target>=im->sectionVM+im->sectionBytes) return false;
    *start=target;*end=im->sectionVM+im->sectionBytes;
    if(!im->startsRead) return false;
    uint64_t current=im->textVM;size_t at=0;bool preceding=false;
    while(at<im->startsBytes) {
        uint64_t delta=0;unsigned shift=0;
        for(;;) {
            if(at>=im->startsBytes || shift>=64) return false;
            unsigned char byte=im->starts[at++];
            if(shift==63 && (byte&0x7e)) return false;
            delta|=(uint64_t)(byte&127)<<shift;
            if(!(byte&128)) break;shift+=7;
        }
        if(!delta) break;
        if(delta>UINT64_MAX-current) return false;current+=delta;
        if(current<=target) {*start=current;preceding=true;}
        else {*end=current;return preceding;}
    }
    return preceding;
}
static bool Code(const char *name,uintptr_t address,const struct image *im) {
    uint64_t start=0,end=0;bool exactBounds=Bounds(im,address,&start,&end);
    uint64_t target=(uint64_t)((int64_t)address-im->slide);
    if(target<im->sectionVM || target>=im->sectionVM+im->sectionBytes) return false;
    if(end<=target || end>im->sectionVM+im->sectionBytes) end=im->sectionVM+im->sectionBytes;
    size_t bytes=(size_t)(end-target);if(bytes>2048) bytes=2048;
    unsigned char code[2048],digest[32];bool read=Read(name,address,code,bytes);
    printf("{\"record\":\"code\",\"symbol\":");String(name);
    printf(",\"RVA\":\"0x%" PRIxPTR "\",\"functionStartRVA\":\"0x%llx\",\"functionEndRVA\":\"0x%llx\",\"functionBoundsKnown\":%s,\"entryIsStart\":%s,\"bytes\":%zu,\"readSucceeded\":%s",
        address-im->base,(unsigned long long)(start-im->textVM),(unsigned long long)(end-im->textVM),
        exactBounds?"true":"false",exactBounds&&start==target?"true":"false",bytes,read?"true":"false");
    if(read) {CC_SHA256(code,(CC_LONG)bytes,digest);printf(",\"SHA256\":\"");Hex(digest,32);printf("\",\"hex\":\"");Hex(code,bytes);putchar('"');}
    puts("}");return read;
}
int main(int argc,char **argv) {
    setbuf(stdout,NULL);struct rlimit cpu={3,3},core={0,0};
    if(setrlimit(RLIMIT_CPU,&cpu) || setrlimit(RLIMIT_CORE,&core)) return 78;alarm(8);
    printf("{\"record\":\"start\",\"PID\":%d,\"UID\":%u,\"exceptionCalls\":0,\"RTTIConstructs\":0,\"destructorCalls\":0,\"VMCalls\":0,\"GPUCalls\":0,\"maxFunctionBytes\":2048}\n",getpid(),getuid());
    if(argc>5) return 64;
    void *handle=dlopen("/usr/lib/libc++abi.dylib",RTLD_NOW|RTLD_LOCAL);
    if(!handle) {printf("{\"record\":\"dlopen\",\"success\":false,\"error\":");String(dlerror());puts("}");return 78;}
    const char *names[]={"__cxa_allocate_exception","_ZN10__cxxabiv120__si_class_type_infoD1Ev",
        "_ZN10__cxxabiv120__si_class_type_infoD2Ev","_ZN10__cxxabiv120__si_class_type_infoD0Ev",
        "_ZNSt9type_infoD1Ev","_ZNSt9type_infoD2Ev","_ZNSt9type_infoD0Ev"};
    struct image image={0};bool haveImage=false,all=true;unsigned found=0,read=0;
    for(unsigned i=0;i<sizeof(names)/sizeof(names[0]);++i) {
        void *signedEntry=dlsym(handle,names[i]);void *raw=ptrauth_strip(signedEntry,ptrauth_key_function_pointer);
        Dl_info d={0};int located=signedEntry?dladdr(raw,&d):0;
        printf("{\"record\":\"address\",\"symbol\":");String(names[i]);
        printf(",\"found\":%s,\"signedPointer\":\"%p\",\"PACStrippedPointer\":\"%p\",\"dladdrRC\":%d,\"dladdrHeader\":\"%p\",\"provider\":",
            signedEntry?"true":"false",signedEntry,raw,located,d.dli_fbase);String(d.dli_fname);puts("}");
        if(!signedEntry) {if(i==0) all=false;continue;}++found;
        if(!located || !d.dli_fname || strcmp(d.dli_fname,"/usr/lib/libc++abi.dylib") || !d.dli_fbase) {all=false;continue;}
        if(!haveImage) {haveImage=Image((uintptr_t)d.dli_fbase,&image);if(!haveImage) {all=false;continue;}}
        if((uintptr_t)d.dli_fbase!=image.base) {all=false;continue;}
        bool ok=Code(names[i],(uintptr_t)raw,&image);all=all&&ok;if(ok) ++read;
    }
    if(haveImage) {
        const unsigned char expected[16]={0xfa,0x87,0x14,0x17,0xbe,0x08,0x3e,0x90,0xb3,0x3c,0xa6,0xaa,0x89,0x81,0x3f,0x3b};
        if(memcmp(image.uuid,expected,16)) {puts("{\"record\":\"RTTIImageGate\",\"passed\":false}");return 78;}
        const char *tableName="_ZTVN10__cxxabiv120__si_class_type_infoE";
        void *table=dlsym(handle,tableName);Dl_info info={0};int located=table?dladdr(table,&info):0;
        printf("{\"record\":\"vtableAddress\",\"symbol\":");String(tableName);
        printf(",\"pointer\":\"%p\",\"dladdrRC\":%d,\"header\":\"%p\",\"provider\":",table,located,info.dli_fbase);String(info.dli_fname);puts("}");
        bool tableScope=located && info.dli_fname && !strcmp(info.dli_fname,"/usr/lib/libc++abi.dylib") &&
            (uintptr_t)info.dli_fbase==image.base;
        bool tableBounds=false;uint64_t vm=(uint64_t)((int64_t)(uintptr_t)table-image.slide);
        for(unsigned i=0;i<image.dataCount;++i) if(vm>=image.dataVM[i] && vm-image.dataVM[i]<=image.dataBytes[i] &&
            32<=image.dataBytes[i]-(vm-image.dataVM[i])) tableBounds=true;
        uint64_t entries[4]={0};
        if(!tableScope || !tableBounds || !Read("native-si-vtable-first-four",(uintptr_t)table,entries,sizeof(entries))) {all=false;}
        else {
            printf("{\"record\":\"vtable\",\"RVA\":\"0x%llx\",\"dataBounds\":true,\"offsetToTop\":%lld,\"rawEntries\":[",
                (unsigned long long)((uintptr_t)table-image.base),(long long)entries[0]);
            for(unsigned j=0;j<4;++j)printf("%s\"0x%llx\"",j?",":"",(unsigned long long)entries[j]);puts("]}");
            if(entries[0]!=0)all=false;
            for(unsigned j=2;j<4;++j) {
                void *raw=ptrauth_strip((void*)(uintptr_t)entries[j],ptrauth_key_function_pointer);Dl_info d={0};
                int rc=dladdr(raw,&d);printf("{\"record\":\"vtableEntry\",\"index\":%u,\"signedPointer\":\"0x%llx\",\"PACStrippedPointer\":\"%p\",\"dladdrRC\":%d,\"provider\":",j,(unsigned long long)entries[j],raw,rc);String(d.dli_fname);puts("}");
                if(!rc||!d.dli_fname||strcmp(d.dli_fname,"/usr/lib/libc++abi.dylib")||(uintptr_t)d.dli_fbase!=image.base)all=false;
                else {bool ok=Code(j==2?"native-si-complete-destructor-vtable-entry":"native-si-deleting-destructor-vtable-entry",(uintptr_t)raw,&image);all=all&&ok;if(ok)++read;}
            }
        }
    }
    for(int i=1;i<argc && haveImage;++i) {
        char *end=NULL;errno=0;uint64_t rva=strtoull(argv[i],&end,16);
        if(errno || !end || *end || end==argv[i] || strlen(argv[i])>18 || rva>image.textBytes || rva&3) {all=false;continue;}
        bool ok=Code("explicit-libcxxabi-internal-RVA",image.base+(uintptr_t)rva,&image);all=all&&ok;if(ok) ++read;
    }
    printf("{\"record\":\"summary\",\"symbolsFound\":%u,\"codeReads\":%u,\"passed\":%s,\"exceptionCalls\":0}\n",found,read,all?"true":"false");
    alarm(0);return all?0:78;
}
