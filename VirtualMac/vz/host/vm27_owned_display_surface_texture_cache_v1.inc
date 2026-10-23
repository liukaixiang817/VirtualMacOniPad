/* Own VMM only. Reuse a texture view of the same retained IOSurface; never
 * cache pixels or change native present/command-buffer completion/readiness.
 * The exact native display call is admitted once. All other Metal calls use
 * their original implementation, with their original arguments and result. */
#import <IOSurface/IOSurfaceRef.h>
#include <pthread.h>

typedef id (*VM27SurfaceTextureOriginalV1)(id,SEL,id,IOSurfaceRef,NSUInteger);
typedef struct {
    id device,texture;
    IOSurfaceRef surface;
    NSUInteger plane,width,height,format,storage,options,hazard,cpu;
} VM27SurfaceTextureEntryV1;
static pthread_mutex_t VM27SurfaceTextureMutexV1=PTHREAD_MUTEX_INITIALIZER;
static VM27SurfaceTextureEntryV1 VM27SurfaceTexturesV1[4];
static unsigned VM27SurfaceTextureNextV1,VM27SurfaceTextureHitsV1,VM27SurfaceTextureMissesV1;
static VM27SurfaceTextureOriginalV1 VM27SurfaceTextureOriginalIMP;
static id VM27SurfaceTextureDeviceV1;
static Class VM27SurfaceTextureDeviceClassV1;
static SEL VM27SurfaceTextureSelectorV1;
static uintptr_t VM27SurfaceTextureCallerV1;
static pid_t VM27SurfaceTexturePIDV1;

static BOOL VM27SurfaceTextureKeyV1(id device,id descriptor,IOSurfaceRef surface,
    NSUInteger plane,VM27SurfaceTextureEntryV1 *key) {
    if(!descriptor || !surface || CFGetTypeID(surface)!=IOSurfaceGetTypeID() ||
       ![descriptor isKindOfClass:MTLTextureDescriptor.class])return NO;
    MTLTextureDescriptor *d=descriptor;
    /* Native27's display path builds a single-level, read-only 2D texture.
     * Other layouts and optional settings keep the original creation path. */
    if(d.textureType!=MTLTextureType2D || d.mipmapLevelCount!=1 || d.sampleCount!=1 ||
       d.arrayLength!=1 || d.depth!=1 || d.usage!=MTLTextureUsageShaderRead ||
       !d.width || !d.height || d.width>16384 || d.height>16384 ||
       (d.pixelFormat!=MTLPixelFormatBGRA8Unorm && d.pixelFormat!=MTLPixelFormatRGBA8Unorm) ||
       !d.allowGPUOptimizedContents || plane!=0 || IOSurfaceGetPlaneCount(surface)!=0 ||
       IOSurfaceGetWidth(surface)!=d.width || IOSurfaceGetHeight(surface)!=d.height)return NO;
    *key=(VM27SurfaceTextureEntryV1){device,nil,surface,plane,d.width,d.height,d.pixelFormat,
        d.storageMode,d.resourceOptions,d.hazardTrackingMode,d.cpuCacheMode};
    return YES;
}
static BOOL VM27SurfaceTextureSameV1(const VM27SurfaceTextureEntryV1 *a,
    const VM27SurfaceTextureEntryV1 *b) {
    return a->texture && a->device==b->device && a->surface==b->surface && a->plane==b->plane &&
        a->width==b->width && a->height==b->height && a->format==b->format && a->storage==b->storage &&
        a->options==b->options && a->hazard==b->hazard && a->cpu==b->cpu;
}
static id VM27SurfaceTextureCreateV1(id device,SEL selector,id descriptor,
    IOSurfaceRef surface,NSUInteger plane) __attribute__((ns_returns_retained));
static id VM27SurfaceTextureCreateV1(id device,SEL selector,id descriptor,
    IOSurfaceRef surface,NSUInteger plane) {
    int incoming=errno;
    void *caller=ptrauth_strip(__builtin_return_address(0),ptrauth_key_return_address);
    VM27SurfaceTextureEntryV1 key={0};
    if(getpid()!=VM27SurfaceTexturePIDV1 || device!=VM27SurfaceTextureDeviceV1 ||
       object_getClass(device)!=VM27SurfaceTextureDeviceClassV1 || selector!=VM27SurfaceTextureSelectorV1 ||
       (uintptr_t)caller!=VM27SurfaceTextureCallerV1 || !VM27SurfaceTextureKeyV1(device,descriptor,surface,plane,&key)) {
        errno=incoming;return VM27SurfaceTextureOriginalIMP(device,selector,descriptor,surface,plane);
    }
    pthread_mutex_lock(&VM27SurfaceTextureMutexV1);
    for(unsigned i=0;i<4;i++)if(VM27SurfaceTextureSameV1(&VM27SurfaceTexturesV1[i],&key)) {
        id texture=[VM27SurfaceTexturesV1[i].texture retain];
        unsigned hits=++VM27SurfaceTextureHitsV1;
        pthread_mutex_unlock(&VM27SurfaceTextureMutexV1);
        if(hits<=2 || !(hits%256))dprintf(2,"[VM27DisplayTextureCacheV1] hit=%u boundedEntries=4 sameRetainedIOSurface=1 nativePresentAndACKUnchanged=1\n",hits);
        errno=incoming;return texture;
    }
    pthread_mutex_unlock(&VM27SurfaceTextureMutexV1);
    /* Creation/driver calls and releases happen outside the cache mutex. */
    errno=incoming;id texture=VM27SurfaceTextureOriginalIMP(device,selector,descriptor,surface,plane);
    int actualErrno=errno;if(!texture)return nil;
    key.texture=[texture retain];key.device=[device retain];CFRetain(surface);
    pthread_mutex_lock(&VM27SurfaceTextureMutexV1);
    unsigned slot=VM27SurfaceTextureNextV1++%4;
    VM27SurfaceTextureEntryV1 evicted=VM27SurfaceTexturesV1[slot];VM27SurfaceTexturesV1[slot]=key;
    unsigned misses=++VM27SurfaceTextureMissesV1;
    pthread_mutex_unlock(&VM27SurfaceTextureMutexV1);
    [evicted.texture release];[evicted.device release];if(evicted.surface)CFRelease(evicted.surface);
    if(misses<=4 || !(misses%256))dprintf(2,"[VM27DisplayTextureCacheV1] miss=%u width=%lu height=%lu originalCreateCalledOnce=1\n",misses,(unsigned long)key.width,(unsigned long)key.height);
    errno=actualErrno;return texture;
}

__attribute__((constructor)) static void VM27InstallOwnedDisplayTextureCacheV1(void) {
    int incoming=errno;
    @autoreleasepool {
        char path[4096]={0},canonical[4096]={0};uint32_t capacity=sizeof(path),status=0;
        if(getuid()!=501 || geteuid()!=501 || _NSGetExecutablePath(path,&capacity) ||
           capacity>sizeof(path) || !memchr(path,0,sizeof(path)) || !realpath(path,canonical) ||
           strcmp(canonical,PVGChildPathV1)) {errno=incoming;return;}
        Dl_info pg={0};uint8_t uuid[16];
        unsigned mainMatches=0;
        BOOL admitted=!csops(getpid(),0,&status,sizeof(status)) &&
            (status&UINT32_C(0x04000001))==UINT32_C(0x04000001) && vm27_metal_device_array_profile_matches();
        for(uint32_t i=0;admitted && i<_dyld_image_count();i++) {
            const char *name=_dyld_get_image_name(i);
            if(name && !strcmp(name,PVGChildPathV1)) {
                if(++mainMatches!=1 || !PVGReadUUIDV1(_dyld_get_image_header(i),MH_EXECUTE,uuid) ||
                   memcmp(uuid,PVGChildUUIDV1,16))admitted=NO;
            }
            if(name && !strcmp(name,PVGImagePathV1)) {
                const void *header=_dyld_get_image_header(i);
                if(!PVGReadUUIDV1(header,MH_DYLIB,uuid) || memcmp(uuid,PVGImageUUIDV1,16))admitted=NO;
                else pg.dli_fbase=(void *)header;
            }
        }
        if(!admitted || mainMatches!=1 || !pg.dli_fbase) {errno=incoming;return;}
        id device=MTLCreateSystemDefaultDevice();Class cls=object_getClass(device);
        SEL selector=sel_registerName("newTextureWithDescriptor:iosurface:plane:");
        Method method=cls?class_getInstanceMethod(cls,selector):NULL;
        char result[32]={0},types[5][64]={{0}};
        if(method && method_getNumberOfArguments(method)==5) {
            method_getReturnType(method,result,sizeof(result));
            for(unsigned i=0;i<5;i++)method_getArgumentType(method,i,types[i],sizeof(types[i]));
        }
        IMP original=method?method_getImplementation(method):NULL;Dl_info driver={0};
        static const uint8_t driverUUID[16]={0xb0,0xa1,0x68,0x66,0x30,0x77,0x32,0xa2,0xb7,0x4f,0xf2,0x8e,0xb0,0x41,0x1e,0xb4};
        BOOL valid=original && !strcmp(result,"@") && !strcmp(types[0],"@") && !strcmp(types[1],":") &&
            !strcmp(types[2],"@") && !strcmp(types[3],@encode(IOSurfaceRef)) && !strcmp(types[4],@encode(NSUInteger)) &&
            dladdr(ptrauth_strip((void *)original,ptrauth_key_function_pointer),&driver) && driver.dli_fname &&
            !strcmp(driver.dli_fname,"/System/Library/Extensions/AGXMetalG14G.bundle/AGXMetalG14G") &&
            PVGReadUUIDV1(driver.dli_fbase,MH_DYLIB,uuid) && !memcmp(uuid,driverUUID,16);
        if(!valid) {
            dprintf(2,"[VM27DisplayTextureCacheV1] installed=0 originalMetalMethodsUnchanged=1 type=%s expectedIOSurface=%s\n",method?method_getTypeEncoding(method):"missing",@encode(IOSurfaceRef));
            [device release];errno=incoming;return;
        }
        VM27SurfaceTextureOriginalIMP=(VM27SurfaceTextureOriginalV1)original;
        VM27SurfaceTextureDeviceV1=device;VM27SurfaceTextureDeviceClassV1=cls;
        VM27SurfaceTextureSelectorV1=selector;VM27SurfaceTextureCallerV1=(uintptr_t)pg.dli_fbase+0x27b94;
        VM27SurfaceTexturePIDV1=getpid();
        /* Add an own-class override when inherited; otherwise replace only
         * this process's already-present concrete device implementation. */
        if(!class_addMethod(cls,selector,(IMP)VM27SurfaceTextureCreateV1,method_getTypeEncoding(method))) {
            IMP replaced=method_setImplementation(method,(IMP)VM27SurfaceTextureCreateV1);
            if(replaced!=original) {
                method_setImplementation(method,replaced);VM27SurfaceTexturePIDV1=0;
                [device release];VM27SurfaceTextureDeviceV1=nil;errno=incoming;return;
            }
        }
        dprintf(2,"[VM27DisplayTextureCacheV1] installed=1 ownVMMPID=%d exactPGCallerRVA=0x27b94 boundedEntries=4 originalGPUCommandsAndCompletionUnchanged=1\n",(int)getpid());
    }
    errno=incoming;
}
