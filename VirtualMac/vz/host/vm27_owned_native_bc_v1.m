/* Process-local BC frontend for the independent native macOS 27 GPU task.
 * AGX consumes the original compressed bytes and original BC format numbers.
 * Surrogates are used only by the older generic Metal geometry/validation API.
 * No backend-13 transport, capability overrides, or kernel changes are used. */
#import <Foundation/Foundation.h>
#import <Metal/Metal.h>
#import <objc/runtime.h>
#import <objc/message.h>
#import <dlfcn.h>
#import "native_bc_texture_support.h"

typedef struct { uint64_t words[7]; } BCFormatInfo;
typedef void (*BCHook)(void *, void *, void **);
static BCFormatInfo (*OriginalInfo)(id, MTLPixelFormat);
static void (*OriginalViewValidation)(id,id,MTLPixelFormat,MTLTextureType,
    NSUInteger,NSUInteger,NSUInteger,NSUInteger,BOOL);
static void (*OriginalSetFormat)(id,SEL,MTLPixelFormat);
static BOOL (*OriginalValidateDescriptor)(id,SEL,id);
static id (*OriginalNewTexture)(id,SEL,id);
static id (*OriginalHeapTexture)(id,SEL,id);
static id (*OriginalHeapTextureOffset)(id,SEL,id,NSUInteger);
static id (*OriginalView)(id,SEL,MTLPixelFormat);
static id (*OriginalViewRanges)(id,SEL,MTLPixelFormat,MTLTextureType,NSRange,NSRange);
static id (*OriginalViewSwizzle)(id,SEL,MTLPixelFormat,MTLTextureType,NSRange,NSRange,MTLTextureSwizzleChannels);
static BOOL Installed;

static void *CheckedIvar(id object, const char *name, const char *encoding, size_t size) {
    Ivar ivar = object ? class_getInstanceVariable(object_getClass(object), name) : NULL;
    if (!ivar || strcmp(ivar_getTypeEncoding(ivar), encoding)) return NULL;
    ptrdiff_t offset = ivar_getOffset(ivar);
    size_t total = class_getInstanceSize(object_getClass(object));
    if (offset < 0 || (size_t)offset > total || size > total-(size_t)offset) return NULL;
    return (uint8_t *)(void *)object + offset;
}
static MTLPixelFormat *FormatStorage(id texture) {
    return CheckedIvar(texture, "_pixelFormat", @encode(MTLPixelFormat), sizeof(MTLPixelFormat));
}
static BOOL *CompressedStorage(id texture) {
    BOOL *p = CheckedIvar(texture, "_isCompressed", @encode(BOOL), sizeof(BOOL));
    if (!p) p = CheckedIvar(texture, "_isCompressed", "c", 1);
    if (!p) p = CheckedIvar(texture, "_isCompressed", "B", 1);
    return p;
}
static id RestoreMetadata(id texture, MTLPixelFormat format) {
    if (!texture || !VZIsBCPixelFormat(format)) return texture;
    MTLPixelFormat *stored = FormatStorage(texture); BOOL *compressed = CompressedStorage(texture);
    if (!stored || !compressed) {
        fprintf(stderr,"[Independent27GPU] BC texture metadata ABI mismatch\n");
        [texture release]; return nil;
    }
    *stored = format; *compressed = YES;
    return texture;
}
static NSUInteger *DescriptorPrivate(id object) {
    return ((NSUInteger *(*)(id,SEL))objc_msgSend)(object,sel_registerName("descriptorPrivate"));
}
static void SetFormat(id self,SEL cmd,MTLPixelFormat format) {
    if (!VZIsBCPixelFormat(format)) { OriginalSetFormat(self,cmd,format); return; }
    // The layout was checked on a real descriptor before installing this method.
    NSUInteger *p = DescriptorPrivate(self);
    if (!p) [NSException raise:NSInternalInconsistencyException format:@"BC descriptor storage unavailable"];
    p[1] = format;
}
static BOOL ValidateDescriptor(id self,SEL cmd,id device) {
    NSUInteger *p = DescriptorPrivate(self);
    MTLPixelFormat format = p ? p[1] : MTLPixelFormatInvalid;
    if (!VZIsBCPixelFormat(format)) return OriginalValidateDescriptor(self,cmd,device);
    @try { p[1] = VZBCValidationSurrogate(format); return OriginalValidateDescriptor(self,cmd,device); }
    @finally { p[1] = format; }
}
static BCFormatInfo FormatInfo(id device, MTLPixelFormat format) {
    return OriginalInfo(device,VZIsBCPixelFormat(format)?VZBCValidationSurrogate(format):format);
}
static void ValidateView(id device,id texture,MTLPixelFormat format,MTLTextureType type,
    NSUInteger ls,NSUInteger lc,NSUInteger ss,NSUInteger sc,BOOL compressed) {
    MTLPixelFormat original = [texture pixelFormat];
    MTLPixelFormat *stored = FormatStorage(texture);
    if (!stored || !VZIsBCPixelFormat(original) || !VZIsBCPixelFormat(format)) {
        OriginalViewValidation(device,texture,format,type,ls,lc,ss,sc,compressed); return;
    }
    @try {
        *stored=VZBCValidationSurrogate(original);
        OriginalViewValidation(device,texture,VZBCValidationSurrogate(format),type,ls,lc,ss,sc,compressed);
    } @finally { *stored=original; }
}
static id NewTexture(id self,SEL cmd,id descriptor) {
    return RestoreMetadata(OriginalNewTexture(self,cmd,descriptor),[descriptor pixelFormat]);
}
static id HeapTexture(id self,SEL cmd,id descriptor) {
    return RestoreMetadata(OriginalHeapTexture(self,cmd,descriptor),[descriptor pixelFormat]);
}
static id HeapTextureOffset(id self,SEL cmd,id descriptor,NSUInteger offset) {
    return RestoreMetadata(OriginalHeapTextureOffset(self,cmd,descriptor,offset),[descriptor pixelFormat]);
}
static id NewView(id self,SEL cmd,MTLPixelFormat format) {
    return RestoreMetadata(OriginalView(self,cmd,format),format);
}
static id NewViewRanges(id self,SEL cmd,MTLPixelFormat format,MTLTextureType type,NSRange levels,NSRange slices) {
    return RestoreMetadata(OriginalViewRanges(self,cmd,format,type,levels,slices),format);
}
static id NewViewSwizzle(id self,SEL cmd,MTLPixelFormat format,MTLTextureType type,NSRange levels,NSRange slices,MTLTextureSwizzleChannels swizzle) {
    return RestoreMetadata(OriginalViewSwizzle(self,cmd,format,type,levels,slices,swizzle),format);
}
static BCHook LoadHook(void) {
    BCHook hook=(BCHook)dlsym(RTLD_DEFAULT,"MSHookFunction");
    if (hook) return hook;
    const char *paths[]={"/var/jb/usr/lib/libellekit.dylib","/var/jb/usr/lib/libhooker.dylib"};
    for (unsigned i=0;i<2;i++) {
        void *handle=dlopen(paths[i],RTLD_NOW|RTLD_LOCAL);
        if (handle && (hook=(BCHook)dlsym(handle,"MSHookFunction"))) return hook;
    }
    return NULL;
}
static IMP Replace(Class cls,SEL selector,IMP replacement) {
    Method method=class_getInstanceMethod(cls,selector); if (!method) return NULL;
    IMP original=method_getImplementation(method);
    // Add an override on the concrete class instead of changing an inherited
    // superclass method used by unrelated Metal resource classes.
    if (!class_addMethod(cls,selector,replacement,method_getTypeEncoding(method)))
        method_setImplementation(class_getInstanceMethod(cls,selector),replacement);
    return original;
}
__attribute__((visibility("hidden")))
BOOL VM27InstallNativeBCV1(id<MTLDevice> device) {
    static dispatch_once_t once;
    dispatch_once(&once, ^{
        BCHook hook=LoadHook();
        void *info=dlsym(RTLD_DEFAULT,"MTLPixelFormatGetInfoForDevice");
        void *validate=dlsym(RTLD_DEFAULT,"_mtlValidateArgumentsForTextureViewOnDevice");
        MTLTextureDescriptor *descriptor=[MTLTextureDescriptor texture2DDescriptorWithPixelFormat:MTLPixelFormatRGBA8Unorm width:4 height:4 mipmapped:NO];
        Class dc=object_getClass(descriptor);
        Method privateMethod=class_getInstanceMethod(dc,sel_registerName("descriptorPrivate"));
        Method validationMethod=class_getInstanceMethod(dc,sel_registerName("validateWithDevice:"));
        id texture=[device newTextureWithDescriptor:descriptor];
        MTLHeapDescriptor *hd=[MTLHeapDescriptor new];hd.size=16384;hd.storageMode=MTLStorageModePrivate;
        id heap=[device newHeapWithDescriptor:hd];[hd release];
        if (!hook || !info || !validate || !privateMethod || !validationMethod || !texture || !heap ||
            !FormatStorage(texture) || !CompressedStorage(texture) ||
            !DescriptorPrivate(descriptor) || DescriptorPrivate(descriptor)[1]!=MTLPixelFormatRGBA8Unorm ||
            !VZInstallNativeBCTextureSupport()) {
            fprintf(stderr,"[Independent27GPU] native BC bridge unavailable: frontend or driver ABI not admitted\n");
            [texture release];[heap release];return;
        }
        hook(info,(void *)FormatInfo,(void **)&OriginalInfo);
        hook(validate,(void *)ValidateView,(void **)&OriginalViewValidation);
        if (!OriginalInfo || !OriginalViewValidation) _exit(70);
        OriginalSetFormat=(void *)Replace(dc,@selector(setPixelFormat:),(IMP)SetFormat);
        OriginalValidateDescriptor=(void *)Replace(dc,sel_registerName("validateWithDevice:"),(IMP)ValidateDescriptor);
        OriginalNewTexture=(void *)Replace(object_getClass(device),@selector(newTextureWithDescriptor:),(IMP)NewTexture);
        OriginalHeapTexture=(void *)Replace(object_getClass(heap),@selector(newTextureWithDescriptor:),(IMP)HeapTexture);
        OriginalHeapTextureOffset=(void *)Replace(object_getClass(heap),@selector(newTextureWithDescriptor:offset:),(IMP)HeapTextureOffset);
        Class tc=object_getClass(texture);
        OriginalView=(void *)Replace(tc,@selector(newTextureViewWithPixelFormat:),(IMP)NewView);
        OriginalViewRanges=(void *)Replace(tc,@selector(newTextureViewWithPixelFormat:textureType:levels:slices:),(IMP)NewViewRanges);
        OriginalViewSwizzle=(void *)Replace(tc,@selector(newTextureViewWithPixelFormat:textureType:levels:slices:swizzle:),(IMP)NewViewSwizzle);
        Installed=OriginalSetFormat && OriginalValidateDescriptor && OriginalNewTexture && OriginalHeapTexture && OriginalView && OriginalViewRanges;
        [texture release];[heap release];
        if (!Installed) _exit(70);
        fprintf(stderr,"[Independent27GPU] native BC bridge active: original compressed bytes, native AGX format records, 8/16-byte block geometry\n");
    });
    return Installed;
}
