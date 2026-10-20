#!/usr/bin/env python3
"""Actual macOS IOSurface and CGImage tests of the frozen V4 copy helper only."""
import argparse,hashlib,json,pathlib,subprocess,sys
sys.dont_write_bytecode=True
R=pathlib.Path(__file__).resolve().parents[3];N=R/'DeviceDiagnostics/2026-10-08-full-macos27-cpu-vmm';S=R/'VirtualMac/vz/host'
def pin(p):
 p=pathlib.Path(p).resolve();b=p.read_bytes();return dict(path=str(p),bytes=len(b),sha256=hashlib.sha256(b).hexdigest())
def main():
 ap=argparse.ArgumentParser();ap.add_argument('--output',required=True,type=pathlib.Path);a=ap.parse_args();o=a.output.resolve();assert o.parent==N and not o.exists()
 src=S/'vm27_uikit_guest_display_v4.mm';assert pin(src)['sha256']=='d510c5ef9f440b6890f7bf306d53659bdf0ec0317c7bf0538bc57a2e7bb709b0'
 text=src.read_text();body=text[text.index('static NSError *BitmapErrorV4'):text.index('@interface VM27UIKitBitmapDisplayV4')];o.mkdir(mode=0o700)
 head='#import <Foundation/Foundation.h>\n#import <IOSurface/IOSurface.h>\n#import <CoreGraphics/CoreGraphics.h>\n#include <stdint.h>\n#include <stdio.h>\n#include <string.h>\n#include <stdlib.h>\n'
 test=r'''
static unsigned checks;
static void Require(BOOL yes,const char *message) {checks++;if(!yes){fprintf(stderr,"FAIL: %s\n",message);exit(1);}}
static IOSurfaceRef Surface(size_t width,size_t height,OSType format) {
 NSDictionary *properties=@{(__bridge NSString*)kIOSurfaceWidth:@(width),(__bridge NSString*)kIOSurfaceHeight:@(height),
   (__bridge NSString*)kIOSurfaceBytesPerElement:@4,(__bridge NSString*)kIOSurfacePixelFormat:@(format)};
 IOSurfaceRef s=IOSurfaceCreate((__bridge CFDictionaryRef)properties);Require(s!=NULL,"actual IOSurface creation");return s;
}
static void Write(IOSurfaceRef surface,uint8_t first) {
 Require(IOSurfaceLock(surface,0,NULL)==KERN_SUCCESS,"actual write lock");
 uint8_t *base=(uint8_t*)IOSurfaceGetBaseAddress(surface);size_t count=IOSurfaceGetBytesPerRow(surface)*IOSurfaceGetHeight(surface);
 for(size_t i=0;i<count;i++)base[i]=(uint8_t)(first+i);
 Require(IOSurfaceUnlock(surface,0,NULL)==KERN_SUCCESS,"actual write unlock");
}
int main(void) {@autoreleasepool {
 IOSurfaceRef s=Surface(4,2,0x42475241);Write(s,7);size_t width=0,height=0;BOOL changed=NO,unresolved=NO;NSError *error=nil;
 CGImageRef image=CopyBitmapImageV4(s,&width,&height,&changed,&unresolved,&error);
 Require(image && width==4 && height==2 && !changed && !unresolved && !error,"actual valid BGRA snapshot");
 Require(CGImageGetWidth(image)==4 && CGImageGetHeight(image)==2 && CGImageGetBitsPerComponent(image)==8 && CGImageGetBitsPerPixel(image)==32 && CGImageGetAlphaInfo(image)==kCGImageAlphaNoneSkipFirst,"real CGImage shape and opaque BGRA declaration");
 CFDataRef copied=CGDataProviderCopyData(CGImageGetDataProvider(image));Require(copied!=NULL,"real CGDataProvider copied data");
 size_t count=IOSurfaceGetBytesPerRow(s)*2;Require((size_t)CFDataGetLength(copied)==count,"real copied stride retained");
 const UInt8 *bytes=CFDataGetBytePtr(copied);for(size_t i=0;i<count;i++)Require(bytes[i]==(uint8_t)(7+i),"actual original surface bytes copied");
 Write(s,99);CFDataRef after=CGDataProviderCopyData(CGImageGetDataProvider(image));Require(after && CFEqual(after,copied),"image data independent of source mutation after unlock");
 CFRelease(after);CFRelease(copied);CGImageRelease(image);CFRelease(s);
 IOSurfaceRef wrong=Surface(4,2,0x52474241);error=nil;image=CopyBitmapImageV4(wrong,&width,&height,&changed,&unresolved,&error);
 Require(!image && error && [error.userInfo[@"stage"] isEqual:@"surface-profile"] && !unresolved,"real unsupported format rejected");
 Require(IOSurfaceLock(wrong,0,NULL)==KERN_SUCCESS && IOSurfaceUnlock(wrong,0,NULL)==KERN_SUCCESS,"rejected format leaves no lock held");CFRelease(wrong);
 IOSurfaceRef large=Surface(8193,1,0x42475241);error=nil;image=CopyBitmapImageV4(large,&width,&height,&changed,&unresolved,&error);
 Require(!image && error && [error.userInfo[@"stage"] isEqual:@"surface-profile"] && !unresolved,"real surface over dimension bound rejected");CFRelease(large);
 error=nil;image=CopyBitmapImageV4(NULL,&width,&height,&changed,&unresolved,&error);
 Require(!image && error && [error.userInfo[@"stage"] isEqual:@"surface-type"],"null surface refused before native lock");
 printf("actual macOS IOSurface/CGImage copy tests passed; checks=%u\n",checks);
 return 0;
}}
'''
 generated=o/'actual-copy-tests.mm';generated.write_text(head+body+test);commands=[]
 for variant,flags in [('normal',[]),('asan-ubsan',['-fsanitize=address,undefined','-fno-omit-frame-pointer'])]:
  exe=o/(variant+'.test');args=['xcrun','clang++','-O1','-fobjc-arc','-fblocks','-std=c++17','-Wall','-Wextra','-Werror']+flags+[str(generated),'-framework','Foundation','-framework','IOSurface','-framework','CoreGraphics','-o',str(exe)]
  for label,argv in [(variant+'-compile',args),(variant+'-run',[str(exe)])]:
   run=subprocess.run(argv,capture_output=True);(o/(label+'.stdout')).write_bytes(run.stdout);(o/(label+'.stderr')).write_bytes(run.stderr);commands.append(dict(label=label,argv=argv,exit=run.returncode));assert run.returncode==0,(label,run.stderr.decode())
 report=dict(schema='Frozen DisplayV4 helper actual macOS public IOSurface/CGImage finite tests',source=pin(src),helperSliceWholeBytesFromFrozenSource=True,generatedTest=pin(generated),commands=commands,actualSourceIOSurfaceDataCopied=True,actualCFDataProviderLifetimeIndependentAfterSurfaceMutation=True,actualFormatAndDimensionRejectionsTested=True,actualFailureUnlockRetainedPathExecuted=False,actualCATransactionOrUIKitExecuted=False,actualGenuineGuestFrames=False,deviceOperations=0,findings=[])
 (o/'report.json').write_text(json.dumps(report,indent=2)+'\n');rows=[pin(p)for p in o.iterdir()if p.is_file()]+[pin(src),pin(__file__)];(o/'freeze.json').write_text(json.dumps(dict(files=rows,deviceOperations=0),indent=2)+'\n');print(json.dumps(dict(report=pin(o/'report.json'),freeze=pin(o/'freeze.json'))))
if __name__=='__main__':main()
