#import "VM27CameraFrame.h"
#import <ImageIO/ImageIO.h>

CMVideoDimensions VM27CameraDimensions(VM27CameraProfile profile) {
    switch (profile) {
        case VM27CameraProfile480p: return (CMVideoDimensions){640, 480};
        case VM27CameraProfile720p: return (CMVideoDimensions){1280, 720};
        case VM27CameraProfile1080p: return (CMVideoDimensions){1920, 1080};
    }
    return (CMVideoDimensions){0, 0};
}

NSData *VM27CameraEncodeJPEG(CIContext *context, CIImage *image,
                            VM27CameraProfile profile, BOOL mirrored) {
    CMVideoDimensions dimensions = VM27CameraDimensions(profile);
    CGRect source = image.extent;
    if (!dimensions.width || CGRectIsEmpty(source) || CGRectIsInfinite(source)) return nil;

    CGRect target = CGRectMake(0, 0, dimensions.width, dimensions.height);
    CGFloat scale = MIN(target.size.width / source.size.width, target.size.height / source.size.height);
    CGFloat x = (target.size.width - source.size.width * scale) / 2 - source.origin.x * scale;
    CGFloat y = (target.size.height - source.size.height * scale) / 2 - source.origin.y * scale;
    CIImage *fitted = [image imageByApplyingTransform:CGAffineTransformMake(scale, 0, 0, scale, x, y)];
    if (mirrored) {
        CGAffineTransform flip = CGAffineTransformMake(-1, 0, 0, 1, target.size.width, 0);
        fitted = [fitted imageByApplyingTransform:flip];
    }
    CIImage *black = [[CIImage imageWithColor:CIColor.blackColor] imageByCroppingToRect:target];
    CIImage *frame = [[fitted imageByCompositingOverImage:black] imageByCroppingToRect:target];
    CGColorSpaceRef rgb = CGColorSpaceCreateWithName(kCGColorSpaceSRGB);
    if (!rgb) return nil;
    NSData *jpeg = [context JPEGRepresentationOfImage:frame colorSpace:rgb options:@{
        (__bridge NSString *)kCGImageDestinationLossyCompressionQuality: @0.9,
    }];
    CGColorSpaceRelease(rgb);
    return jpeg.length && jpeg.length <= VM27CameraMaxJPEGBytes ? jpeg : nil;
}

static CGImageRef CopyFrameImage(NSData *data, CMVideoDimensions expected) {
    if (!data.length || data.length > VM27CameraMaxJPEGBytes) return NULL;
    CGImageSourceRef source = CGImageSourceCreateWithData((__bridge CFDataRef)data, NULL);
    if (!source) return NULL;
    CGImageRef image = NULL;
    if ([(__bridge NSString *)CGImageSourceGetType(source) isEqualToString:@"public.jpeg"] &&
        CGImageSourceGetCount(source) == 1 && CGImageSourceGetStatus(source) == kCGImageStatusComplete) {
        NSDictionary *properties = CFBridgingRelease(CGImageSourceCopyPropertiesAtIndex(source, 0, NULL));
        if ([properties[(__bridge NSString *)kCGImagePropertyPixelWidth] intValue] == expected.width &&
            [properties[(__bridge NSString *)kCGImagePropertyPixelHeight] intValue] == expected.height)
            image = CGImageSourceCreateImageAtIndex(source, 0, NULL);
    }
    CFRelease(source);
    return image;
}

CVPixelBufferRef VM27CameraCreateOutput(CIContext *context, NSData *jpeg, VM27CameraProfile profile) {
    CMVideoDimensions dimensions = VM27CameraDimensions(profile);
    if (!dimensions.width) return NULL;
    CVPixelBufferRef surface = NULL;
    NSDictionary *attributes = @{(__bridge NSString *)kCVPixelBufferIOSurfacePropertiesKey: @{}};
    if (CVPixelBufferCreate(kCFAllocatorDefault, dimensions.width, dimensions.height, kCVPixelFormatType_32BGRA,
                            (__bridge CFDictionaryRef)attributes, &surface) != kCVReturnSuccess)
        return NULL;

    CGColorSpaceRef rgb = CGColorSpaceCreateWithName(kCGColorSpaceSRGB);
    if (!rgb) { CVPixelBufferRelease(surface); return NULL; }
    CGImageRef decoded = CopyFrameImage(jpeg, dimensions);
    CIImage *frame = decoded ? [CIImage imageWithCGImage:decoded] : [CIImage imageWithColor:CIColor.blackColor];
    [context render:frame toCVPixelBuffer:surface
             bounds:CGRectMake(0, 0, dimensions.width, dimensions.height) colorSpace:rgb];
    CGColorSpaceRelease(rgb);
    if (decoded) CGImageRelease(decoded);
    return surface;
}
