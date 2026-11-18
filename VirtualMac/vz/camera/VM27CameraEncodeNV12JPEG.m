#import "VM27CameraFrame.h"
#import <Accelerate/Accelerate.h>
#import <ImageIO/ImageIO.h>

static CGImageRef CopyNV12Image(CVPixelBufferRef pixels, CGColorSpaceRef colorSpace) CF_RETURNS_RETAINED;
static CGImageRef CopyNV12Image(CVPixelBufferRef pixels, CGColorSpaceRef colorSpace) {
    size_t width = CVPixelBufferGetWidth(pixels), height = CVPixelBufferGetHeight(pixels);
    if (CVPixelBufferGetPixelFormatType(pixels) != kCVPixelFormatType_420YpCbCr8BiPlanarVideoRange ||
        CVPixelBufferGetPlaneCount(pixels) != 2 || width < 2 || height < 2 || width > 1920 || height > 1920 ||
        ((width | height) & 1) || CVPixelBufferGetBytesPerRowOfPlane(pixels, 0) < width ||
        CVPixelBufferGetBytesPerRowOfPlane(pixels, 1) < width ||
        CVPixelBufferGetHeightOfPlane(pixels, 0) != height || CVPixelBufferGetHeightOfPlane(pixels, 1) != height / 2)
        return NULL;

    const vImage_YpCbCrToARGBMatrix *matrix = kvImage_YpCbCrToARGBMatrix_ITU_R_709_2;
    CFTypeRef attachment = CVBufferCopyAttachment(pixels, kCVImageBufferYCbCrMatrixKey, NULL);
    if (attachment) {
        if (CFEqual(attachment, kCVImageBufferYCbCrMatrix_ITU_R_601_4))
            matrix = kvImage_YpCbCrToARGBMatrix_ITU_R_601_4;
        CFRelease(attachment);
    }
    const vImage_YpCbCrPixelRange range = {16, 128, 235, 240, 235, 16, 240, 16};
    vImage_YpCbCrToARGB conversion;
    if (vImageConvert_YpCbCrToARGB_GenerateConversion(matrix, &range, &conversion,
            kvImage420Yp8_CbCr8, kvImageARGB8888, kvImageNoFlags) != kvImageNoError) return NULL;

    NSMutableData *rgb = [NSMutableData dataWithLength:width * height * 4];
    if (CVPixelBufferLockBaseAddress(pixels, kCVPixelBufferLock_ReadOnly) != kCVReturnSuccess) return NULL;
    const vImage_Buffer luma = {
        CVPixelBufferGetBaseAddressOfPlane(pixels, 0), height, width, CVPixelBufferGetBytesPerRowOfPlane(pixels, 0),
    };
    const vImage_Buffer chroma = {
        CVPixelBufferGetBaseAddressOfPlane(pixels, 1), height / 2, width / 2, CVPixelBufferGetBytesPerRowOfPlane(pixels, 1),
    };
    const vImage_Buffer destination = {rgb.mutableBytes, height, width, width * 4};
    const uint8_t bgra[4] = {3, 2, 1, 0};
    vImage_Error error = vImageConvert_420Yp8_CbCr8ToARGB8888(&luma, &chroma, &destination,
        &conversion, bgra, 255, kvImageNoFlags);
    CVPixelBufferUnlockBaseAddress(pixels, kCVPixelBufferLock_ReadOnly);
    if (error != kvImageNoError) return NULL;

    CGDataProviderRef provider = CGDataProviderCreateWithCFData((__bridge CFDataRef)rgb);
    if (!provider) return NULL;
    CGImageRef image = CGImageCreate(width, height, 8, 32, width * 4, colorSpace,
        kCGBitmapByteOrder32Little | kCGImageAlphaNoneSkipFirst, provider, NULL, false, kCGRenderingIntentDefault);
    CGDataProviderRelease(provider);
    return image;
}

NSData *VM27CameraEncodeNV12JPEG(CVPixelBufferRef pixels, VM27CameraProfile profile, BOOL mirrored) {
    CMVideoDimensions dimensions = VM27CameraDimensions(profile);
    if (!pixels || !dimensions.width) return nil;
    CGColorSpaceRef colorSpace = CGColorSpaceCreateWithName(kCGColorSpaceSRGB);
    if (!colorSpace) return nil;
    CGImageRef image = CopyNV12Image(pixels, colorSpace);
    if (!image) { CGColorSpaceRelease(colorSpace); return nil; }

    size_t width = CGImageGetWidth(image), height = CGImageGetHeight(image);
    if (mirrored || width != (size_t)dimensions.width || height != (size_t)dimensions.height) {
        CGContextRef canvas = CGBitmapContextCreate(NULL, dimensions.width, dimensions.height, 8, 0,
            colorSpace, kCGBitmapByteOrder32Little | kCGImageAlphaNoneSkipFirst);
        if (!canvas) { CGImageRelease(image); CGColorSpaceRelease(colorSpace); return nil; }
        CGContextSetGrayFillColor(canvas, 0, 1);
        CGContextFillRect(canvas, CGRectMake(0, 0, dimensions.width, dimensions.height));
        if (mirrored) {
            CGContextTranslateCTM(canvas, dimensions.width, 0);
            CGContextScaleCTM(canvas, -1, 1);
        }
        CGFloat scale = MIN((CGFloat)dimensions.width / width, (CGFloat)dimensions.height / height);
        CGFloat fittedWidth = width * scale, fittedHeight = height * scale;
        CGContextDrawImage(canvas, CGRectMake((dimensions.width - fittedWidth) / 2,
            (dimensions.height - fittedHeight) / 2, fittedWidth, fittedHeight), image);
        CGImageRelease(image);
        image = CGBitmapContextCreateImage(canvas);
        CGContextRelease(canvas);
    }
    CGColorSpaceRelease(colorSpace);
    if (!image) return nil;

    NSMutableData *jpeg = [NSMutableData data];
    CGImageDestinationRef destination = CGImageDestinationCreateWithData((__bridge CFMutableDataRef)jpeg,
        CFSTR("public.jpeg"), 1, NULL);
    if (!destination) { CGImageRelease(image); return nil; }
    CGImageDestinationAddImage(destination, image, (__bridge CFDictionaryRef)@{
        (__bridge NSString *)kCGImageDestinationLossyCompressionQuality: @0.9,
    });
    BOOL complete = CGImageDestinationFinalize(destination);
    CFRelease(destination);
    CGImageRelease(image);
    return complete && jpeg.length && jpeg.length <= VM27CameraMaxJPEGBytes ? jpeg : nil;
}
