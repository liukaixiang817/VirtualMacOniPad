// Bounded IMG4 editor for disposable guest boot research. Untouched DER
// fields (including the personalized manifest and PAYP) remain byte-identical.
#import <Foundation/Foundation.h>
#include <CommonCrypto/CommonDigest.h>
#include <compression.h>

static NSString *radioSHA(NSData *data) {
    uint8_t digest[CC_SHA256_DIGEST_LENGTH]; CC_SHA256(data.bytes,(CC_LONG)data.length,digest);
    NSMutableString *s=[NSMutableString string];
    for (unsigned i=0;i<sizeof(digest);++i) [s appendFormat:@"%02x",digest[i]];
    return s;
}
static NSData *radioBody(NSData *element, NSUInteger *consumed) {
    if (element.length<2 || element.length>128*1024*1024) return nil;
    const uint8_t *p=element.bytes; NSUInteger header=2,length=p[1];
    if ((p[0]&31)==31 || length==128) return nil;
    if (length&128) {
        NSUInteger count=length&127;
        if (!count || count>4 || header+count>element.length) return nil;
        length=0; for (NSUInteger i=0;i<count;++i) length=(length<<8)|p[header++];
    }
    if (length>element.length-header) return nil;
    if (consumed) *consumed=header+length;
    return [element subdataWithRange:NSMakeRange(header,length)];
}
static NSArray<NSData *> *radioChildren(NSData *element) {
    if (!element.length || ((const uint8_t *)element.bytes)[0]!=0x30) return nil;
    NSUInteger total=0; NSData *body=radioBody(element,&total);
    if (!body || total!=element.length) return nil;
    NSMutableArray *rows=[NSMutableArray array]; NSUInteger at=0;
    while (at<body.length) {
        if (rows.count>=64) return nil;
        NSData *remaining=[body subdataWithRange:NSMakeRange(at,body.length-at)];
        NSUInteger length=0; if (!radioBody(remaining,&length) || !length) return nil;
        [rows addObject:[remaining subdataWithRange:NSMakeRange(0,length)]]; at+=length;
    }
    return rows;
}
static BOOL radioString(NSData *element, const char *s) {
    if (!element.length || ((const uint8_t *)element.bytes)[0]!=0x16) return NO;
    NSData *body=radioBody(element,NULL);
    return body.length==strlen(s) && !memcmp(body.bytes,s,body.length);
}
static NSData *radioEncode(uint8_t tag, NSData *body) {
    if (body.length>128*1024*1024) return nil;
    NSMutableData *result=[NSMutableData dataWithBytes:&tag length:1];
    uint8_t size[5]; NSUInteger count=0,n=body.length;
    if (n<128) { uint8_t small=(uint8_t)n; [result appendBytes:&small length:1]; }
    else {
        while (n) { size[4-count++]=(uint8_t)n; n>>=8; }
        uint8_t prefix=128|(uint8_t)count; [result appendBytes:&prefix length:1];
        [result appendBytes:size+5-count length:count];
    }
    [result appendData:body]; return result;
}
static NSData *radioJoin(NSArray<NSData *> *parts) {
    NSMutableData *data=[NSMutableData data];
    for (NSData *part in parts) { if (data.length+part.length>128*1024*1024) return nil; [data appendData:part]; }
    return radioEncode(0x30,data);
}
static NSDictionary *radioImage(NSData *data) {
    NSArray *outer=radioChildren(data); if (outer.count<2) return nil;
    BOOL wrapped=radioString(outer[0],"IMG4");
    NSArray *parts=wrapped?radioChildren(outer[1]):outer;
    if (parts.count<4 || !radioString(parts[0],"IM4P") ||
        ((const uint8_t *)[parts[3] bytes])[0]!=4) return nil;
    NSData *payload=radioBody(parts[3],NULL); if (!payload) return nil;
    BOOL compressed=payload.length>=4 && !memcmp(payload.bytes,"bvx",3);
    if (compressed) {
        // IM4P declares the decoded size. In particular, do not allocate a
        // 128 MB scratch buffer for a sub-megabyte iPad bootloader payload.
        if (parts.count<5) return nil;
        NSArray *metadata=radioChildren(parts[4]);
        if (metadata.count!=2) return nil;
        uint64_t values[2]={0,0};
        for (unsigned i=0;i<2;++i) {
            if (((const uint8_t *)[metadata[i] bytes])[0]!=2) return nil;
            NSData *integer=radioBody(metadata[i],NULL);
            if (!integer.length||integer.length>8) return nil;
            for (NSUInteger j=0;j<integer.length;++j) values[i]=(values[i]<<8)|((const uint8_t *)integer.bytes)[j];
        }
        if (values[0]!=1||!values[1]||values[1]>=128*1024*1024) return nil;
        NSMutableData *decoded=[NSMutableData dataWithLength:(NSUInteger)values[1]];
        size_t length=compression_decode_buffer(decoded.mutableBytes,decoded.length,payload.bytes,payload.length,NULL,COMPRESSION_LZFSE);
        if (length!=values[1]) return nil;
        decoded.length=length; payload=decoded;
    }
    return @{@"outer":outer,@"parts":parts,@"payload":payload,@"wrapped":@(wrapped),@"compressed":@(compressed)};
}
static NSData *radioReplace(NSDictionary *image, NSData *payload) {
    if (!image || payload.length!=[image[@"payload"] length]) return nil;
    NSMutableArray *parts=[image[@"parts"] mutableCopy];
    parts[3]=radioEncode(4,payload); if (!parts[3]) return nil;
    if ([image[@"compressed"] boolValue]) {
        if (parts.count<5) return nil;
        NSArray *metadata=radioChildren(parts[4]);
        if (metadata.count!=2) return nil;
        uint64_t values[2]={0,0};
        for (unsigned i=0;i<2;++i) {
            if (((const uint8_t *)[metadata[i] bytes])[0]!=2) return nil;
            NSData *integer=radioBody(metadata[i],NULL); if (!integer.length || integer.length>8) return nil;
            for (NSUInteger j=0;j<integer.length;++j) values[i]=(values[i]<<8)|((const uint8_t *)integer.bytes)[j];
        }
        if (values[0]!=1 || values[1]!=payload.length) return nil;
        [parts removeObjectAtIndex:4];
    }
    NSData *result=radioJoin(parts);
    if ([image[@"wrapped"] boolValue]) {
        NSMutableArray *outer=[image[@"outer"] mutableCopy]; outer[1]=result; result=radioJoin(outer);
    }
    NSDictionary *check=radioImage(result);
    if (!check || ![check[@"payload"] isEqual:payload] || [check[@"compressed"] boolValue] ||
        ![check[@"parts"] isEqual:parts]) return nil;
    if ([image[@"wrapped"] boolValue]) {
        NSArray *before=image[@"outer"],*after=check[@"outer"];
        if (before.count!=after.count) return nil;
        for (NSUInteger i=2;i<before.count;++i) if (![before[i] isEqual:after[i]]) return nil;
    }
    return result;
}
