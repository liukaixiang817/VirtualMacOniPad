// Read-only, fixed temporary 24G90 guest probe. Exports public payload hashes
// and kernel version strings only; personalized IMG4 envelopes stay in guest.
#import <Foundation/Foundation.h>
#include <CommonCrypto/CommonDigest.h>
#include <compression.h>
#include <sys/stat.h>
#include <sys/sysctl.h>
#include <fcntl.h>
#include <unistd.h>

typedef struct { const uint8_t *p; size_t n; uint8_t tag; } Node;
static BOOL take(Node *input, Node *output) {
    if (input->n < 2) return NO;
    const uint8_t *p = input->p;
    size_t header = 2, length = p[1];
    if ((p[0] & 31) == 31 || length == 128) return NO;
    if (length & 128) {
        size_t count = length & 127;
        if (!count || count > 4 || input->n < 2 + count) return NO;
        length = 0;
        for (size_t i = 0; i < count; ++i) length = (length << 8) | p[header++];
    }
    if (length > input->n - header) return NO;
    *output = (Node){p + header, length, p[0]};
    input->p += header + length; input->n -= header + length;
    return YES;
}
static BOOL equals(Node n, const char *text) {
    return n.tag == 0x16 && n.n == strlen(text) && !memcmp(n.p, text, n.n);
}
static NSString *hash(const void *p, size_t length) {
    uint8_t digest[CC_SHA256_DIGEST_LENGTH]; CC_SHA256(p, (CC_LONG)length, digest);
    NSMutableString *s = [NSMutableString string];
    for (size_t i = 0; i < sizeof(digest); ++i) [s appendFormat:@"%02x", digest[i]];
    return s;
}
static NSDictionary *inspect(NSString *path, NSString *label) {
    int fd = open(path.fileSystemRepresentation, O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
    struct stat st;
    if (fd < 0) return @{@"label":label, @"opened":@NO};
    // Restore assets are installed mode 0666 on this guest. This probe only
    // hashes data; it does not trust, execute, or rewrite the inspected file.
    BOOL valid = !fstat(fd, &st) && S_ISREG(st.st_mode) && st.st_uid == 0 &&
        st.st_nlink == 1 && st.st_size > 0 && st.st_size <= 128 * 1024 * 1024;
    NSMutableData *data = valid ? [NSMutableData dataWithLength:(NSUInteger)st.st_size] : nil;
    size_t at = 0;
    while (valid && at < data.length) {
        ssize_t count = read(fd, (uint8_t *)data.mutableBytes + at, data.length - at);
        if (count <= 0) { valid = NO; break; } at += (size_t)count;
    }
    close(fd);
    if (!valid) return @{@"label":label, @"validFile":@NO};
    Node input = {data.bytes, data.length, 0}, root, name, im4p;
    if (!take(&input, &root) || input.n || root.tag != 0x30) return nil;
    Node fields = root;
    if (!take(&fields, &name)) return nil;
    if (equals(name, "IMG4")) {
        if (!take(&fields, &im4p) || im4p.tag != 0x30) return nil;
        fields = im4p;
        if (!take(&fields, &name)) return nil;
    }
    Node kind, description, payload;
    if (!equals(name, "IM4P") || !take(&fields, &kind) || kind.tag != 0x16 ||
        !take(&fields, &description) || description.tag != 0x16 ||
        !take(&fields, &payload) || payload.tag != 4) return nil;
    NSString *fourcc = [[NSString alloc] initWithBytes:kind.p length:kind.n encoding:NSASCIIStringEncoding];
    NSString *desc = [[NSString alloc] initWithBytes:description.p length:description.n encoding:NSASCIIStringEncoding];
    if (kind.n != 4 || ![@[@"krnl",@"rkrn",@"ibot",@"fuos"] containsObject:fourcc] ||
        !desc || description.n > 128) return nil;
    NSMutableData *decoded = nil;
    if (payload.n >= 4 && !memcmp(payload.p, "bvx", 3)) {
        decoded = [NSMutableData dataWithLength:128 * 1024 * 1024];
        size_t size = compression_decode_buffer(decoded.mutableBytes, decoded.length,
            payload.p, payload.n, NULL, COMPRESSION_LZFSE);
        if (!size || size >= decoded.length) return nil;
        decoded.length = size; payload.p = decoded.bytes; payload.n = size;
    }
    NSMutableArray *versions = [NSMutableArray array];
    const char *prefix = "Darwin Kernel Version";
    for (size_t offset = 0; offset + strlen(prefix) < payload.n; ++offset) {
        if (memcmp(payload.p + offset, prefix, strlen(prefix))) continue;
        size_t count = strnlen((const char *)payload.p + offset, MIN((size_t)256, payload.n - offset));
        if (count == 256 || count == payload.n - offset) continue;
        NSString *version = [[NSString alloc] initWithBytes:payload.p + offset length:count encoding:NSASCIIStringEncoding];
        if (version && versions.count < 4) [versions addObject:version];
    }
    return @{@"label":label, @"fourcc":fourcc, @"description":desc,
        @"publicPayloadSHA256":hash(payload.p,payload.n), @"decodedBytes":@(payload.n),
        @"kernelVersionStrings":versions, @"personalizedEnvelopeExported":@NO};
}
int main(int argc, const char **argv) { @autoreleasepool {
    (void)argv;
    NSDictionary *version = [NSDictionary dictionaryWithContentsOfFile:@"/System/Library/CoreServices/SystemVersion.plist"];
    char kernel[512] = {0}; size_t size = sizeof(kernel);
    if (argc != 1 || geteuid() || ![version[@"ProductBuildVersion"] isEqual:@"24G90"] ||
        sysctlbyname("kern.version",kernel,&size,NULL,0) || !strstr(kernel,"RADIO15_ARM64_VMAPPLE")) return 77;
    NSString *preboot = @"/System/Volumes/Preboot/D2DEF9D2-5B3D-4BDC-A473-E6958FE7E29C";
    NSString *boot = [preboot stringByAppendingPathComponent:@"boot/4E5E204AE9F945CEEB65FCC5D455CA9FC7A99C9EB29B4CDE7AB27EE9D60825B3DFCF60A8CCAB88F0F2F51AF8F800E6AA"];
    NSArray *paths = @[[boot stringByAppendingPathComponent:@"System/Library/Caches/com.apple.kernelcaches/kernelcache"],
        [preboot stringByAppendingPathComponent:@"restore/kernelcache.release.vma2"],
        [boot stringByAppendingPathComponent:@"usr/standalone/firmware/iBoot.img4"]];
    NSArray *labels = @[@"stockMainKernel",@"KcgenRestoreKernel",@"guestIBoot"];
    NSMutableArray *rows = [NSMutableArray array];
    for (NSUInteger i = 0; i < paths.count; ++i) {
        NSDictionary *row = inspect(paths[i],labels[i]); if (!row) return 65; [rows addObject:row];
    }
    NSData *json = [NSJSONSerialization dataWithJSONObject:@{@"schema":@1, @"readOnly":@YES,
        @"personalizedEnvelopesExported":@NO, @"payloads":rows} options:NSJSONWritingPrettyPrinted error:NULL];
    if (!json) return 65; fwrite(json.bytes,1,json.length,stdout); putchar('\n'); return 0;
} }
