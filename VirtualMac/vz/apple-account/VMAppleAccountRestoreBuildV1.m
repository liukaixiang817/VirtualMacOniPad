// Read the actual BuildManifest using the system ZIP64 reader. Image filenames
// and catalog labels are hints, not authority for enabling a kernel profile.
#import "VMAppleAccountProfileV1.h"
#include <dlfcn.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <unistd.h>

// libarchive's public C ABI. The iOS SDK provides libarchive.2.tbd but omits
// archive.h. Resolve only these stable public functions from the system image.
// https://github.com/libarchive/libarchive/blob/master/libarchive/archive.h
typedef struct {
    void *library;
    void *(*create)(void);
    int (*zip)(void *);
    int (*openFD)(void *, int, size_t);
    int (*next)(void *, void **);
    const char *(*name)(void *);
    int64_t (*size)(void *);
    ssize_t (*read)(void *, void *, size_t);
    int (*skip)(void *);
    int (*destroy)(void *);
} AccountArchiveV1;

static AccountArchiveV1 Archive;
static BOOL ArchiveReady;
static void LoadArchive(void) {
    Archive.library = dlopen("/usr/lib/libarchive.2.dylib", RTLD_NOW | RTLD_LOCAL);
    if (!Archive.library) return;
#define LOAD(field, symbol) Archive.field = (__typeof__(Archive.field))dlsym(Archive.library, symbol)
    LOAD(create, "archive_read_new");
    LOAD(zip, "archive_read_support_format_zip_seekable");
    LOAD(openFD, "archive_read_open_fd");
    LOAD(next, "archive_read_next_header");
    LOAD(name, "archive_entry_pathname");
    LOAD(size, "archive_entry_size");
    LOAD(read, "archive_read_data");
    LOAD(skip, "archive_read_data_skip");
    LOAD(destroy, "archive_read_free");
#undef LOAD
    ArchiveReady = Archive.create && Archive.zip && Archive.openFD && Archive.next &&
        Archive.name && Archive.size && Archive.read && Archive.skip && Archive.destroy;
}
static NSDictionary *Manifest(int fd) {
    void *reader = Archive.create();
    if (!reader) return nil;
    NSDictionary *manifest = nil;
    @try {
        if (Archive.zip(reader) || Archive.openFD(reader, fd, 65536)) return nil;
        unsigned count = 0, matches = 0;
        int status;
        void *entry = NULL;
        while ((status = Archive.next(reader, &entry)) == 0 && ++count <= 65536) {
            const char *name = Archive.name(entry);
            if (!name || strcmp(name, "BuildManifest.plist")) {
                if (Archive.skip(reader) < 0) return nil;
                continue;
            }
            if (++matches != 1) return nil;
            int64_t size = Archive.size(entry);
            // Current universal restore manifests contain all supported Mac
            // board identities and exceed 19 MiB. Keep a bound above those
            // actual manifests rather than rejecting genuine restore media.
            if (size <= 0 || size > 64 * 1024 * 1024) return nil;
            NSMutableData *data = [NSMutableData dataWithLength:(NSUInteger)size];
            NSUInteger at = 0;
            while (at < data.length) {
                ssize_t n = Archive.read(reader, (uint8_t *)data.mutableBytes + at, data.length - at);
                if (n <= 0) return nil;
                at += (NSUInteger)n;
            }
            uint8_t extra;
            if (Archive.read(reader, &extra, 1) != 0) return nil;
            id value = [NSPropertyListSerialization propertyListWithData:data options:NSPropertyListImmutable format:NULL error:nil];
            if (![value isKindOfClass:NSDictionary.class]) return nil;
            manifest = value;
        }
        if (status != 1 || count > 65536 || matches != 1) return nil;
    } @finally {
        Archive.destroy(reader);
    }
    return manifest;
}
NSString *VMAppleAccountRestoreBuildV1(NSURL *url, NSError **error) {
    static dispatch_once_t once;
    dispatch_once(&once, ^{ LoadArchive(); });
    int fd = url.isFileURL ? open(url.path.fileSystemRepresentation, O_RDONLY | O_NOFOLLOW | O_CLOEXEC) : -1;
    struct stat before, after;
    BOOL valid = ArchiveReady && fd >= 0 && !fstat(fd, &before) && S_ISREG(before.st_mode) &&
        before.st_size >= 1024 * 1024 && (uint64_t)before.st_size <= (UINT64_C(128) << 30);
    NSDictionary *manifest = valid ? Manifest(fd) : nil;
    valid = valid && !fstat(fd, &after) && before.st_dev == after.st_dev && before.st_ino == after.st_ino &&
        before.st_size == after.st_size && before.st_mtimespec.tv_sec == after.st_mtimespec.tv_sec &&
        before.st_mtimespec.tv_nsec == after.st_mtimespec.tv_nsec;
    if (fd >= 0) close(fd);
    NSString *build = manifest[@"ProductBuildVersion"];
    if (!valid || ![build isKindOfClass:NSString.class] || !build.length || build.length >= 16 ||
        [build rangeOfCharacterFromSet:[[NSCharacterSet alphanumericCharacterSet] invertedSet]].location != NSNotFound) {
        if (error) *error = [NSError errorWithDomain:@"VMAppleAccountRestoreBuildV1" code:1
            userInfo:@{NSLocalizedDescriptionKey:@"The restore image's BuildManifest could not be verified."}];
        return nil;
    }
    return build;
}
