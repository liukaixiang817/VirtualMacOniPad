#import "VM27ClipboardChannel_v1.h"
#include <sys/socket.h>
#include <fcntl.h>
#include <unistd.h>
#include <errno.h>
#include <arpa/inet.h>
NSArray<NSString *> *VM27ClipboardTypes(void) {
    return @[@"public.utf8-plain-text",@"public.utf16-external-plain-text",
        @"public.png",@"public.jpeg",@"public.tiff",@"public.rtf",
        @"public.html",@"public.url"];
}
BOOL VM27ClipboardValidateItems(id items) {
    if(![items isKindOfClass:NSArray.class] || [items count]>16)return NO;
    NSUInteger bytes=0;
    for(id item in items) {
        if(![item isKindOfClass:NSDictionary.class] || ![item count] || [item count]>8)return NO;
        for(id key in item) {
            if(![key isKindOfClass:NSString.class] || ![VM27ClipboardTypes() containsObject:key] ||
               ![item[key] isKindOfClass:NSData.class])return NO;
            NSUInteger length=[item[key] length];
            if(length>VM27_CLIPBOARD_MAX_BYTES-bytes)return NO;
            bytes+=length;
        }
    }
    return YES;
}
@implementation VM27ClipboardChannel {
    int _fd;
    dispatch_source_t _readSource,_writeSource;
    NSMutableData *_input;
    NSMutableArray<NSData *> *_output;
    NSUInteger _offset,_queued;
}
- (instancetype)initWithOwnedDescriptor:(int)descriptor {
    NSParameterAssert(NSThread.isMainThread);
    if((self=[super init])) {
        _fd=descriptor;
        int flags=fcntl(_fd,F_GETFL,0),one=1;
        if(_fd<0 || flags<0 || fcntl(_fd,F_SETFL,flags|O_NONBLOCK)<0 ||
           fcntl(_fd,F_SETFD,FD_CLOEXEC)<0 ||
           setsockopt(_fd,SOL_SOCKET,SO_NOSIGPIPE,&one,sizeof(one))<0) {
            if(_fd>=0)close(_fd);_fd=-1;return nil;
        }
        _input=[NSMutableData new];_output=[NSMutableArray new];
        _readSource=dispatch_source_create(DISPATCH_SOURCE_TYPE_READ,_fd,0,dispatch_get_main_queue());
        if(!_readSource){close(_fd);_fd=-1;return nil;}
        __weak typeof(self) weak=self;
        dispatch_source_set_event_handler(_readSource,^{[weak readAvailable];});
        dispatch_resume(_readSource);
    }
    return self;
}
- (void)close {
    NSAssert(NSThread.isMainThread,@"Clipboard channel must close on its queue");
    if(_fd<0)return;
    if(_readSource){dispatch_source_cancel(_readSource);_readSource=nil;}
    if(_writeSource){dispatch_source_cancel(_writeSource);_writeSource=nil;}
    close(_fd);_fd=-1;[_input setLength:0];[_output removeAllObjects];_offset=_queued=0;
    void(^callback)(void)=self.disconnected;self.received=nil;self.disconnected=nil;
    if(callback)callback();
}
- (void)readAvailable {
    if(_fd<0)return;
    uint8_t buffer[16384];
    for(unsigned turn=0;turn<8;++turn) {
        ssize_t n=recv(_fd,buffer,sizeof(buffer),0);
        if(n<0 && errno==EINTR)continue;
        if(n<0 && (errno==EAGAIN || errno==EWOULDBLOCK))break;
        if(n<=0){[self close];return;}
        [_input appendBytes:buffer length:(NSUInteger)n];
        while(_input.length>=4) {
            uint32_t be;memcpy(&be,_input.bytes,4);NSUInteger length=ntohl(be);
            if(!length || length>VM27_CLIPBOARD_MAX_BYTES){[self close];return;}
            if(_input.length<length+4)break;
            NSData *data=[_input subdataWithRange:NSMakeRange(4,length)];
            [_input replaceBytesInRange:NSMakeRange(0,length+4) withBytes:NULL length:0];
            NSPropertyListFormat format=0;NSError *error=nil;
            id value=[NSPropertyListSerialization propertyListWithData:data options:NSPropertyListImmutable format:&format error:&error];
            if(error || format!=NSPropertyListBinaryFormat_v1_0 || ![value isKindOfClass:NSDictionary.class] ||
               ![value[@"v"] isEqual:@1] || ![value[@"kind"] isKindOfClass:NSString.class]){[self close];return;}
            if(self.received)self.received(value);
            if(_fd<0)return;
        }
    }
}
- (BOOL)send:(NSDictionary *)message {
    NSAssert(NSThread.isMainThread,@"Clipboard send must execute on its queue");
    if(_fd<0)return NO;
    NSData *payload=[NSPropertyListSerialization dataWithPropertyList:message format:NSPropertyListBinaryFormat_v1_0 options:0 error:nil];
    if(!payload.length || payload.length>VM27_CLIPBOARD_MAX_BYTES ||
       _output.count>=8 || _queued+payload.length+4>2*VM27_CLIPBOARD_MAX_BYTES){[self close];return NO;}
    uint32_t length=htonl((uint32_t)payload.length);
    NSMutableData *frame=[NSMutableData dataWithBytes:&length length:4];[frame appendData:payload];
    [_output addObject:frame];_queued+=frame.length;
    if(!_writeSource) {
        _writeSource=dispatch_source_create(DISPATCH_SOURCE_TYPE_WRITE,_fd,0,dispatch_get_main_queue());
        if(!_writeSource){[self close];return NO;}
        __weak typeof(self) weak=self;
        dispatch_source_set_event_handler(_writeSource,^{[weak writeAvailable];});dispatch_resume(_writeSource);
    }
    return YES;
}
- (void)writeAvailable {
    if(_fd<0)return;
    for(unsigned turn=0;turn<8 && _output.count;++turn) {
        NSData *data=_output.firstObject;
        ssize_t n=send(_fd,(const uint8_t *)data.bytes+_offset,MIN((NSUInteger)16384,data.length-_offset),0);
        if(n<0 && errno==EINTR)continue;
        if(n<0 && (errno==EAGAIN || errno==EWOULDBLOCK))return;
        if(n<=0){[self close];return;}
        _offset+=(NSUInteger)n;_queued-=(NSUInteger)n;
        if(_offset==data.length){[_output removeObjectAtIndex:0];_offset=0;}
    }
    if(!_output.count && _writeSource){dispatch_source_cancel(_writeSource);_writeSource=nil;}
}
- (void)dealloc {
    if(_fd>=0){if(_readSource)dispatch_source_cancel(_readSource);if(_writeSource)dispatch_source_cancel(_writeSource);close(_fd);}
}
@end
