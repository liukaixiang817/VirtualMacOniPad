#import <Foundation/Foundation.h>

NS_ASSUME_NONNULL_BEGIN

static NSString *const VM27BuiltInAudioKey = @"BuiltInAudioDevices";
static NSString *const VM27SpeakerKey = @"AudioOutputEnabled";
static NSString *const VM27MicrophoneKey = @"NativeMicrophoneEnabled27";
static NSString *const VM27NextSpeakerKey = @"NextBootAudioOutputEnabled";
static NSString *const VM27NextMicrophoneKey = @"NextBootNativeMicrophoneEnabled27";

// The stream descriptors stay present in the guest. A nil source produces
// silence and a nil sink discards samples in Virtualization.framework.
static inline BOOL VM27UsesBuiltInAudio(BOOL independent, NSDictionary *options) {
    return independent && [options[VM27BuiltInAudioKey] isEqual:@YES];
}

static inline BOOL VM27NextBootAudioEnabled(NSDictionary *options, BOOL microphone) {
    NSString *pending = microphone ? VM27NextMicrophoneKey : VM27NextSpeakerKey;
    NSString *current = microphone ? VM27MicrophoneKey : VM27SpeakerKey;
    NSNumber *next = options[pending];
    return [([next isKindOfClass:NSNumber.class] ? next : options[current]) isEqual:@YES];
}

static inline void VM27ApplyBuiltInAudioPreferences(NSMutableDictionary *options,
                                                   BOOL microphoneAvailable) {
    options[VM27SpeakerKey] = @(VM27NextBootAudioEnabled(options, NO));
    options[VM27MicrophoneKey] = @(microphoneAvailable && VM27NextBootAudioEnabled(options, YES));
    [options removeObjectsForKeys:@[VM27NextSpeakerKey, VM27NextMicrophoneKey]];
}

@protocol VM27NativeSoundConfiguration <NSObject>
- (void)setAudioDevices:(NSArray *)devices;
- (NSArray *)audioDevices;
- (void)setStreams:(NSArray *)streams;
- (NSArray *)streams;
- (void)setSource:(nullable id)source;
- (nullable id)source;
- (void)setSink:(nullable id)sink;
- (nullable id)sink;
@end

static inline BOOL VM27ConfigureBuiltInAudio(id<VM27NativeSoundConfiguration> configuration,
                                           BOOL inputEnabled, BOOL outputEnabled) {
    id<VM27NativeSoundConfiguration> sound = [NSClassFromString(@"VZVirtioSoundDeviceConfiguration") new];
    id<VM27NativeSoundConfiguration> input = [NSClassFromString(@"VZVirtioSoundDeviceInputStreamConfiguration") new];
    id<VM27NativeSoundConfiguration> output = [NSClassFromString(@"VZVirtioSoundDeviceOutputStreamConfiguration") new];
    id source = inputEnabled ? [NSClassFromString(@"VZHostAudioInputStreamSource") new] : nil;
    id sink = outputEnabled ? [NSClassFromString(@"VZHostAudioOutputStreamSink") new] : nil;
    BOOL available = sound && input && output && (!inputEnabled || source) && (!outputEnabled || sink);
    if (available) {
        input.source = source;
        output.sink = sink;
        NSArray *streams = @[input, output];
        sound.streams = streams;
        configuration.audioDevices = @[sound];
        available = [configuration.audioDevices isEqualToArray:@[sound]] &&
            [sound.streams isEqualToArray:streams] && input.source == source && output.sink == sink;
    }
#if !__has_feature(objc_arc)
    [source release];
    [sink release];
    [input release];
    [output release];
    [sound release];
#endif
    return available;
}

NS_ASSUME_NONNULL_END
