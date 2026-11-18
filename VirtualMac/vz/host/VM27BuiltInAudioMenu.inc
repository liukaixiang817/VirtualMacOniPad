// The system audio attachments are fixed when the VM is created. Keep a
// pending choice separate from the configuration bound to a hibernated VM.
- (UIMenuElement *)builtInAudioMenuForOptions:(NSDictionary *)options
                                 microphone:(BOOL)microphone {
    BOOL selected = VM27NextBootAudioEnabled(options, microphone);
    NSString *title = microphone ? VZL(@"Microphone Input") : VZL(@"Speakers");
    NSString *icon = microphone ? @"mic" : @"speaker.wave.2";
    NSString *currentKey = microphone ? VM27MicrophoneKey : VM27SpeakerKey;
    NSString *pendingKey = microphone ? VM27NextMicrophoneKey : VM27NextSpeakerKey;
    BOOL current = [options[currentKey] isEqual:@YES];
    NSString *status = selected == current ? VZL(current ? @"On" : @"Off")
        : VZL(selected ? @"On After Next Cold Boot" : @"Off After Next Cold Boot");
    uint64_t generation = gIndependent27SessionEpoch;
    NSString *bundle = self.activeVMBundlePath;
    BOOL (^stillActive)(void) = ^BOOL{
        return gVirtualMachine && generation == gIndependent27SessionEpoch && self.isVMDisplayActive &&
            [self.activeVMBundlePath isEqualToString:bundle] && !VM27HibernateOperationPendingV4();
    };
    UIAction *change = [UIAction actionWithTitle:selected ? VZL(@"Turn Off on Next Cold Boot") : VZL(@"Turn On on Next Cold Boot")
        image:nil identifier:nil handler:^(UIAction *action) {
        (void)action;
        if (!stillActive()) return;
        void (^save)(void) = ^{
            if (!stillActive()) return;
            NSMutableDictionary *updated = [[VZVMOptionsForBundle(bundle) mutableCopy] autorelease];
            if (!VM27UsesBuiltInAudio(VZIndependent27SourceRouteSelected(), updated)) return;
            if ([updated[currentKey] isEqual:@(!selected)]) [updated removeObjectForKey:pendingKey];
            else updated[pendingKey] = @(!selected);
            NSError *error = nil;
            if (!VZWriteVMOptions(updated, bundle, &error)) {
                VZPresentFailureReport(self, title, error.localizedDescription,
                    nil, VZFailureSupportOptionNone);
                return;
            }
            [(VZHUDView *)gHUDView refreshMenu];
        };
        if (!microphone || selected || AVAudioSession.sharedInstance.recordPermission == AVAudioSessionRecordPermissionGranted) {
            save();
            return;
        }
        [AVAudioSession.sharedInstance requestRecordPermission:^(BOOL granted) {
            dispatch_async(dispatch_get_main_queue(), ^{
                if (!stillActive()) return;
                if (granted) save();
                else VZPresentFailureReport(self, title,
                    VZL(@"Allow microphone access in iPadOS Settings to share it with the guest."),
                    nil, VZFailureSupportOptionNone);
            });
        }];
    }];
    if (VM27HibernateOperationPendingV4()) change.attributes = UIMenuElementAttributesDisabled;
    UIMenu *menu = [UIMenu menuWithTitle:title image:[UIImage systemImageNamed:icon]
        identifier:nil options:0 children:@[change]];
    menu.subtitle = status;
    return menu;
}
