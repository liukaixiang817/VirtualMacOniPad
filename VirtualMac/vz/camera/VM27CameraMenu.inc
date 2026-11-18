- (UIMenuElement *)cameraMenu {
    VM27HostCamera *camera = gGuestCamera;
    BOOL enabled = camera.sharingRequested;
    UIAction *share = [UIAction actionWithTitle:VZL(@"Share Camera") image:nil identifier:nil handler:^(UIAction *action) {
        (void)action;
        if (gGuestCamera != camera || !self.isVMDisplayActive) return;
        [camera requestSharing:!enabled completion:^(BOOL granted) {
            if (gGuestCamera != camera) return;
            if (!granted) VZPresentFailureReport(self, VZL(@"Camera"),
                VZL(@"Allow camera access in iPadOS Settings to share it with the guest."), nil, VZFailureSupportOptionNone);
            [(VZHUDView *)gHUDView refreshMenu];
        }];
    }];
    share.state = enabled ? UIMenuElementStateOn : UIMenuElementStateOff;
    NSMutableArray *profiles = [NSMutableArray array];
    NSArray *labels = @[@"480p", @"720p", @"1080p"];
    for (NSUInteger i = 0; i < labels.count; i++) {
        UIAction *profile = [UIAction actionWithTitle:labels[i] image:nil identifier:nil handler:^(UIAction *action) {
            (void)action;
            if (gGuestCamera != camera || !self.isVMDisplayActive) return;
            camera.profile = (VM27CameraProfile)i;
            [(VZHUDView *)gHUDView refreshMenu];
        }];
        profile.state = i == camera.profile ? UIMenuElementStateOn : UIMenuElementStateOff;
        [profiles addObject:profile];
    }
    UIMenu *resolution = [UIMenu menuWithTitle:VZL(@"Resolution") children:profiles];
    resolution.subtitle = labels[camera.profile];
    UIAction *lens = [UIAction actionWithTitle:VZL(camera.isFrontCamera ? @"Rear Camera" : @"Front Camera")
        image:[UIImage systemImageNamed:@"arrow.trianglehead.camera"] identifier:nil handler:^(UIAction *action) {
        (void)action;
        if (gGuestCamera != camera || !self.isVMDisplayActive) return;
        camera.frontCamera = !camera.isFrontCamera;
        [(VZHUDView *)gHUDView refreshMenu];
    }];
    UIAction *mirror = [UIAction actionWithTitle:VZL(@"Flip Horizontally") image:nil identifier:nil handler:^(UIAction *action) {
        (void)action;
        if (gGuestCamera != camera || !self.isVMDisplayActive) return;
        camera.mirrored = !camera.mirrored;
        [(VZHUDView *)gHUDView refreshMenu];
    }];
    mirror.state = camera.mirrored ? UIMenuElementStateOn : UIMenuElementStateOff;
    return [UIMenu menuWithTitle:VZL(@"Camera") image:[UIImage systemImageNamed:@"video"]
        identifier:nil options:0 children:@[share, resolution, lens, mirror]];
}
