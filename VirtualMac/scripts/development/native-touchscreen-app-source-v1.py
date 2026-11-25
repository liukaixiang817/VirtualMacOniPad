"""Connect original VZ27 touchscreen devices to the production UIKit surface."""
import json
from pathlib import Path
import shutil
import subprocess


def once(source, old, new):
    if source.count(old) != 1:
        raise ValueError('Native touchscreen insertion point changed: ' + old[:100])
    return source.replace(old, new)


def apply(source):
    source = once(source, '#import "VMAppleAccountInstallationV1.h"',
        '#import "VMAppleAccountInstallationV1.h"\n#import "vm27_native_touchscreen_v1.h"')
    source = once(source, '    gSoftwareKeyboardRequested = requested;\n',
        '''    static dispatch_once_t keyboardDismissObserverOnce;
    dispatch_once(&keyboardDismissObserverOnce, ^{
        // The notification center owns this app-lifetime observer. Only the
        // current surface can clear the shared HUD/activation show request.
        [NSNotificationCenter.defaultCenter addObserverForName:
            @"com.mac.virtual.input.softwareKeyboardDidDismiss" object:nil queue:nil
            usingBlock:^(NSNotification *notification) {
                if (pthread_main_np() && notification.object == gIndependent27InputSurface)
                    gSoftwareKeyboardRequested = NO;
            }];
    });
    gSoftwareKeyboardRequested = requested;
''')
    source = once(source, '    setObj(graphics, "setDisplays:", @[display]);',
        '''    if (VZIndependent27SourceRouteSelected() &&
        !VM27ConfigureNativeTouchScreenV1(configuration, display, bundlePath, options, error))
        return nil;
    setObj(graphics, "setDisplays:", @[display]);''')
    source = once(source, '    gPointingDevice = [pointingDevices firstObject];',
        '''    gPointingDevice = [pointingDevices firstObject];
    if (VZIndependent27SourceRouteSelected()) {
        VM27NativeTouchScreenV1 *screen = [VM27NativeTouchScreenV1
            screenForVirtualMachine:gVirtualMachine view:gIndependent27InputSurface];
        [(id<VM27NativeTouchScreenSurfaceV1>)gIndependent27InputSurface vm27_setNativeTouchScreenV1:screen];
    }''')
    source = once(source, '    [radioNewGuestOptions setDictionary:accountOptions];',
        '''    [radioNewGuestOptions setDictionary:accountOptions];
    if (VZIndependent27SourceRouteSelected()) {
        NSString *guestBuild = accountOptions[@"AppleAccountGuestBuildV1"] ?:
            VMAppleAccountRestoreBuildV1(url, NULL);
        if (guestBuild.length) radioNewGuestOptions[@"VMGuestOSBuildV1"] = guestBuild;
    }''')
    return source


def settings_source(source):
    source = once(source, '#import "VZAppSettings.h"',
        '#import "VZAppSettings.h"\n#import "vm27_native_touchscreen_v1.h"')
    source = once(source, 'section == 1 ? 7 :', 'section == 1 ? 8 :')
    source = once(source, '    if (section == 4)\n',
        '''    if (section == 1)
        return VZL(@"Native screen gestures use macOS settings on compatible macOS 27.2 or later guests. Restart the virtual Mac after changing this option.");
    if (section == 4)
''')
    source = once(source, '    } else if (indexPath.section == 1 && indexPath.row < 5) {',
        '''    } else if (indexPath.section == 1 && indexPath.row == 7) {
        cell.textLabel.text = VZL(@"Native Touchscreen (macOS 27.2+) ");
        UISwitch *toggle = [[[UISwitch alloc] init] autorelease];
        toggle.on = ![settings.dictionaryRepresentation[VM27NativeTouchScreenSettingV1] isEqual:@NO];
        toggle.accessibilityIdentifier = VM27NativeTouchScreenSettingV1;
        [toggle addTarget:self action:@selector(nativeTouchScreenChanged:)
            forControlEvents:UIControlEventValueChanged];
        cell.accessoryView = toggle;
        cell.selectionStyle = UITableViewCellSelectionStyleNone;
    } else if (indexPath.section == 1 && indexPath.row < 5) {''')
    source = once(source, '- (void)inputToggleChanged:(UISwitch *)sender\n',
        '''- (void)nativeTouchScreenChanged:(UISwitch *)sender
{
    [VZAppSettings.sharedSettings setBool:sender.on forKey:VM27NativeTouchScreenSettingV1];
}

- (void)inputToggleChanged:(UISwitch *)sender
''')
    return source.replace('Native Touchscreen (macOS 27.2+) ', 'Native Touchscreen (macOS 27.2+)')


def rebuild(root, out, app, link, run):
    host = root / 'VirtualMac/vz/host'
    sdk = subprocess.check_output(['xcrun', '--sdk', 'iphoneos', '--show-sdk-path'], text=True).strip()
    replacements = [
        ('17-modern_uikit_input_surface_v20_native_trackpad.o', host / 'modern_uikit_input_surface_v21_native_touchscreen.m'),
        ('18-modern_uikit_input_adapter_v7_publication_wakeup.o', host / 'modern_uikit_input_adapter_v8_native_touchscreen.m'),
        ('12-VZSettingsViewController_v4_complete_dual.o', None),
    ]
    for suffix, source in replacements:
        old = next(a for a in link if str(a).endswith('/' + suffix))
        recipes = json.loads((Path(old).parent / 'commands.json').read_text())
        args = next(c['argv'][:] for c in recipes if '-c' in c.get('argv', []) and
            c['argv'][c['argv'].index('-o') + 1] == old)
        if source is None:
            original = Path(args[args.index('-c') + 1])
            source = out / 'VZSettingsViewController_native_touchscreen_v1.m'
            source.write_text(settings_source(original.read_text()))
        else:
            frozen = out / source.name
            shutil.copyfile(source, frozen)
            source = frozen
        obj = out / (source.stem + '.o')
        args[args.index('-c') + 1] = source
        args[args.index('-o') + 1] = obj
        if '-MF' in args:
            args[args.index('-MF') + 1] = out / (source.stem + '.d')
        args[args.index('-target') + 1] = 'arm64e-apple-ios16.1'
        args[args.index('-isysroot') + 1] = sdk
        run('compile-' + source.stem, args)
        assert link.count(old) == 1
        link[link.index(old)] = obj
    obj = out / 'vm27_native_touchscreen_v1.o'
    run('compile-native-touchscreen', ['xcrun', '--sdk', 'iphoneos', 'clang',
        '-target', 'arm64e-apple-ios16.1', '-O2', '-fobjc-arc', '-fblocks',
        '-Wall', '-Wextra', '-Werror', '-I', host, '-I', host / 'portable_app_v1/host',
        '-c', host / 'vm27_native_touchscreen_v1.m', '-o', obj])
    link.append(obj)
    translations = {
        'Native Touchscreen (macOS 27.2+)': '原生触摸屏（macOS 27.2 及更新版本）',
        'Native screen gestures use macOS settings on compatible macOS 27.2 or later guests. Restart the virtual Mac after changing this option.':
            '兼容的 macOS 27.2 及更新来宾使用系统原生触摸手势。更改此选项后，请重新启动虚拟 Mac。',
    }
    for language in ('en', 'zh_CN'):
        with (app / (language + '.lproj/Localizable.strings')).open('a') as strings:
            for key, chinese in translations.items():
                strings.write('\n' + json.dumps(key) + ' = ' +
                    json.dumps(chinese if language == 'zh_CN' else key, ensure_ascii=False) + ';\n')
