"""Derive a log generation only from a real same-packet successful post.

This HOST helper performs no device operation and creates no receipt.
"""
import re

import independent27_normal_guest_common_v2 as common


def actual_post_log_generation(initializer, launch_path, post_path):
    packet, scope, launch, post = common.initializer_success(
        initializer, launch_path, post_path)
    boot = scope.get('bootSeconds')
    boot_uuid = scope.get('bootSessionUUID')
    common.need(isinstance(boot, int) and not isinstance(boot, bool) and boot > 0 and
                isinstance(boot_uuid, str) and re.fullmatch(
                    r'[A-F0-9]{8}-[A-F0-9]{4}-[A-F0-9]{4}-[A-F0-9]{4}-[A-F0-9]{12}',
                    boot_uuid), 'initializer must bind an actual boot and boot-session UUID')
    text = common.exact(post['stdout']).read_text()
    identities = re.findall(
        r'^OWN_POST_ACTUAL_LOG_IDENTITY ([0-9:]+)$', text, re.M)
    common.need(len(identities) == 1,
                'one actual post log identity; no historical inode or inferred success')
    fields = identities[0].split(':')
    common.need(len(fields) == 6 and all(value.isdigit() for value in fields),
                'actual post log identity has six numeric fields')
    dev, ino, uid, gid, mode, links = map(int, fields)
    common.need(dev > 0 and ino > 0 and uid == gid == 501 and mode == 600 and links == 1,
                'post log must be an ordinary bounded owned mobile log')
    return dict(identity=identities[0], bootSeconds=boot, bootSessionUUID=boot_uuid,
                initializerPost=common.pin(post_path.resolve()),
                actualPostStdout=post['stdout'], initializerLaunch=common.pin(launch_path.resolve()),
                samePacketActualLaunch0AndPost0=True)
