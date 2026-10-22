#!/bin/sh
# Narrow the existing raster-cache workaround to the actual icon-service app.
set -eu
umask 077
export LC_ALL=C
vm27_action=${1:-status}
[ "$#" -le 1 ] || exit 64
case "$vm27_action" in status|apply|restore) ;; *) exit 64;; esac
vm27_uid=$(/usr/bin/id -u)
[ "$vm27_uid" -ge 501 ] && [ "$vm27_uid" -lt 65534 ] || exit 77
[ "$(/usr/sbin/sysctl -n hw.model)" = VirtualMac2,1 ] || exit 78
[ "$(/usr/bin/sw_vers -buildVersion)" = 25G83 ] || exit 78
vm27_global=com.apple.CoreGraphics
vm27_icon=com.apple.iconservicesagent
vm27_key=RIP_ENABLE_IMAGE_CACHE
vm27_state="$HOME/Library/Logs/VirtualMacNativeRasterScope-v1"
vm27_read() { /usr/bin/defaults read "$1" "$vm27_key" 2>/dev/null || printf absent; }
vm27_false() {
    [ "$(vm27_read "$1")" = 0 ] &&
    [ "$(/usr/bin/defaults read-type "$1" "$vm27_key")" = 'Type is boolean' ]
}
if [ "$vm27_action" = status ]; then
    printf 'Global raster cache override: %s\nIcon-service raster cache override: %s\n' \
        "$(vm27_read "$vm27_global")" "$(vm27_read "$vm27_icon")"
    exit 0
fi
[ "$(/usr/bin/defaults read com.apple.coreimage CI_ENABLE_METAL_DAG)" = 0 ] || exit 78
if [ -e "$vm27_state" ] || [ -L "$vm27_state" ]; then
    [ -d "$vm27_state" ] && [ ! -L "$vm27_state" ] || exit 77
    [ "$(/usr/bin/stat -f %u:%Lp "$vm27_state")" = "$vm27_uid:700" ] || exit 77
    [ -f "$vm27_state/prior-state" ] && [ ! -L "$vm27_state/prior-state" ] || exit 77
    [ "$(/usr/bin/stat -f %u:%Lp:%l "$vm27_state/prior-state")" = "$vm27_uid:600:1" ] || exit 77
    [ "$(/bin/cat "$vm27_state/prior-state")" = 'global=false icon=absent' ] || exit 78
else
    [ "$vm27_action" = apply ] || exit 78
    vm27_false "$vm27_global" && [ "$(vm27_read "$vm27_icon")" = absent ] || exit 78
    # Confirm that the removed global value is the prior owned workaround.
    vm27_old="$HOME/Library/Logs/VirtualMacNativeImageCacheCompatibility-v2/prior-state"
    [ -f "$vm27_old" ] && [ ! -L "$vm27_old" ] || exit 77
    case "$(/usr/bin/stat -f %u:%Lp:%l "$vm27_old")" in
        "$vm27_uid:600:1"|"$vm27_uid:644:1") ;; *) exit 77;;
    esac
    [ "$(/bin/cat "$vm27_old")" = absent ] || exit 78
    /bin/mkdir -m 700 "$vm27_state"
    (set -C; printf 'global=false icon=absent\n' > "$vm27_state/prior-state")
fi
if [ "$vm27_action" = apply ]; then
    [ "$(vm27_read "$vm27_global")" = absent ] || vm27_false "$vm27_global" || exit 78
    [ "$(vm27_read "$vm27_icon")" = absent ] || vm27_false "$vm27_icon" || exit 78
    case "$(vm27_read "$vm27_icon")" in
        absent) /usr/bin/defaults write "$vm27_icon" "$vm27_key" -bool NO;;
        0) vm27_false "$vm27_icon" || exit 78;;
        *) exit 78;;
    esac
    vm27_false "$vm27_icon" || exit 74
    if [ "$(vm27_read "$vm27_global")" != absent ]; then
        vm27_false "$vm27_global" || exit 78
        /usr/bin/defaults delete "$vm27_global" "$vm27_key"
    fi
    [ "$(vm27_read "$vm27_global")" = absent ] || exit 74
    printf 'Raster cache workaround scoped to native icon service; normal guest restart required\n'
else
    [ "$(vm27_read "$vm27_global")" = absent ] || vm27_false "$vm27_global" || exit 78
    [ "$(vm27_read "$vm27_icon")" = absent ] || vm27_false "$vm27_icon" || exit 78
    # Restore the previous complete policy before removing its scoped copy.
    if [ "$(vm27_read "$vm27_global")" = absent ]; then
        /usr/bin/defaults write "$vm27_global" "$vm27_key" -bool NO
    else
        vm27_false "$vm27_global" || exit 78
    fi
    if [ "$(vm27_read "$vm27_icon")" != absent ]; then
        vm27_false "$vm27_icon" || exit 78
        /usr/bin/defaults delete "$vm27_icon" "$vm27_key"
    fi
    vm27_false "$vm27_global" && [ "$(vm27_read "$vm27_icon")" = absent ] || exit 74
    printf 'Previous global raster cache workaround restored; normal guest restart required\n'
fi
