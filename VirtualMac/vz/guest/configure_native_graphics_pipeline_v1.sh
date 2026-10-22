#!/bin/sh
# User-only compatibility for two observed native icon-service lifetime failures.
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
vm27_home=$(/usr/bin/dscl . -read "/Users/$(/usr/bin/id -un)" NFSHomeDirectory | /usr/bin/sed 's/^NFSHomeDirectory: //')
case "$vm27_home" in /Users/*) ;; *) exit 77;; esac
[ -d "$vm27_home" ] && [ ! -L "$vm27_home" ] || exit 77
[ "$(/usr/bin/stat -f %u "$vm27_home")" = "$vm27_uid" ] || exit 77
vm27_option() {
    vm27_phase=$1; vm27_suite=$2; vm27_key=$3; vm27_type=$4; vm27_backup=$5
    vm27_dir="$vm27_home/Library/Logs/$vm27_backup"
    vm27_prior="$vm27_dir/prior-state"
    vm27_value=$(/usr/bin/defaults read "$vm27_suite" "$vm27_key" 2>/dev/null) || vm27_value=absent
    if [ "$vm27_action" = status ]; then
        printf '%s %s=%s\n' "$vm27_suite" "$vm27_key" "$vm27_value"
        return
    fi
    if [ -e "$vm27_dir" ] || [ -L "$vm27_dir" ]; then
        [ -d "$vm27_dir" ] && [ ! -L "$vm27_dir" ] || exit 77
        [ "$(/usr/bin/stat -f %u:%Lp "$vm27_dir")" = "$vm27_uid:700" ] || exit 77
        [ -f "$vm27_prior" ] && [ ! -L "$vm27_prior" ] || exit 77
        # The earlier cache trial used 0644 inside its private 0700 directory.
        # Both admitted modes are owner-writable only; reject extra hard links.
        case "$(/usr/bin/stat -f %u:%Lp:%l "$vm27_prior")" in
            "$vm27_uid:600:1"|"$vm27_uid:644:1") ;; *) exit 77;;
        esac
        [ "$(/bin/cat "$vm27_prior")" = absent ] || exit 78
        if [ "$vm27_value" != absent ]; then
            # Never replace a later manual change or another preference type.
            [ "$vm27_value" = 0 ] || exit 78
            [ "$(/usr/bin/defaults read-type "$vm27_suite" "$vm27_key")" = "Type is $vm27_type" ] || exit 78
        fi
    else
        # Do not claim or overwrite pre-existing user options.
        [ "$vm27_action" = apply ] && [ "$vm27_value" = absent ] || exit 78
    fi
    [ "$vm27_phase" = write ] || return 0
    if [ "$vm27_action" = apply ]; then
        if [ ! -d "$vm27_dir" ]; then
            /bin/mkdir -m 700 "$vm27_dir"
            (set -C; printf 'absent\n' > "$vm27_prior")
        fi
        [ "$vm27_value" = absent ] || return 0
        case "$vm27_type" in
            integer) /usr/bin/defaults write "$vm27_suite" "$vm27_key" -int 0;;
            boolean) /usr/bin/defaults write "$vm27_suite" "$vm27_key" -bool NO;;
        esac
        [ "$(/usr/bin/defaults read "$vm27_suite" "$vm27_key")" = 0 ] || exit 74
        [ "$(/usr/bin/defaults read-type "$vm27_suite" "$vm27_key")" = "Type is $vm27_type" ] || exit 74
    elif [ "$vm27_value" != absent ]; then
        /usr/bin/defaults delete "$vm27_suite" "$vm27_key"
        if /usr/bin/defaults read "$vm27_suite" "$vm27_key" >/dev/null 2>&1; then exit 74; fi
    fi
}
# Preflight both options before either write. Existing backups are reused.
for vm27_phase in check write; do
    vm27_option "$vm27_phase" com.apple.coreimage CI_ENABLE_METAL_DAG integer VirtualMacCoreImageDAGCompatibility-v1
    vm27_option "$vm27_phase" com.apple.CoreGraphics RIP_ENABLE_IMAGE_CACHE boolean VirtualMacNativeImageCacheCompatibility-v2
    [ "$vm27_action" != status ] || exit 0
done
printf 'Native graphics compatibility %s complete; a normal guest restart is required after changes.\n' "$vm27_action"
