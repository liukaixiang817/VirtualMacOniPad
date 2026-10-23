[ "${1:-}" = configure ] || exit 0
# Sourced by the package configure script after the private metadata log exists.
# Use the jailbreak's own binary and libraries; never copy or replace basebin.
vm27_read_trust_cache() {
    "$vm27_trust_tool" trustcache info 2>> "$log"
}

vm27_select_trust_tool() {
    vm27_jbroot=$(realpath /var/jb) || return 1
    vm27_trust_tool=
    for vm27_candidate in /var/jb/basebin/jbctl /var/jb/usr/bin/jbctl; do
        [ -x "$vm27_candidate" ] || continue
        vm27_resolved=$(realpath "$vm27_candidate") || continue
        # The symlink installed by dopamine-basebin-link resolves here. Executing
        # the canonical file also gives @loader_path its actual basebin directory.
        [ "$vm27_resolved" = "$vm27_jbroot/basebin/jbctl" ] || continue
        [ -f "$vm27_resolved" ] && [ ! -L "$vm27_resolved" ] || continue
        vm27_trust_tool=$vm27_resolved
        break
    done
    if [ -z "$vm27_trust_tool" ]; then
        printf 'trust-tool-error=no-official-basebin-jbctl\n' >> "$log"
        return 1
    fi
    printf 'trust-tool=%s\n' "$vm27_trust_tool" >> "$log"
}

vm27_query_trust_cache() {
    vm27_status=0
    trusted_raw=$(vm27_read_trust_cache) || vm27_status=$?
    printf 'trust-info-exit=%s\n' "$vm27_status" >> "$log"
    [ "$vm27_status" = 0 ] || return "$vm27_status"
    # Upstream jbctl can return 0 even when its service query failed. Empty
    # stdout must not be mistaken for an empty but functioning trust cache.
    vm27_reply_seen=0
    while IFS= read -r vm27_line; do
        case "$vm27_line" in 'Jailbreak Trustcache '*) vm27_reply_seen=1;; esac
    done <<VM27_TRUST_REPLY
$trusted_raw
VM27_TRUST_REPLY
    if [ "$vm27_reply_seen" != 1 ]; then
        printf 'trust-tool-error=no-service-reply\n%s\n' "$trusted_raw" >> "$log"
        return 1
    fi
}

# Use POSIX shell builtins: awk is optional on a clean Dopamine bootstrap.
# A hash line is data, never shell input. Tokens cannot expand as file globs.
set -f
vm27_parse_trusted() {
    while IFS= read -r vm27_line; do
        set -- $vm27_line
        [ "$#" -gt 0 ] || continue
        while [ "$#" -gt 1 ]; do shift; done
        [ "${#1}" = 40 ] || continue
        case "$1" in *[!0-9a-fA-F]*) continue;; esac
        printf '%s\n' "$1"
    done <<VM27_TRUST_HASHES
$trusted_raw
VM27_TRUST_HASHES
}
vm27_hash_known() {
    case "$vm27_newline$trusted$vm27_newline" in
        *"$vm27_newline$1$vm27_newline"*) return 0;;
    esac
    return 1
}
vm27_newline='
'

app=/var/jb/Applications/VirtualMacIndependent27.app
runtime=/private/var/mobile/Library/VirtualMacIndependent27Runtime-v1
full13=/private/var/mobile/Library/VirtualMacFull13Runtime-v1
metadata=/var/jb/usr/share/virtualmac-independent27
[ "$(id -u)" = 0 ]
for root in "$app" "$runtime" "$metadata"; do
 [ -d "$root" ] && [ ! -L "$root" ]
 [ -z "$(find "$root" -type l -print -quit)" ]
done
[ -d "$full13" ] && [ ! -L "$full13" ]
while IFS="$(printf '	')" read -r path target; do
 case "$path" in "$full13"/*) ;; *) exit 1;; esac
 case "$target" in ''|/*) exit 1;; esac
 [ -L "$path" ] && [ "$(readlink "$path")" = "$target" ]
 case "$(realpath "$path")" in "$full13"/*) ;; *) exit 1;; esac
done < "$metadata/symlinks.tsv"
[ "$(find "$full13" -type l | wc -l | tr -d ' ')" = "$(wc -l < "$metadata/symlinks.tsv" | tr -d ' ')" ]
log="$metadata/configure.log"
[ ! -L "$log" ] && { [ ! -e "$log" ] || [ -f "$log" ]; }
umask 022
: >> "$log"
chmod 0644 "$log"
phase=verify-files
trap 'result=$?; printf "revision=1006 phase=%s exit=%s\n" "$phase" "$result" >> "$log"; if [ "$result" != 0 ]; then printf "[VirtualMac beta6] configuration failed at %s; see %s\n" "$phase" "$log" >&2; fi' 0
printf 'revision=1006 configure-start\n' >> "$log"
sha256sum --status -c "$metadata/files.sha256"
printf '[VirtualMac beta6] installed files verified
'
chown -R 501:501 "$app" "$runtime" "$full13"
phase=provision-private-cache
# A clean device has none of the developer's previously provisioned cache
# directories. The parent adapter deliberately never creates them itself.
for cache in /private/var/mobile/Library/VirtualMacIndependent27Cache-v1 \
 /private/var/mobile/Library/VirtualMacIndependent27Cache-v1/virtualization; do
 [ ! -L "$cache" ]
 if [ ! -e "$cache" ]; then mkdir -m 700 "$cache"; fi
 [ -d "$cache" ]
 chown 501:501 "$cache"
 chmod 700 "$cache"
done
phase=read-trust-cache
vm27_select_trust_tool
trusted=
if vm27_query_trust_cache; then
 trusted=$(vm27_parse_trusted | tr A-F a-f)
else
 # Upstream 1.2.3 uses the native add API directly. Enumeration is an
 # optimization, not a reason to block a working add API on another setup.
 printf 'trust-enumeration-unavailable=using-native-add-api-for-every-owned-hash\n' >> "$log"
fi
phase=validate-trust-bindings
printf 'revision=1006 phase=%s\n' "$phase" >> "$log"
# files.sha256 has already verified all installed bytes in one process.
# Bind each recorded CDHash to that same manifest instead of rehashing each
# image and spawning hundreds of sha256sum/grep processes on the device.
vm27_verified_files=$(cat "$metadata/files.sha256")
vm27_trust_rows=0
while read -r expected expected_file path extra; do
 [ -z "$extra" ] && [ "${#expected}" = 40 ] && [ "${#expected_file}" = 64 ]
 case "$expected$expected_file" in *[!0-9a-f]*) exit 1;; esac
 [ -f "$path" ] && [ ! -L "$path" ]
 case "$path" in "$app"/*|"$runtime"/*|"$full13"/*) ;; *) exit 1;; esac
 case "$vm27_newline$vm27_verified_files$vm27_newline" in
  *"$vm27_newline$expected_file  $path$vm27_newline"*) ;;
  *) printf 'trust-binding-error=%s\n' "$path" >> "$log"; exit 1;;
 esac
 vm27_trust_rows=$((vm27_trust_rows + 1))
done < "$metadata/trustcache-v2.txt"
[ "$vm27_trust_rows" -gt 0 ]
phase=register-owned-images
printf 'revision=1006 phase=%s\n' "$phase" >> "$log"
while read -r expected expected_file path extra; do
 if ! vm27_hash_known "$expected"; then
  printf 'trust-add=%s\n' "$expected" >> "$log"
  "$vm27_trust_tool" trustcache add "$expected" >> "$log" 2>&1
 fi
done < "$metadata/trustcache-v2.txt"
phase=verify-trust-cache
printf 'revision=1006 phase=%s\n' "$phase" >> "$log"
if vm27_query_trust_cache; then
 trusted=$(vm27_parse_trusted | tr A-F a-f)
 while read -r expected expected_file path extra; do
  vm27_hash_known "$expected"
 done < "$metadata/trustcache-v2.txt"
 printf 'trust-verification=enumeration-and-native-add-api\n' >> "$log"
else
 # set -e already enforced success for every needed native add call.
 # Known initial entries plus successful additions cover the pinned manifest.
 printf 'trust-verification=initial-known-entries-and-successful-native-add-api\n' >> "$log"
fi
phase=register-app
printf '[VirtualMac beta6] trust entries ready; registering App
'
uicache -p "$app"
phase=complete
echo 'Complete macOS 13 / macOS 27 beta6 installed. Guest disks and existing settings retained.'
