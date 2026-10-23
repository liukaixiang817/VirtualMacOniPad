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
    if ! printf '%s\n' "$trusted_raw" | awk '
        /^Jailbreak Trustcache [0-9]+ / {seen=1}
        END {exit !seen}'; then
        printf 'trust-tool-error=no-service-reply\n%s\n' "$trusted_raw" >> "$log"
        return 1
    fi
}

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
trap 'result=$?; printf "revision=1005 phase=%s exit=%s\n" "$phase" "$result" >> "$log"; if [ "$result" != 0 ]; then printf "[VirtualMac beta5] configuration failed at %s; see %s\n" "$phase" "$log" >&2; fi' 0
printf 'revision=1005 configure-start\n' >> "$log"
sha256sum --status -c "$metadata/files.sha256"
printf '[VirtualMac beta5] installed files verified
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
 trusted=$(printf '%s\n' "$trusted_raw" | awk 'length($NF)==40 && $NF !~ /[^0-9a-fA-F]/ {print tolower($NF)}')
else
 # Upstream 1.2.3 uses the native add API directly. Enumeration is an
 # optimization, not a reason to block a working add API on another setup.
 printf 'trust-enumeration-unavailable=using-native-add-api-for-every-owned-hash\n' >> "$log"
fi
phase=validate-trust-bindings
printf 'revision=1005 phase=%s\n' "$phase" >> "$log"
# files.sha256 has already verified all installed bytes in one process.
# Bind each recorded CDHash to that same manifest instead of rehashing each
# image and spawning hundreds of sha256sum/grep processes on the device.
awk '
 FILENAME==ARGV[1] {if (NF!=2 || length($1)!=64 || $1 ~ /[^0-9a-f]/ || ($2 in file)) exit 1; file[$2]=$1; next}
 {if (NF!=3 || length($1)!=40 || $1 ~ /[^0-9a-f]/ || length($2)!=64 || $2 ~ /[^0-9a-f]/ || file[$3]!=$2) exit 1; rows++}
 END {if (!rows) exit 1}
' "$metadata/files.sha256" "$metadata/trustcache-v2.txt"
while read -r expected expected_file path extra; do
 [ -f "$path" ] && [ ! -L "$path" ]
 case "$path" in "$app"/*|"$runtime"/*|"$full13"/*) ;; *) exit 1;; esac
done < "$metadata/trustcache-v2.txt"
phase=register-owned-images
printf 'revision=1005 phase=%s\n' "$phase" >> "$log"
missing=$(printf '%s\n' "$trusted" | awk '
 FILENAME=="-" {known[$1]=1; next}
 !($1 in known) {print $1}
' - "$metadata/trustcache-v2.txt")
for expected in $missing; do
 printf 'trust-add=%s\n' "$expected" >> "$log"
 "$vm27_trust_tool" trustcache add "$expected" >> "$log" 2>&1
done
phase=verify-trust-cache
printf 'revision=1005 phase=%s\n' "$phase" >> "$log"
if vm27_query_trust_cache; then
 trusted=$(printf '%s\n' "$trusted_raw" | awk 'length($NF)==40 && $NF !~ /[^0-9a-fA-F]/ {print tolower($NF)}')
 printf '%s\n' "$trusted" | awk '
 FILENAME=="-" {known[$1]=1; next}
 !($1 in known) {exit 1}
 ' - "$metadata/trustcache-v2.txt"
 printf 'trust-verification=enumeration-and-native-add-api\n' >> "$log"
else
 # set -e already enforced success for every needed native add call.
 # Known initial entries plus successful additions cover the pinned manifest.
 printf 'trust-verification=initial-known-entries-and-successful-native-add-api\n' >> "$log"
fi
phase=register-app
printf '[VirtualMac beta5] trust entries ready; registering App
'
uicache -p "$app"
phase=complete
echo 'Complete macOS 13 / macOS 27 beta5 installed. Guest disks and existing settings retained.'
