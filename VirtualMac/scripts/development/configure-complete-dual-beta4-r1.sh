[ "${1:-}" = configure ] || exit 0
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
trap 'result=$?; printf "revision=1004-1 phase=%s exit=%s\n" "$phase" "$result" >> "$log"; if [ "$result" != 0 ]; then printf "[VirtualMac beta4 r1] configuration failed at %s; see %s\n" "$phase" "$log" >&2; fi' 0
printf 'revision=1004-1 configure-start\n' >> "$log"
sha256sum --status -c "$metadata/files.sha256"
printf '[VirtualMac beta4] installed files verified
'
chown -R 501:501 "$app" "$runtime" "$full13"
jbctl=$(command -v jbctl || true)
[ -n "$jbctl" ] || jbctl=/var/jb/basebin/jbctl
[ -x "$jbctl" ]
phase=read-trust-cache
trusted_raw=$("$jbctl" trustcache info)
trusted=$(printf '%s\n' "$trusted_raw" | awk 'length($NF)==40 && $NF !~ /[^0-9a-fA-F]/ {print tolower($NF)}')
phase=register-owned-images
# The package builder binds each CDHash to the full signed file SHA256.
# Check that full identity here; no undeclared on-device signing tool is needed.
while read -r expected expected_file path extra; do
 [ -z "$extra" ]
 case "$expected_file" in ''|*[!0-9a-f]*) exit 1;; esac
 [ "${#expected_file}" = 64 ]
 case "$expected" in ''|*[!0-9a-f]*) exit 1;; esac
 [ "${#expected}" = 40 ] && [ -f "$path" ] && [ ! -L "$path" ]
 case "$path" in "$app"/*|"$runtime"/*|"$full13"/*) ;; *) exit 1;; esac
 actual_file=$(sha256sum "$path")
 [ "${actual_file%% *}" = "$expected_file" ]
 if ! printf '%s\n' "$trusted" | grep -Fqx "$expected"; then
  printf 'trust-add=%s\n' "$expected" >> "$log"
  "$jbctl" trustcache add "$expected" >> "$log" 2>&1
 fi
done < "$metadata/trustcache-v2.txt"
phase=verify-trust-cache
trusted_raw=$("$jbctl" trustcache info)
trusted=$(printf '%s\n' "$trusted_raw" | awk 'length($NF)==40 && $NF !~ /[^0-9a-fA-F]/ {print tolower($NF)}')
while read -r expected expected_file path extra; do
 printf '%s\n' "$trusted" | grep -Fqx "$expected"
done < "$metadata/trustcache-v2.txt"
phase=register-app
printf '[VirtualMac beta4] trust entries ready; registering App
'
uicache -p "$app"
phase=complete
echo 'Complete macOS 13 / macOS 27 beta4 r1 installed. Guest disks and existing settings retained.'
