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
phase=validate-trust-bindings
printf 'revision=1004-1 phase=%s\n' "$phase" >> "$log"
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
printf 'revision=1004-1 phase=%s\n' "$phase" >> "$log"
missing=$(printf '%s\n' "$trusted" | awk '
 FILENAME=="-" {known[$1]=1; next}
 !($1 in known) {print $1}
' - "$metadata/trustcache-v2.txt")
for expected in $missing; do
 printf 'trust-add=%s\n' "$expected" >> "$log"
 "$jbctl" trustcache add "$expected" >> "$log" 2>&1
done
phase=verify-trust-cache
printf 'revision=1004-1 phase=%s\n' "$phase" >> "$log"
trusted_raw=$("$jbctl" trustcache info)
trusted=$(printf '%s\n' "$trusted_raw" | awk 'length($NF)==40 && $NF !~ /[^0-9a-fA-F]/ {print tolower($NF)}')
printf '%s\n' "$trusted" | awk '
 FILENAME=="-" {known[$1]=1; next}
 !($1 in known) {exit 1}
' - "$metadata/trustcache-v2.txt"
phase=register-app
printf '[VirtualMac beta4] trust entries ready; registering App
'
uicache -p "$app"
phase=complete
echo 'Complete macOS 13 / macOS 27 beta4 r1 installed. Guest disks and existing settings retained.'
