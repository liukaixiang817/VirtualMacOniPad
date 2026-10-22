set -eu
[ "$(/usr/bin/id -u)" = 0 ] && [ "$(/usr/bin/id -ru)" = 0 ]
ROOT='/Library/Application Support/VM27OwnedSSH-v2-33547b92f6f7bf5f'
HELPER="$ROOT/vm27-guest-vsock-ssh"
for p in /Library '/Library/Application Support' /Library/LaunchDaemons;do
 [ -d "$p" ] && [ ! -L "$p" ]
 [ "$(cd -P "$p" && /bin/pwd -P)" = "$p" ]
 [ "$(/usr/bin/stat -f '%u' "$p")" = 0 ]
done
if [ ! -e "$ROOT" ] && [ ! -L "$ROOT" ];then /bin/mkdir -m 755 "$ROOT"; /usr/sbin/chown root:wheel "$ROOT";fi
[ -d "$ROOT" ] && [ ! -L "$ROOT" ]
[ "$(cd -P "$ROOT" && /bin/pwd -P)" = "$ROOT" ]
[ "$(/usr/bin/stat -f '%u:%g:%Lp' "$ROOT")" = 0:0:755 ]
if [ ! -e "$HELPER" ] && [ ! -L "$HELPER" ];then
 PENDING='@PENDING@'
 STAGE=${PENDING%/*}
 [ -d "$STAGE" ] && [ ! -L "$STAGE" ]
 [ "$(cd -P "$STAGE" && /bin/pwd -P)" = "$STAGE" ]
 [ "$(/usr/bin/stat -f '%u:%g:%Lp' "$STAGE")" = 0:0:700 ]
 [ -f "$PENDING" ] && [ ! -L "$PENDING" ]
 [ "$(/usr/bin/stat -f '%u:%g:%Lp:%l:%z' "$PENDING")" = 0:0:600:1:52448 ]
 [ "$(/usr/bin/shasum -a 256 "$PENDING" | /usr/bin/cut -d ' ' -f1)" = 33547b92f6f7bf5f60ad47084963f41090c0a736fc85d78a7221fb66cd5b869c ]
 /usr/bin/codesign --verify --strict "$PENDING"
 /bin/chmod 755 "$PENDING"
 /bin/mv -n "$PENDING" "$HELPER"
 [ ! -e "$PENDING" ]
 /bin/rmdir "$STAGE"
fi
[ -f "$HELPER" ] && [ ! -L "$HELPER" ]
[ "$(/usr/bin/stat -f '%u:%g:%Lp:%l:%z' "$HELPER")" = 0:0:755:1:52448 ]
[ "$(/usr/bin/shasum -a 256 "$HELPER" | /usr/bin/cut -d ' ' -f1)" = 33547b92f6f7bf5f60ad47084963f41090c0a736fc85d78a7221fb66cd5b869c ]
/usr/bin/codesign --verify --strict "$HELPER"
LEGACY='/Library/LaunchDaemons/com.mac.virtual.independent27.owned-ssh-v2.plist'
if [ -e "$LEGACY" ] || [ -L "$LEGACY" ];then
 [ -f "$LEGACY" ] && [ ! -L "$LEGACY" ]
 [ "$(/usr/bin/stat -f '%u:%g:%Lp:%l' "$LEGACY")" = 0:0:644:1 ]
 [ "$(/usr/bin/shasum -a 256 "$LEGACY" | /usr/bin/cut -d ' ' -f1)" = a205e34c8103ff415a129e0f04b1211d5afc7538fdf256f2d90570b30d49c159 ]
 JOB="$LEGACY"
 LABEL=com.mac.virtual.independent27.owned-ssh-v2
else
 JOB='/Library/LaunchDaemons/com.mac.virtual.ssh-forward-v3.plist'
 LABEL=com.mac.virtual.ssh-forward-v3
 if [ ! -e "$JOB" ] && [ ! -L "$JOB" ];then
  pending=$(/usr/bin/mktemp "$ROOT/job.XXXXXX")
  trap '/bin/rm -f "$pending"' EXIT HUP INT TERM
  /bin/cat > "$pending" <<'VM27_SSH_JOB_V3'
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0"><dict>
<key>Label</key><string>com.mac.virtual.ssh-forward-v3</string>
<key>ProgramArguments</key><array><string>/Library/Application Support/VM27OwnedSSH-v2-33547b92f6f7bf5f/vm27-guest-vsock-ssh</string><string>--serve-v1</string></array>
<key>UserName</key><string>nobody</string>
<key>RunAtLoad</key><true/><key>KeepAlive</key><true/>
<key>ThrottleInterval</key><integer>5</integer>
<key>StandardOutPath</key><string>/dev/null</string><key>StandardErrorPath</key><string>/dev/null</string>
</dict></plist>
VM27_SSH_JOB_V3
  /usr/sbin/chown root:wheel "$pending"
  /bin/chmod 644 "$pending"
  /bin/mv -n "$pending" "$JOB"
  [ ! -e "$pending" ]
  trap - EXIT HUP INT TERM
 fi
 [ -f "$JOB" ] && [ ! -L "$JOB" ]
 [ "$(/usr/bin/stat -f '%u:%g:%Lp:%l' "$JOB")" = 0:0:644:1 ]
 [ "$(/usr/bin/shasum -a 256 "$JOB" | /usr/bin/cut -d ' ' -f1)" = 674046d5d09dfb24d0a13b23be5b5d124752a45c93277378be3964eb4fdb1a01 ]
fi
/usr/bin/plutil -lint "$JOB" >/dev/null
/bin/launchctl enable system/com.openssh.sshd
if ! /bin/launchctl print system/com.openssh.sshd >/dev/null 2>&1;then /bin/launchctl bootstrap system /System/Library/LaunchDaemons/ssh.plist;fi
/bin/launchctl enable "system/$LABEL"
if ! /bin/launchctl print "system/$LABEL" >/dev/null 2>&1;then /bin/launchctl bootstrap system "$JOB";fi
/bin/launchctl kickstart "system/$LABEL"
/bin/launchctl print system/com.openssh.sshd >/dev/null
/bin/launchctl print "system/$LABEL" >/dev/null
printf 'VM27_GUEST_PERSISTENT_SSH_READY OpenSSH=1 RunAtLoad=1 KeepAlive=1 authenticationRequired=1\n'
