#!/bin/sh
# Start the existing native wallpaper job at Aqua login, before Dock demand.
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
vm27_label=com.mac.virtual.wallpaper-early-start-v1
vm27_agents="$HOME/Library/LaunchAgents"
vm27_job="$vm27_agents/$vm27_label.plist"
vm27_state="$HOME/Library/Logs/VirtualMacWallpaperEarlyStart-v1"
vm27_expected() {
    /bin/cat <<EOF
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0"><dict>
<key>Label</key><string>$vm27_label</string>
<key>ProgramArguments</key><array><string>/bin/launchctl</string><string>kickstart</string><string>gui/$vm27_uid/com.apple.wallpaper.agent</string></array>
<key>RunAtLoad</key><true/>
<key>LimitLoadToSessionType</key><string>Aqua</string>
<key>ProcessType</key><string>Interactive</string>
<key>StandardOutPath</key><string>$vm27_state/stdout.log</string>
<key>StandardErrorPath</key><string>$vm27_state/stderr.log</string>
</dict></plist>
EOF
}
vm27_check_owned() {
    [ -f "$vm27_job" ] && [ ! -L "$vm27_job" ] || exit 77
    [ "$(/usr/bin/stat -f %u:%Lp:%l "$vm27_job")" = "$vm27_uid:600:1" ] || exit 77
    [ "$(/bin/cat "$vm27_job")" = "$(vm27_expected)" ] || exit 78
}
if [ "$vm27_action" = status ]; then
    if [ -e "$vm27_job" ] || [ -L "$vm27_job" ]; then
        vm27_check_owned
        printf 'Native wallpaper early start installed\n'
        /bin/launchctl print "gui/$vm27_uid/$vm27_label" || true
    else
        printf 'Native wallpaper early start absent\n'
    fi
    exit 0
fi
[ -d "$vm27_agents" ] && [ ! -L "$vm27_agents" ] || exit 77
[ "$(/usr/bin/stat -f %u "$vm27_agents")" = "$vm27_uid" ] || exit 77
if [ "$vm27_action" = apply ]; then
    if [ -e "$vm27_job" ] || [ -L "$vm27_job" ]; then
        vm27_check_owned
        printf 'Native wallpaper early start already installed\n'
        exit 0
    fi
    [ ! -e "$vm27_state" ] && [ ! -L "$vm27_state" ] || exit 77
    /bin/mkdir -m 700 "$vm27_state"
    # No wallpaper choice, image, system job or native service is replaced.
    (set -C; vm27_expected > "$vm27_job")
    /usr/bin/plutil -lint "$vm27_job"
    /bin/launchctl bootstrap "gui/$vm27_uid" "$vm27_job"
    printf 'Native wallpaper early start installed; next Aqua login starts the original job once\n'
else
    vm27_check_owned
    /bin/launchctl bootout "gui/$vm27_uid/$vm27_label" 2>/dev/null || {
        if /bin/launchctl print "gui/$vm27_uid/$vm27_label" >/dev/null 2>&1; then exit 74; fi
    }
    /bin/rm "$vm27_job"
    printf 'Native wallpaper early start removed; original wallpaper service retained\n'
fi
