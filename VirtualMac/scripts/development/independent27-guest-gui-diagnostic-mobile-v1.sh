#!/var/jb/bin/sh
set -eu
[ "$(id -u)" = 501 ]
printf 'OWN_GUEST_GUI_URL_MOBILE_BEGIN uid=501 url=virtualmac27://guest-gui-diagnostic calls=1\n'
url_exit=0
/var/jb/usr/bin/uiopen 'virtualmac27://guest-gui-diagnostic' || url_exit=$?
printf 'OWN_GUEST_GUI_URL_MOBILE_END uiopenExit=%s acceptedOrDiagnosticSuccessNotClaimed=1\n' "$url_exit"
exit "$url_exit"
