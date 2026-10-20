#!/var/jb/bin/sh
set -eu
[ "$(id -u)" = 501 ]
printf 'OWN_DIAGNOSTIC_SSH_URL_MOBILE_BEGIN uid=501 url=virtualmac27://diagnostic-ssh-enable calls=1\n'
url_exit=0
/var/jb/usr/bin/uiopen 'virtualmac27://diagnostic-ssh-enable' || url_exit=$?
printf 'OWN_DIAGNOSTIC_SSH_URL_MOBILE_END uiopenExit=%s acceptedOrSSHAuthenticationNotClaimed=1\n' "$url_exit"
exit "$url_exit"
