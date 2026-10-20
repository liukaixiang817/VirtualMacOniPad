#!/var/jb/bin/sh
set -eu
[ "$(id -u)" = 501 ]
printf 'OWN_DISPLAY_NATIVE_URL_MOBILE_BEGIN uid=501 url=virtualmac27://display-native-iosurface calls=1\n'
url_exit=0
/var/jb/usr/bin/uiopen 'virtualmac27://display-native-iosurface' || url_exit=$?
printf 'OWN_DISPLAY_NATIVE_URL_MOBILE_END uiopenExit=%s acceptedOrActualVisibilityNotClaimed=1\n' "$url_exit"
exit "$url_exit"
