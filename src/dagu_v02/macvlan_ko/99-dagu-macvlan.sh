#!/system/bin/sh
# Load the macvlan link type from /data/adb/dagu-macvlan before Droidspaces runs.
[ -e /sys/module/dagu_macvlan ] && exit 0
insmod /data/adb/dagu-macvlan/dagu_macvlan.ko
