#!/system/bin/sh
# ABK: boot-completed runs before user storage (CE) is unlocked, so targets
# whose data dir lives on CE (the detector) cannot be resolved there.
# Re-run the idempotent sync once the detector's dir becomes visible.
# Install at: /data/adb/service.d/hma_late_sync.sh (0755)
(
  i=0
  while [ "$i" -lt 180 ]; do
    if [ -d /data/user/0/com.chunqiunativecheck ]; then
      sh /data/adb/boot-completed.d/hmaoss.sh >/dev/null 2>&1
      break
    fi
    sleep 10
    i=$((i+1))
  done
) &
