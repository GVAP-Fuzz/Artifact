#!/bin/bash
# dedupe_qemu_log.sh RAW_LOG DEDUP_LOG
if [[ $# -ne 2 ]]; then
  echo "usage: dedupe_qemu_log.sh RAW_LOG DEDUP_LOG" >&2
  exit 2
fi
awk 'NF && !seen[$0]++' "$1" > "$2"
