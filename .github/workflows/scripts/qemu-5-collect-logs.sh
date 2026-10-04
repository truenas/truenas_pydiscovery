#!/usr/bin/env bash

######################################################################
# Collect test output and system logs from the VM
######################################################################

set -eu

echo "Collecting logs..."

LOG_DIR="/tmp/test-logs"
mkdir -p "$LOG_DIR"

cp /tmp/test-output.txt "$LOG_DIR/" 2>/dev/null || true
cp /tmp/test-exitcode.txt "$LOG_DIR/" 2>/dev/null || true

# Absent if the VM was never started.
if [ -f /tmp/vm-info.sh ]; then
  source /tmp/vm-info.sh

  sudo install -m 0644 -o "$(id -u)" -g "$(id -g)" \
    "$CONSOLE_LOG" "$LOG_DIR/console.log" 2>/dev/null || true
  ssh "debian@$VM_IP" "sudo journalctl -u truenas-discoveryd --no-pager" \
    > "$LOG_DIR/truenas-discoveryd.log" 2>/dev/null || true
  ssh "debian@$VM_IP" "sudo journalctl -n 2000 --no-pager" \
    > "$LOG_DIR/journalctl.log" 2>/dev/null || true
  ssh "debian@$VM_IP" "sudo dmesg" > "$LOG_DIR/dmesg.log" 2>/dev/null || true
fi

cd /tmp
tar czf qemu-logs.tar.gz test-logs/

echo "Logs collected at /tmp/qemu-logs.tar.gz"
