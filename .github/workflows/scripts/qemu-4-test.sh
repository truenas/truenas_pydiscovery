#!/usr/bin/env bash

######################################################################
# Run the whole test suite in the VM as root, functional tests included
######################################################################

set -eu

echo "Running tests..."

source /tmp/vm-info.sh

set +e
ssh "debian@$VM_IP" 'sudo bash -s' <<'REMOTE_SCRIPT'
set -eu

cd /home/debian/truenas_pydiscovery

# The integration tests run their daemons on the first non-loopback
# interface that is UP, BROADCAST and MULTICAST.  Give them a dummy
# one with a fixed address, as the container job does, and take
# MULTICAST off the VM's uplink so they skip it (unicast, SSH
# included, is unaffected).
UPLINK=$(ip -o route show default | awk '{print $5; exit}')

# truenas-discoveryd binds UDP 5353 exclusively by default
# (disallow-other-stacks), as on TrueNAS, where no other mDNS stack
# runs.  Keep systemd-resolved, if the image runs it, off mDNS/LLMNR.
if systemctl is-active --quiet systemd-resolved; then
  mkdir -p /etc/systemd/resolved.conf.d
  printf '[Resolve]\nMulticastDNS=no\nLLMNR=no\n' \
    > /etc/systemd/resolved.conf.d/90-no-mdns.conf
  systemctl restart systemd-resolved
fi

ip link add mdnstest0 type dummy
ip link set mdnstest0 multicast on
ip link set mdnstest0 up
ip addr add 192.0.2.10/24 brd + dev mdnstest0
ip link set "$UPLINK" multicast off

echo "=========================================="
echo "Running pytest"
echo "=========================================="

# The installed package is what gets tested: no PYTHONPATH, so the
# imports resolve to /usr/lib/python3/dist-packages.  The functional
# tests drive the installed truenas-discoveryd unit.
TRUENAS_PYDISCOVERY_FUNCTIONAL=1 python3 -m pytest tests/ -v -rs \
  2>&1 | tee /home/debian/test-output.txt
TEST_EXIT_CODE=${PIPESTATUS[0]}

echo "$TEST_EXIT_CODE" > /home/debian/test-exitcode.txt
echo "Test run complete (exit code: $TEST_EXIT_CODE)"
exit "$TEST_EXIT_CODE"
REMOTE_SCRIPT
TEST_EXIT_CODE=$?
set -e

scp "debian@$VM_IP":~/test-output.txt /tmp/ || true
scp "debian@$VM_IP":~/test-exitcode.txt /tmp/ || true

if [ "$TEST_EXIT_CODE" -ne 0 ]; then
  echo "Tests failed with exit code $TEST_EXIT_CODE"
  exit "$TEST_EXIT_CODE"
fi

echo "All tests passed!"
