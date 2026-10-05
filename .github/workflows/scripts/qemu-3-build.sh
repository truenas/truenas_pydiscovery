#!/usr/bin/env bash

######################################################################
# Build the Debian package in the VM and install it
######################################################################

set -eu

echo "Building and installing truenas_pydiscovery..."

source /tmp/vm-info.sh

echo "Waiting for cloud-init to complete..."
ssh "debian@$VM_IP" "cloud-init status --wait" || true

echo "Installing rsync in VM..."
ssh "debian@$VM_IP" "sudo apt-get update && sudo apt-get install -y rsync"

echo "Copying source code to VM..."
ssh "debian@$VM_IP" "mkdir -p ~/truenas_pydiscovery"
rsync -az --exclude='.git' --exclude='debian/.debhelper' \
  --exclude='__pycache__' \
  "$GITHUB_WORKSPACE/" "debian@$VM_IP":~/truenas_pydiscovery/

ssh "debian@$VM_IP" 'bash -s' <<'REMOTE_SCRIPT'
set -eu
export DEBIAN_FRONTEND=noninteractive

cd ~/truenas_pydiscovery

sudo apt-get update

# Build the deb (same dependencies as the container job), then run
# the tests: pytest, iproute2 for the veth links and network
# namespaces the functional tests create.
sudo apt-get install -y --no-install-recommends \
  build-essential devscripts debhelper \
  dh-python pybuild-plugin-pyproject \
  python3-all python3-all-dev python3-setuptools \
  python3-defusedxml \
  python3-pytest \
  iproute2 \
  adduser

echo "Building the Debian package..."
dpkg-buildpackage -us -uc -b

echo "Installing the Debian package..."
sudo apt-get install -y ../python3-truenas-pydiscovery_*.deb

# Installed as a systemd unit, with the client tools on PATH
systemctl cat truenas-discoveryd.service >/dev/null
for tool in truenas-discoveryd nbt-lookup mdns-resolve wsd-discover; do
  command -v "$tool" >/dev/null
done

echo "Build and installation complete"
REMOTE_SCRIPT

echo "truenas_pydiscovery installed in VM"
