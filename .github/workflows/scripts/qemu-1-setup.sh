#!/usr/bin/env bash

######################################################################
# Set up QEMU/libvirt on the GitHub Actions runner
######################################################################

set -eu

echo "Setting up QEMU environment..."

export DEBIAN_FRONTEND="noninteractive"
sudo apt-get -y update

# virtinst rather than virt-manager: no GUI dependencies.
sudo apt-get install -y --no-install-recommends \
  cloud-image-utils \
  guestfs-tools \
  virtinst \
  qemu-system-x86 \
  qemu-utils \
  libvirt-daemon-system \
  libvirt-clients \
  dnsmasq \
  rsync \
  wget

# SSH key for VM access
rm -f ~/.ssh/id_ed25519
ssh-keygen -t ed25519 -f ~/.ssh/id_ed25519 -q -N ""

# Free resources the runner does not need
sudo systemctl stop docker.socket || true
sudo systemctl stop multipathd.socket || true

# libvirt runs its own dnsmasq for the default network
sudo systemctl stop dnsmasq || true
sudo systemctl disable dnsmasq || true
sudo systemctl mask dnsmasq || true

mkdir -p "$HOME/.ssh"
cat <<EOF >> "$HOME/.ssh/config"
# No questions please
StrictHostKeyChecking no

# Small timeout for connection attempts
ConnectTimeout 10
EOF

sudo systemctl start libvirtd
sudo systemctl enable libvirtd
sudo usermod -a -G libvirt "$USER"

echo "QEMU setup complete"
