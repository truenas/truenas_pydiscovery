#!/usr/bin/env bash

######################################################################
# Download and boot a Debian Trixie cloud image as the test VM
######################################################################

set -eu

echo "Starting Debian Trixie VM..."

URL="https://cloud.debian.org/images/cloud/trixie/latest/debian-13-generic-amd64.qcow2"
VM_NAME="pydiscovery-test"
VM_IP="192.168.122.10"
VM_MAC="52:54:00:83:79:10"

WORK_DIR="/tmp/qemu-work"
# The VM's serial console: firmware, GRUB, kernel and cloud-init output.
CONSOLE_LOG="$WORK_DIR/console.log"
mkdir -p "$WORK_DIR"
cd "$WORK_DIR"

echo "Downloading Debian Trixie cloud image..."
if [ ! -f "debian-trixie.qcow2" ]; then
  wget -q --show-progress "$URL" -O debian-trixie.qcow2
fi

echo "Creating VM disk..."
qemu-img create -f qcow2 -F qcow2 -b "$WORK_DIR/debian-trixie.qcow2" \
  "$WORK_DIR/vm-disk.qcow2" 20G

PUBKEY=$(cat ~/.ssh/id_ed25519.pub)

cat <<EOF > /tmp/user-data
#cloud-config

hostname: debian-trixie

users:
- name: debian
  sudo: ALL=(ALL) NOPASSWD:ALL
  shell: /bin/bash
  ssh_authorized_keys:
    - $PUBKEY

packages:
  - python3

runcmd:
  - echo "VM initialization complete"

growpart:
  mode: auto
  devices: ['/']
  ignore_growroot_disabled: false
EOF

echo "Starting libvirt network..."
sudo virsh net-destroy default 2>/dev/null || true
sudo virsh net-start default
sudo virsh net-autostart default

for i in {1..10}; do
  if ip link show virbr0 >/dev/null 2>&1; then
    echo "Network bridge virbr0 is ready"
    break
  fi
  echo "Waiting for network bridge... ($i/10)"
  sleep 2
done

if ! sudo virsh net-info default | grep -q "Active:.*yes"; then
  echo "ERROR: Failed to start libvirt default network"
  sudo virsh net-info default || true
  exit 1
fi

sudo virsh net-update default add ip-dhcp-host \
  "<host mac='$VM_MAC' ip='$VM_IP'/>" --live --config || true

# UEFI, as pam_truenas and truenas_pyos boot this image.
echo "Starting VM..."
# Exists before libvirt hands it to QEMU, which runs as libvirt-qemu.
touch "$CONSOLE_LOG"
sudo virt-install \
  --name "$VM_NAME" \
  --os-variant debian12 \
  --cpu host-passthrough \
  --virt-type=kvm \
  --vcpus=4 \
  --memory 4096 \
  --graphics none \
  --network bridge=virbr0,model=virtio,mac="$VM_MAC" \
  --cloud-init user-data=/tmp/user-data \
  --disk path="$WORK_DIR/vm-disk.qcow2",format=qcow2,bus=virtio \
  --boot uefi=on \
  --serial file,path="$CONSOLE_LOG" \
  --import \
  --noautoconsole >/dev/null

# Written now, so that the logs are collected even if the VM never
# comes up.
cat <<EOF > /tmp/vm-info.sh
export VM_IP="$VM_IP"
export VM_NAME="$VM_NAME"
export WORK_DIR="$WORK_DIR"
export CONSOLE_LOG="$CONSOLE_LOG"
EOF

echo "Waiting for VM to be ready..."
for i in {1..60}; do
  if ssh -o ConnectTimeout=2 "debian@$VM_IP" "echo 'VM ready'" 2>/dev/null; then
    echo "VM is accessible via SSH"
    break
  fi
  echo "Waiting for VM... ($i/60)"
  sleep 5
done

if ! ssh "debian@$VM_IP" "uname -a"; then
  echo "ERROR: VM is not accessible"
  sudo virsh domstate --reason "$VM_NAME" || true
  sudo virsh net-dhcp-leases default || true
  echo "---- VM console, last 80 lines ----"
  sudo tail -n 80 "$CONSOLE_LOG" || true
  exit 1
fi

echo "VM started successfully at $VM_IP"
