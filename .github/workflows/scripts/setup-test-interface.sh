#!/usr/bin/env bash
# Configure a dedicated dummy interface for the pytest integration
# tests to discover via tests/integration/conftest.py's
# SIOCGIFCONF scan (`_find_candidate_interface`).  The fixture
# picks the first non-loopback interface with UP + BROADCAST +
# MULTICAST — we give it a deterministic dummy netdev rather
# than the runner's eth0 (which has a nondeterministic bridge IP
# and variable multicast-snooping behaviour across kernels).

set -euo pipefail

apt-get install -y --no-install-recommends iproute2

# RFC 5737 TEST-NET-1 — reserved for documentation / testing.
# Won't collide with any routable network on the GHA runner.
IFACE=mdnstest0
ADDR=192.0.2.10/24

ip link add "$IFACE" type dummy
ip link set "$IFACE" multicast on
ip link set "$IFACE" up
# ``brd +`` auto-computes the subnet broadcast from the /24
# prefix (→ 192.0.2.255).  Without it, ``ip addr add`` leaves
# the broadcast at 0.0.0.0, which causes the NetBIOS NS daemon
# to silently drop its REGISTRATION packets and the integration
# tests that follow to fail with "No response from 192.0.2.10".
ip addr add "$ADDR" brd + dev "$IFACE"

# eth0 would otherwise be the first match in the fixture's
# SIOCGIFCONF scan (lower ifindex, also UP+BROADCAST+MULTICAST);
# clearing its MULTICAST flag makes `_find_candidate_interface`
# skip it and fall through to mdnstest0.  eth0 stays UP so
# unicast traffic (apt, HTTPS, etc.) continues to work — only
# the multicast capability is toggled off for the fixture's
# benefit.
ip link set eth0 multicast off

echo "--- interfaces after setup ---"
ip link show
ip -4 addr show
