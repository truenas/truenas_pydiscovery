"""Duplicate suppression for a broadcast received on two sockets.

A subnet broadcast is delivered to the subnet's broadcast socket and to
the daemon-wide 0.0.0.0 receiver, and both dispatch it.  Samba nmbd
drops the second copy (``is_processed_packet`` in
``source3/nmbd/nmbd_packets.c``); a client's retransmission, 250 ms
later with the same NAME_TRN_ID, is still answered.
"""
from __future__ import annotations

import time
from ipaddress import IPv4Address

from truenas_pynetbiosns.protocol.constants import (
    DUPLICATE_PACKET_WINDOW,
    NBFlag,
    NameType,
    REGISTRATION_RETRY_INTERVAL,
)
from truenas_pynetbiosns.protocol.message import NBNSMessage
from truenas_pynetbiosns.protocol.name import NetBIOSName
from truenas_pynetbiosns.server.config import DaemonConfig, ServerConfig
from truenas_pynetbiosns.server.net.dedup import PacketDedup
from truenas_pynetbiosns.server.net.subnet import NbnsSubnet
from truenas_pynetbiosns.server.net.transport import NBNSTransport
from truenas_pynetbiosns.server.query.responder import Responder
from truenas_pynetbiosns.server.server import NBNSServer, PerSubnetState

_MY_IP = IPv4Address("192.0.2.10")
_CLIENT = ("192.0.2.50", 51000)


class TestPacketDedup:
    def test_second_copy_within_window_is_duplicate(self):
        dedup = PacketDedup()
        assert dedup.is_duplicate(("a", 1)) is False
        assert dedup.is_duplicate(("a", 1)) is True

    def test_distinct_keys_are_not_duplicates(self):
        dedup = PacketDedup()
        assert dedup.is_duplicate(("a", 1)) is False
        assert dedup.is_duplicate(("a", 2)) is False

    def test_key_is_forgotten_after_window(self):
        dedup = PacketDedup(window=0.05)
        assert dedup.is_duplicate(("a", 1)) is False
        time.sleep(0.07)
        assert dedup.is_duplicate(("a", 1)) is False

    def test_window_is_shorter_than_request_retransmission(self):
        assert DUPLICATE_PACKET_WINDOW < REGISTRATION_RETRY_INTERVAL


def _server_with_registered_name(tmp_path) -> tuple[NBNSServer, list]:
    """An NBNSServer with one subnet that owns ``NAS01<20>``; its
    responder's replies are collected in the returned list."""
    server = NBNSServer(DaemonConfig(
        server=ServerConfig(netbios_name="NAS01", workgroup="WG"),
        rundir=tmp_path,
    ))
    subnet = NbnsSubnet(
        interface_name="eth0", interface_index=2, my_ip=_MY_IP,
        netmask=IPv4Address("255.255.255.0"),
        broadcast=IPv4Address("192.0.2.255"),
    )
    state = PerSubnetState(subnet, NBNSTransport(
        interface_name="eth0", interface_addr=str(_MY_IP),
        broadcast_addr=str(subnet.broadcast),
    ))
    name = NetBIOSName("NAS01", NameType.SERVER)
    state.name_table.add(name, _MY_IP, NBFlag(0), 0)
    state.name_table.mark_registered(name)
    sent: list = []
    state.responder = Responder(
        lambda msg, addr: sent.append((msg, addr)), state.name_table,
    )
    server._subnets.append(state)
    return server, sent


class TestServerDispatch:
    def test_broadcast_query_received_twice_is_answered_once(self, tmp_path):
        server, sent = _server_with_registered_name(tmp_path)
        query = NBNSMessage.build_name_query("NAS01", NameType.SERVER)
        # The subnet's broadcast socket and the 0.0.0.0 receiver each
        # hand the same datagram to the dispatcher.
        server._handle_message(query, _CLIENT, "eth0")
        server._handle_message(query, _CLIENT, "eth0")
        assert len(sent) == 1

    def test_retransmitted_query_is_answered_again(self, tmp_path):
        server, sent = _server_with_registered_name(tmp_path)
        query = NBNSMessage.build_name_query("NAS01", NameType.SERVER)
        server._handle_message(query, _CLIENT, "eth0")
        time.sleep(DUPLICATE_PACKET_WINDOW + 0.02)
        server._handle_message(query, _CLIENT, "eth0")
        assert len(sent) == 2

    def test_copy_no_subnet_takes_does_not_suppress_the_next(self, tmp_path):
        """Only a dispatched copy is recorded: a copy that arrives on an
        interface with no subnet state is dropped without hiding the
        copy that arrives where the subnet is."""
        server, sent = _server_with_registered_name(tmp_path)
        query = NBNSMessage.build_name_query("NAS01", NameType.SERVER)
        server._handle_message(query, _CLIENT, "eth1")
        server._handle_message(query, _CLIENT, "eth0")
        assert len(sent) == 1
