"""Tests for DNS name encoding/decoding with compression."""
import pytest
from truenas_pymdns.protocol.name import decode_name, encode_name


class TestEncodeName:
    def test_simple_name(self):
        buf = bytearray()
        encode_name("myhost.local", buf)
        # 6 m y h o s t 5 l o c a l 0
        assert buf == b"\x06myhost\x05local\x00"

    def test_single_label(self):
        buf = bytearray()
        encode_name("localhost", buf)
        assert buf == b"\x09localhost\x00"

    def test_trailing_dot(self):
        buf = bytearray()
        encode_name("myhost.local.", buf)
        assert buf == b"\x06myhost\x05local\x00"

    def test_empty_name(self):
        buf = bytearray()
        encode_name("", buf)
        assert buf == b"\x00"

    def test_root(self):
        buf = bytearray()
        encode_name(".", buf)
        assert buf == b"\x00"

    def test_compression_reuses_suffix(self):
        buf = bytearray()
        comp: dict[str, int] = {}
        encode_name("foo.local", buf, comp)
        first_len = len(buf)
        encode_name("bar.local", buf, comp)
        # "bar.local" should use a pointer for "local"
        # bar(3 + 1) + pointer(2) = 6 bytes added
        assert len(buf) == first_len + 6

    def test_compression_reuses_full_name(self):
        buf = bytearray()
        comp: dict[str, int] = {}
        encode_name("_http._tcp.local", buf, comp)
        first_len = len(buf)
        encode_name("_http._tcp.local", buf, comp)
        # Should be just a 2-byte pointer
        assert len(buf) == first_len + 2

    def test_label_too_long(self):
        with pytest.raises(ValueError, match="Label too long"):
            buf = bytearray()
            encode_name("a" * 64 + ".local", buf)

    def test_service_name(self):
        buf = bytearray()
        encode_name("_smb._tcp.local", buf)
        assert buf == b"\x04_smb\x04_tcp\x05local\x00"

    def test_instance_name(self):
        buf = bytearray()
        encode_name("My NAS._smb._tcp.local", buf)
        assert buf == b"\x06My NAS\x04_smb\x04_tcp\x05local\x00"


class TestDecodeName:
    def test_simple_name(self):
        data = b"\x06myhost\x05local\x00"
        name, end = decode_name(data, 0)
        assert name == "myhost.local"
        assert end == len(data)

    def test_with_offset(self):
        prefix = b"\xff\xff"  # 2 bytes of junk
        data = prefix + b"\x03foo\x05local\x00"
        name, end = decode_name(data, 2)
        assert name == "foo.local"
        assert end == len(data)

    def test_pointer(self):
        # First name at offset 0: "local" = \x05local\x00
        # Second name at offset 7: "foo" + pointer to offset 0
        data = b"\x05local\x00\x03foo\xc0\x00"
        name, end = decode_name(data, 7)
        assert name == "foo.local"
        # end should be after the pointer (offset 7 + 3+1 label + 2 pointer = 13)
        assert end == 13

    def test_pointer_loop_detected(self):
        # Two pointers pointing at each other
        data = b"\xc0\x02\xc0\x00"
        with pytest.raises(ValueError, match="loop"):
            decode_name(data, 0)

    def test_truncated_name(self):
        data = b"\x06myho"  # claims 6 bytes but only has 4
        with pytest.raises(ValueError, match="truncated"):
            decode_name(data, 0)

    def test_truncated_pointer(self):
        data = b"\xc0"
        with pytest.raises(ValueError, match="truncated"):
            decode_name(data, 0)

    def test_empty_at_offset(self):
        data = b"\x00"
        name, end = decode_name(data, 0)
        assert name == ""
        assert end == 1


class TestRoundTrip:
    @pytest.mark.parametrize("name", [
        "myhost.local",
        "_http._tcp.local",
        "My NAS._smb._tcp.local",
        "_services._dns-sd._udp.local",
        "a.b.c.d.e.f",
        "x",
        "100.168.192.in-addr.arpa",
    ])
    def test_encode_decode(self, name):
        buf = bytearray()
        encode_name(name, buf)
        decoded, end = decode_name(buf, 0)
        assert decoded == name
        assert end == len(buf)

    def test_compressed_round_trip(self):
        buf = bytearray()
        comp: dict[str, int] = {}
        names = [
            "_http._tcp.local",
            "_smb._tcp.local",
            "My NAS._smb._tcp.local",
            "truenas.local",
        ]
        offsets = []
        for n in names:
            offsets.append(len(buf))
            encode_name(n, buf, comp)

        for n, off in zip(names, offsets):
            decoded, _ = decode_name(buf, off)
            assert decoded == n
