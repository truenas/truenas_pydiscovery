"""Tests for ``truenas_pydiscovery.server.__main__``.

The critical behaviour here: when every protocol is disabled,
``main()`` must exit with status 0 so systemd's
``Restart=on-failure`` does not crash-loop and flood the journal.
"""
from __future__ import annotations

from pathlib import Path

import pytest

from truenas_pydiscovery.server.__main__ import main


def _write(tmp_path: Path, body: str) -> Path:
    p = tmp_path / "unified.conf"
    p.write_text(body)
    return p


def test_all_disabled_exits_zero(tmp_path, monkeypatch):
    conf = _write(tmp_path, """
[discovery]
interfaces = eth0

[mdns]
enabled = false

[netbiosns]
enabled = false

[wsd]
enabled = false
""")
    monkeypatch.setattr(
        "sys.argv",
        ["truenas-discoveryd", "-c", str(conf), "-v"],
    )

    with pytest.raises(SystemExit) as excinfo:
        main()

    assert excinfo.value.code == 0


def test_missing_config_exits_zero(tmp_path, monkeypatch):
    # Same clean-exit path when the config file is absent entirely —
    # still not a crash, so systemd leaves the unit inactive instead
    # of restart-looping.
    missing = tmp_path / "nope.conf"
    monkeypatch.setattr(
        "sys.argv",
        ["truenas-discoveryd", "-c", str(missing), "-v"],
    )

    with pytest.raises(SystemExit) as excinfo:
        main()

    assert excinfo.value.code == 0
