from __future__ import annotations

from pathlib import Path
from unittest.mock import AsyncMock, patch

import asyncssh
import pytest

from equipment_registry.connector import _fingerprint, trust_host
from equipment_registry.storage import Equipment, RegistryError


def equipment() -> Equipment:
    return Equipment(
        id="test-id",
        name="R1",
        ip="192.0.2.1",
        ssh_port=22,
        brand="Cisco",
        username="admin",
        created_at="2026-01-01T00:00:00+00:00",
        updated_at="2026-01-01T00:00:00+00:00",
    )


def test_trust_host_requires_exact_fingerprint(tmp_path: Path) -> None:
    key = asyncssh.generate_private_key("ssh-rsa")
    with (
        patch(
            "equipment_registry.connector._fetch_host_key",
            new=AsyncMock(return_value=key),
        ),
        pytest.raises(RegistryError, match="Fingerprint divergente"),
    ):
        trust_host(equipment(), tmp_path / "known_hosts", "SHA256:wrong")
    assert not (tmp_path / "known_hosts").exists()


def test_trust_host_records_validated_key(tmp_path: Path) -> None:
    key = asyncssh.generate_private_key("ssh-rsa")
    destination = tmp_path / "known_hosts"
    with patch(
        "equipment_registry.connector._fetch_host_key",
        new=AsyncMock(return_value=key),
    ):
        trust_host(equipment(), destination, _fingerprint(key))
    content = destination.read_text(encoding="ascii")
    assert content.startswith("192.0.2.1 ssh-rsa ")
    assert "PRIVATE" not in content
