from __future__ import annotations

import asyncio
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from unittest.mock import AsyncMock, patch

import asyncssh

from equipment_registry.connector import CommandResult, run_command, trust_host_on_first_use
from equipment_registry.storage import Equipment


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


def second_equipment() -> Equipment:
    return Equipment(
        id="test-id-2",
        name="R2",
        ip="192.0.2.2",
        ssh_port=22,
        brand="Cisco",
        username="admin",
        created_at="2026-01-01T00:00:00+00:00",
        updated_at="2026-01-01T00:00:00+00:00",
    )


def test_trust_host_on_first_use_records_unknown_host(tmp_path: Path) -> None:
    key = asyncssh.generate_private_key("ssh-rsa")
    destination = tmp_path / "known_hosts"
    with patch(
        "equipment_registry.connector._fetch_host_key",
        new=AsyncMock(return_value=key),
    ):
        trust_host_on_first_use(equipment(), destination)
    assert destination.read_text(encoding="ascii").startswith("192.0.2.1 ssh-rsa ")
    assert destination.stat().st_mode & 0o777 == 0o600


def test_trust_host_on_first_use_keeps_pinned_key(tmp_path: Path) -> None:
    destination = tmp_path / "known_hosts"
    original = "192.0.2.1 ssh-rsa AAAAexisting\n"
    destination.write_text(original, encoding="ascii")
    with patch("equipment_registry.connector._fetch_host_key", new=AsyncMock()) as fetch:
        trust_host_on_first_use(equipment(), destination)
    fetch.assert_not_awaited()
    assert destination.read_text(encoding="ascii") == original


def test_concurrent_first_use_preserves_both_hosts(tmp_path: Path) -> None:
    first_key = asyncssh.generate_private_key("ssh-rsa")
    second_key = asyncssh.generate_private_key("ssh-rsa")
    destination = tmp_path / "known_hosts"

    async def fetch(item: Equipment) -> asyncssh.SSHKey:
        await asyncio.sleep(0.01)
        return first_key if item.id == "test-id" else second_key

    with (
        patch("equipment_registry.connector._fetch_host_key", side_effect=fetch),
        ThreadPoolExecutor(max_workers=2) as executor,
    ):
        futures = [
            executor.submit(trust_host_on_first_use, item, destination)
            for item in (equipment(), second_equipment())
        ]
        for future in futures:
            future.result()

    labels = {
        line.split(" ", 1)[0]
        for line in destination.read_text(encoding="ascii").splitlines()
    }
    assert labels == {"192.0.2.1", "192.0.2.2"}


def test_run_command_uses_tofu_before_connecting(tmp_path: Path) -> None:
    item = equipment()
    destination = tmp_path / "known_hosts"
    expected = CommandResult(0, "ok\n", "")
    with (
        patch("equipment_registry.connector.trust_host_on_first_use") as trust,
        patch(
            "equipment_registry.connector._run_command",
            new=AsyncMock(return_value=expected),
        ) as remote_run,
    ):
        result = run_command(item, "secret", destination, "show version")
    trust.assert_called_once_with(item, destination, timeout=30)
    remote_run.assert_awaited_once_with(item, "secret", destination, "show version", 30)
    assert result == expected
