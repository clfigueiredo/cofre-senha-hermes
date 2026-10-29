from __future__ import annotations

import asyncio
import time
from concurrent.futures import ThreadPoolExecutor
from dataclasses import replace
from io import BytesIO
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock, patch

import asyncssh
import pytest
from asyncssh.known_hosts import match_known_hosts

from equipment_registry import connector
from equipment_registry.connector import (
    CommandResult,
    SFTPDownloadResult,
    SFTPEntry,
    connection_endpoint,
    download_sftp,
    known_host_alias,
    list_sftp,
    run_command,
    trust_host_on_first_use,
)
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


def test_ddns_nonstandard_port_keeps_plain_asyncssh_alias_and_scoped_known_host(
    tmp_path: Path,
) -> None:
    item = Equipment(
        id="ddns-id",
        name="Pfsense-VLL",
        ip="vll.dyndns.info",
        ssh_port=2222,
        brand="pfSense",
        username="admin",
        created_at="now",
        updated_at="now",
    )
    destination = tmp_path / "known_hosts"
    key = asyncssh.generate_private_key("ssh-rsa")

    assert connection_endpoint(item) == ("vll.dyndns.info", 2222)
    assert known_host_alias(item) == "vll.dyndns.info"
    with patch(
        "equipment_registry.connector._fetch_host_key",
        new=AsyncMock(return_value=key),
    ):
        trust_host_on_first_use(item, destination)
    assert destination.read_text(encoding="ascii").startswith(
        "[vll.dyndns.info]:2222 ssh-rsa "
    )


def test_relay_with_nonstandard_logical_port_loads_key_by_logical_identity(
    tmp_path: Path,
) -> None:
    item = Equipment(
        id="relay-ddns-id",
        name="Pfsense-VLL",
        ip="vll.dyndns.info",
        ssh_port=2222,
        brand="pfSense",
        username="admin",
        created_at="now",
        updated_at="now",
        relay_host="127.0.0.1",
        relay_port=22000,
    )
    destination = tmp_path / "known_hosts"
    key = asyncssh.generate_private_key("ssh-rsa")

    with patch(
        "equipment_registry.connector._fetch_host_key",
        new=AsyncMock(return_value=key),
    ):
        trust_host_on_first_use(item, destination)

    assert destination.read_text(encoding="ascii").startswith(
        "[vll.dyndns.info]:2222 ssh-rsa "
    )
    matched = connector._known_hosts_for_target(item, destination)
    assert matched[0][0].export_public_key("openssh") == key.export_public_key("openssh")
    rematched = match_known_hosts(matched, item.ip, "127.0.0.1", item.relay_port)
    assert rematched[0][0].export_public_key("openssh") == key.export_public_key("openssh")


def test_nonstandard_port_rejects_unqualified_default_port_key(tmp_path: Path) -> None:
    item = Equipment(
        id="ddns-port-id",
        name="Pfsense-VLL",
        ip="vll.dyndns.info",
        ssh_port=2222,
        brand="pfSense",
        username="admin",
        created_at="now",
        updated_at="now",
    )
    destination = tmp_path / "known_hosts"
    key = asyncssh.generate_private_key("ssh-rsa")
    destination.write_text(
        f"vll.dyndns.info {key.export_public_key('openssh').decode('ascii').strip()}\n",
        encoding="ascii",
    )

    with pytest.raises(RegistryError, match="não foi encontrada"):
        connector._known_hosts_for_target(item, destination)


def test_loopback_relay_changes_transport_without_changing_host_key_identity() -> None:
    item = Equipment(
        id="target-id",
        name="Proxmox-Glagio",
        ip="10.10.1.211",
        ssh_port=22,
        brand="Proxmox",
        username="root",
        created_at="now",
        updated_at="now",
        relay_host="127.0.0.1",
        relay_port=22211,
    )

    assert connection_endpoint(item) == ("127.0.0.1", 22211)
    assert known_host_alias(item) == "10.10.1.211"


def test_direct_equipment_uses_its_registered_endpoint_and_identity() -> None:
    item = equipment()

    assert connection_endpoint(item) == ("192.0.2.1", 22)
    assert known_host_alias(item) == "192.0.2.1"


def test_list_sftp_rejects_equipment_without_configured_root(tmp_path: Path) -> None:
    with pytest.raises(RegistryError, match="SFTP não está habilitado"):
        list_sftp(equipment(), "secret", tmp_path / "known_hosts")


@pytest.mark.parametrize("relative_path", ["../secret", "folder/../secret", "/etc", "folder\\file"])
def test_list_sftp_rejects_unsafe_relative_path_before_connecting(
    tmp_path: Path, relative_path: str
) -> None:
    item = replace(equipment(), sftp_root="/")
    with (
        patch("equipment_registry.connector.trust_host_on_first_use") as trust,
        pytest.raises(RegistryError, match="caminho SFTP relativo e seguro"),
    ):
        list_sftp(item, "secret", tmp_path / "known_hosts", relative_path=relative_path)
    trust.assert_not_called()


def test_list_sftp_uses_tofu_and_returns_remote_metadata(tmp_path: Path) -> None:
    item = replace(equipment(), sftp_root="/srv/supply")
    destination = tmp_path / "known_hosts"
    expected = [SFTPEntry("supply.war", "releases/supply.war", "file", 1234, 1_700_000_000)]
    with (
        patch("equipment_registry.connector.trust_host_on_first_use") as trust,
        patch(
            "equipment_registry.connector._list_sftp",
            new=AsyncMock(return_value=expected),
        ) as remote_list,
    ):
        result = list_sftp(
            item,
            "secret",
            destination,
            relative_path="releases",
            timeout=12,
        )

    trust.assert_called_once_with(item, destination, timeout=12)
    remote_list.assert_awaited_once_with(
        item,
        "secret",
        destination,
        connector.PurePosixPath("releases"),
        12,
        1000,
    )
    assert result == expected


def test_list_sftp_enforces_total_operation_timeout(tmp_path: Path) -> None:
    item = replace(equipment(), sftp_root="/")

    async def never_finishes(*args, **kwargs):
        await asyncio.sleep(1)
        return []

    with (
        patch("equipment_registry.connector.trust_host_on_first_use"),
        patch("equipment_registry.connector._list_sftp", side_effect=never_finishes),
        pytest.raises(RegistryError, match="tempo limite"),
    ):
        list_sftp(item, "secret", tmp_path / "known_hosts", timeout=0.01)


def test_list_sftp_shares_one_timeout_budget_with_tofu(tmp_path: Path) -> None:
    item = replace(equipment(), sftp_root="/")

    def consume_budget(*args, **kwargs):
        time.sleep(0.03)

    with (
        patch("equipment_registry.connector.trust_host_on_first_use", side_effect=consume_budget),
        patch("equipment_registry.connector._list_sftp", new=AsyncMock(return_value=[])) as remote,
        pytest.raises(RegistryError, match="tempo limite"),
    ):
        list_sftp(item, "secret", tmp_path / "known_hosts", timeout=0.01)
    remote.assert_not_awaited()


def test_list_sftp_reads_entries_with_pinned_target_identity(tmp_path: Path) -> None:
    item = replace(equipment(), sftp_root="/srv/supply")
    destination = tmp_path / "known_hosts"
    trusted_keys = object()
    entry = asyncssh.SFTPName(
        "supply.war",
        "",
        asyncssh.SFTPAttrs(
            type=asyncssh.FILEXFER_TYPE_REGULAR,
            size=2048,
            mtime=1_700_000_001,
        ),
    )

    async def names():
        yield entry

    sftp = MagicMock()
    sftp.realpath = AsyncMock(side_effect=["/srv/supply", "/srv/supply/releases"])
    sftp.lstat = AsyncMock(
        side_effect=[
            asyncssh.SFTPAttrs(type=asyncssh.FILEXFER_TYPE_DIRECTORY),
            asyncssh.SFTPAttrs(type=asyncssh.FILEXFER_TYPE_DIRECTORY),
        ]
    )
    sftp.scandir = MagicMock(return_value=names())
    sftp_context = AsyncMock()
    sftp_context.__aenter__.return_value = sftp
    connection = MagicMock()
    connection.start_sftp_client.return_value = sftp_context
    connection_context = AsyncMock()
    connection_context.__aenter__.return_value = connection

    with (
        patch(
            "equipment_registry.connector._known_hosts_for_target",
            return_value=trusted_keys,
        ),
        patch("equipment_registry.connector.asyncssh.connect", return_value=connection_context) as connect,
    ):
        result = asyncio.run(
            connector._list_sftp(
                item,
                "secret",
                destination,
                connector.PurePosixPath("releases"),
                12,
                1000,
            )
        )

    connect.assert_called_once_with(
        "192.0.2.1",
        port=22,
        username="admin",
        password="secret",
        known_hosts=trusted_keys,
        host_key_alias="192.0.2.1",
        client_keys=[],
        agent_path=None,
        connect_timeout=12,
        login_timeout=12,
    )
    connection.start_sftp_client.assert_called_once_with(
        path_encoding="utf-8", path_errors="strict"
    )
    assert result == [
        SFTPEntry("supply.war", "releases/supply.war", "file", 2048, 1_700_000_001)
    ]


def test_list_sftp_rejects_symlink_configured_as_root(tmp_path: Path) -> None:
    item = replace(equipment(), sftp_root="/srv/supply")
    sftp = MagicMock()
    sftp.realpath = AsyncMock(return_value="/outside")
    sftp.lstat = AsyncMock(
        return_value=asyncssh.SFTPAttrs(type=asyncssh.FILEXFER_TYPE_SYMLINK)
    )
    sftp_context = AsyncMock()
    sftp_context.__aenter__.return_value = sftp
    connection = MagicMock()
    connection.start_sftp_client.return_value = sftp_context
    connection_context = AsyncMock()
    connection_context.__aenter__.return_value = connection

    with (
        patch("equipment_registry.connector._known_hosts_for_target", return_value=object()),
        patch("equipment_registry.connector.asyncssh.connect", return_value=connection_context),
        pytest.raises(RegistryError, match="raiz SFTP configurada"),
    ):
        asyncio.run(
            connector._list_sftp(
                item,
                "secret",
                tmp_path / "known_hosts",
                connector.PurePosixPath("."),
                12,
                1000,
            )
        )

    sftp.lstat.assert_awaited_once_with("/srv/supply")
    sftp.realpath.assert_not_awaited()


def test_list_sftp_rejects_realpath_outside_root_on_prefix_collision(tmp_path: Path) -> None:
    item = replace(equipment(), sftp_root="/srv/root")

    async def no_entries():
        if False:
            yield None

    sftp = MagicMock()
    sftp.realpath = AsyncMock(side_effect=["/srv/root", "/srv/root2"])
    sftp.lstat = AsyncMock(
        side_effect=[
            asyncssh.SFTPAttrs(type=asyncssh.FILEXFER_TYPE_DIRECTORY),
            asyncssh.SFTPAttrs(type=asyncssh.FILEXFER_TYPE_DIRECTORY),
        ]
    )
    sftp.scandir = MagicMock(return_value=no_entries())
    sftp_context = AsyncMock()
    sftp_context.__aenter__.return_value = sftp
    connection = MagicMock()
    connection.start_sftp_client.return_value = sftp_context
    connection_context = AsyncMock()
    connection_context.__aenter__.return_value = connection

    with (
        patch("equipment_registry.connector._known_hosts_for_target", return_value=object()),
        patch("equipment_registry.connector.asyncssh.connect", return_value=connection_context),
        pytest.raises(RegistryError, match="fora da raiz SFTP"),
    ):
        asyncio.run(
            connector._list_sftp(
                item,
                "secret",
                tmp_path / "known_hosts",
                connector.PurePosixPath("child"),
                12,
                1000,
            )
        )


def test_list_sftp_rejects_symlink_in_intermediate_component(tmp_path: Path) -> None:
    item = replace(equipment(), sftp_root="/srv/root")
    sftp = MagicMock()
    sftp.realpath = AsyncMock(side_effect=["/srv/root", "/srv/root/folder/sub"])
    sftp.lstat = AsyncMock(
        side_effect=[
            asyncssh.SFTPAttrs(type=asyncssh.FILEXFER_TYPE_DIRECTORY),
            asyncssh.SFTPAttrs(type=asyncssh.FILEXFER_TYPE_SYMLINK),
        ]
    )
    sftp_context = AsyncMock()
    sftp_context.__aenter__.return_value = sftp
    connection = MagicMock()
    connection.start_sftp_client.return_value = sftp_context
    connection_context = AsyncMock()
    connection_context.__aenter__.return_value = connection

    with (
        patch("equipment_registry.connector._known_hosts_for_target", return_value=object()),
        patch("equipment_registry.connector.asyncssh.connect", return_value=connection_context),
        pytest.raises(RegistryError, match="symlink"),
    ):
        asyncio.run(
            connector._list_sftp(
                item,
                "secret",
                tmp_path / "known_hosts",
                connector.PurePosixPath("folder/sub"),
                12,
                1000,
            )
        )

    assert sftp.lstat.await_args_list[1].args == ("/srv/root/folder",)


def test_list_sftp_enforces_entry_limit(tmp_path: Path) -> None:
    item = replace(equipment(), sftp_root="/srv/root")

    async def two_entries():
        for name in ("one.war", "two.war"):
            yield asyncssh.SFTPName(
                name,
                "",
                asyncssh.SFTPAttrs(type=asyncssh.FILEXFER_TYPE_REGULAR, size=1, mtime=1),
            )

    sftp = MagicMock()
    sftp.realpath = AsyncMock(side_effect=["/srv/root", "/srv/root"])
    sftp.lstat = AsyncMock(
        return_value=asyncssh.SFTPAttrs(type=asyncssh.FILEXFER_TYPE_DIRECTORY)
    )
    sftp.scandir = MagicMock(return_value=two_entries())
    sftp_context = AsyncMock()
    sftp_context.__aenter__.return_value = sftp
    connection = MagicMock()
    connection.start_sftp_client.return_value = sftp_context
    connection_context = AsyncMock()
    connection_context.__aenter__.return_value = connection

    with (
        patch("equipment_registry.connector._known_hosts_for_target", return_value=object()),
        patch("equipment_registry.connector.asyncssh.connect", return_value=connection_context),
        pytest.raises(RegistryError, match="limite de entradas"),
    ):
        asyncio.run(
            connector._list_sftp(
                item,
                "secret",
                tmp_path / "known_hosts",
                connector.PurePosixPath("."),
                12,
                1,
            )
        )


@pytest.mark.parametrize("unsafe_name", ["../secret", "folder/file", "folder\\file", "bad\r\nname"])
def test_list_sftp_rejects_unsafe_remote_names(tmp_path: Path, unsafe_name: str) -> None:
    item = replace(equipment(), sftp_root="/srv/root")

    async def unsafe_entry():
        yield asyncssh.SFTPName(
            unsafe_name,
            "",
            asyncssh.SFTPAttrs(type=asyncssh.FILEXFER_TYPE_REGULAR, size=1, mtime=1),
        )

    sftp = MagicMock()
    sftp.realpath = AsyncMock(side_effect=["/srv/root", "/srv/root"])
    sftp.lstat = AsyncMock(
        return_value=asyncssh.SFTPAttrs(type=asyncssh.FILEXFER_TYPE_DIRECTORY)
    )
    sftp.scandir = MagicMock(return_value=unsafe_entry())
    sftp_context = AsyncMock()
    sftp_context.__aenter__.return_value = sftp
    connection = MagicMock()
    connection.start_sftp_client.return_value = sftp_context
    connection_context = AsyncMock()
    connection_context.__aenter__.return_value = connection

    with (
        patch("equipment_registry.connector._known_hosts_for_target", return_value=object()),
        patch("equipment_registry.connector.asyncssh.connect", return_value=connection_context),
        pytest.raises(RegistryError, match="nome de arquivo inválido"),
    ):
        asyncio.run(
            connector._list_sftp(
                item,
                "secret",
                tmp_path / "known_hosts",
                connector.PurePosixPath("."),
                12,
                1000,
            )
        )


def test_download_sftp_uses_tofu_and_returns_size_and_hash(tmp_path: Path) -> None:
    item = replace(equipment(), sftp_root="/srv/root")
    destination = tmp_path / "known_hosts"
    output = BytesIO()
    expected = SFTPDownloadResult(
        4,
        "9f64a747e1b97f131fabb6b447296c9b6f0201e79fb3c5356e6c77e89b6a806a",
    )
    with (
        patch("equipment_registry.connector.trust_host_on_first_use") as trust,
        patch(
            "equipment_registry.connector._download_sftp",
            new=AsyncMock(return_value=expected),
        ) as remote_download,
    ):
        result = download_sftp(
            item,
            "secret",
            destination,
            "releases/supply.war",
            output,
            max_bytes=4096,
            timeout=12,
        )

    trust.assert_called_once_with(item, destination, timeout=12)
    remote_download.assert_awaited_once_with(
        item,
        "secret",
        destination,
        connector.PurePosixPath("releases/supply.war"),
        output,
        4096,
        12,
    )
    assert result == expected


def test_download_sftp_enforces_total_operation_timeout(tmp_path: Path) -> None:
    item = replace(equipment(), sftp_root="/")

    async def never_finishes(*args, **kwargs):
        await asyncio.sleep(1)
        return SFTPDownloadResult(0, "")

    with (
        patch("equipment_registry.connector.trust_host_on_first_use"),
        patch("equipment_registry.connector._download_sftp", side_effect=never_finishes),
        pytest.raises(RegistryError, match="tempo limite"),
    ):
        download_sftp(
            item,
            "secret",
            tmp_path / "known_hosts",
            "supply.war",
            BytesIO(),
            max_bytes=4096,
            timeout=0.01,
        )


def test_download_sftp_shares_one_timeout_budget_with_tofu(tmp_path: Path) -> None:
    item = replace(equipment(), sftp_root="/")

    def consume_budget(*args, **kwargs):
        time.sleep(0.03)

    with (
        patch("equipment_registry.connector.trust_host_on_first_use", side_effect=consume_budget),
        patch(
            "equipment_registry.connector._download_sftp",
            new=AsyncMock(return_value=SFTPDownloadResult(0, "")),
        ) as remote,
        pytest.raises(RegistryError, match="tempo limite"),
    ):
        download_sftp(
            item,
            "secret",
            tmp_path / "known_hosts",
            "supply.war",
            BytesIO(),
            max_bytes=4096,
            timeout=0.01,
        )
    remote.assert_not_awaited()


def test_download_sftp_rejects_nonpositive_limit_before_connecting(tmp_path: Path) -> None:
    item = replace(equipment(), sftp_root="/")
    with (
        patch("equipment_registry.connector.trust_host_on_first_use") as trust,
        pytest.raises(RegistryError, match="limite de tamanho"),
    ):
        download_sftp(
            item,
            "secret",
            tmp_path / "known_hosts",
            "supply.war",
            BytesIO(),
            max_bytes=0,
        )
    trust.assert_not_called()


def test_download_sftp_streams_regular_file_and_hashes_bytes(tmp_path: Path) -> None:
    item = replace(equipment(), sftp_root="/srv/root")
    output = BytesIO()
    remote_file = AsyncMock()
    remote_file.stat.return_value = asyncssh.SFTPAttrs(
        type=asyncssh.FILEXFER_TYPE_REGULAR, size=4
    )
    remote_file.read.side_effect = [b"\x00\x01\x02\x03", b""]
    file_context = AsyncMock()
    file_context.__aenter__.return_value = remote_file
    sftp = MagicMock()
    sftp.realpath = AsyncMock(
        side_effect=["/srv/root", "/srv/root/releases/supply.war"]
    )
    sftp.lstat = AsyncMock(
        side_effect=[
            asyncssh.SFTPAttrs(type=asyncssh.FILEXFER_TYPE_DIRECTORY),
            asyncssh.SFTPAttrs(type=asyncssh.FILEXFER_TYPE_DIRECTORY),
            asyncssh.SFTPAttrs(type=asyncssh.FILEXFER_TYPE_REGULAR, size=4),
        ]
    )
    sftp.open = MagicMock(return_value=file_context)
    sftp_context = AsyncMock()
    sftp_context.__aenter__.return_value = sftp
    connection = MagicMock()
    connection.start_sftp_client.return_value = sftp_context
    connection_context = AsyncMock()
    connection_context.__aenter__.return_value = connection

    with (
        patch("equipment_registry.connector._known_hosts_for_target", return_value=object()),
        patch("equipment_registry.connector.asyncssh.connect", return_value=connection_context),
    ):
        result = asyncio.run(
            connector._download_sftp(
                item,
                "secret",
                tmp_path / "known_hosts",
                connector.PurePosixPath("releases/supply.war"),
                output,
                4096,
                12,
            )
        )

    sftp.open.assert_called_once_with("/srv/root/releases/supply.war", "rb")
    remote_file.stat.assert_awaited_once()
    assert output.getvalue() == b"\x00\x01\x02\x03"
    assert result == SFTPDownloadResult(
        4,
        "054edec1d0211f624fed0cbca9d4f9400b0e491c43742af2c5b0abebf0c990d8",
    )


def test_download_sftp_stops_when_server_sends_more_than_limit(tmp_path: Path) -> None:
    item = replace(equipment(), sftp_root="/srv/root")
    output = BytesIO()
    remote_file = AsyncMock()
    remote_file.stat.return_value = asyncssh.SFTPAttrs(
        type=asyncssh.FILEXFER_TYPE_REGULAR, size=1
    )
    remote_file.read.side_effect = [b"12345", b""]
    file_context = AsyncMock()
    file_context.__aenter__.return_value = remote_file
    sftp = MagicMock()
    sftp.realpath = AsyncMock(side_effect=["/srv/root", "/srv/root/supply.war"])
    sftp.lstat = AsyncMock(
        side_effect=[
            asyncssh.SFTPAttrs(type=asyncssh.FILEXFER_TYPE_DIRECTORY),
            asyncssh.SFTPAttrs(type=asyncssh.FILEXFER_TYPE_REGULAR, size=1),
        ]
    )
    sftp.open = MagicMock(return_value=file_context)
    sftp_context = AsyncMock()
    sftp_context.__aenter__.return_value = sftp
    connection = MagicMock()
    connection.start_sftp_client.return_value = sftp_context
    connection_context = AsyncMock()
    connection_context.__aenter__.return_value = connection

    with (
        patch("equipment_registry.connector._known_hosts_for_target", return_value=object()),
        patch("equipment_registry.connector.asyncssh.connect", return_value=connection_context),
        pytest.raises(RegistryError, match="limite de tamanho"),
    ):
        asyncio.run(
            connector._download_sftp(
                item,
                "secret",
                tmp_path / "known_hosts",
                connector.PurePosixPath("supply.war"),
                output,
                4,
                12,
            )
        )

    assert output.getvalue() == b""
