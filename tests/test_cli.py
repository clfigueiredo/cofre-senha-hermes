from __future__ import annotations

import json
import sys
from pathlib import Path
from unittest.mock import patch

import pytest

from equipment_registry.auth import create_admin
from equipment_registry.cli import main
from equipment_registry.connector import CommandResult, SFTPDownloadResult, SFTPEntry
from equipment_registry.storage import EquipmentInput, MonitorTargetInput, Registry, RegistryError


def test_run_subcommand_dispatches_remote_command(tmp_path: Path, monkeypatch, capsys) -> None:
    registry = Registry(tmp_path / "equipment.db", tmp_path / "encryption.key")
    registry.initialize()
    registry.create(EquipmentInput("R1", "192.0.2.1", 22, "test", "Cisco", "admin"))
    (tmp_path / "known_hosts").write_text("placeholder\n", encoding="ascii")
    monkeypatch.setenv("EQUIPMENT_REGISTRY_DATA_DIR", str(tmp_path))
    monkeypatch.setattr(sys, "argv", ["equipment-registry", "run", "R1", "--command", "show version"])

    with patch(
        "equipment_registry.cli.run_command",
        return_value=CommandResult(0, "device-output\n", ""),
    ) as connector:
        assert main() == 0

    assert capsys.readouterr().out == "device-output\n"
    assert connector.call_args.args[0].name == "R1"
    assert connector.call_args.args[3] == "show version"


def test_monitor_list_never_requires_or_returns_credentials(tmp_path: Path, monkeypatch, capsys) -> None:
    registry = Registry(tmp_path / "equipment.db", tmp_path / "encryption.key")
    registry.initialize()
    registry.create_monitor_target(
        MonitorTargetInput("Pfsense-DRN-WAN1", "dornas1.dyndns.org", "snmp", 161, "pfSense")
    )
    monkeypatch.setenv("EQUIPMENT_REGISTRY_DATA_DIR", str(tmp_path))
    monkeypatch.setattr(sys, "argv", ["equipment-registry", "monitor-list"])

    assert main() == 0

    output = capsys.readouterr().out
    assert "Pfsense-DRN-WAN1" in output
    assert "dornas1.dyndns.org" in output
    assert "password" not in output.lower()


def test_private_lan_serve_requires_literal_risk_acceptance(tmp_path: Path, monkeypatch) -> None:
    create_admin(tmp_path / "auth.json", "admin-test-password")
    monkeypatch.setenv("EQUIPMENT_REGISTRY_DATA_DIR", str(tmp_path))
    monkeypatch.setenv("EQUIPMENT_REGISTRY_ALLOW_REMOTE", "1")
    monkeypatch.setattr(
        sys,
        "argv",
        ["equipment-registry", "serve", "--host", "192.168.1.10", "--port", "8787"],
    )
    with pytest.raises(SystemExit) as refusal:
        main()
    assert refusal.value.code == 2

    monkeypatch.setenv(
        "EQUIPMENT_REGISTRY_ALLOW_INSECURE_HTTP", "I_ACCEPT_PRIVATE_LAN_RISK"
    )
    with patch("equipment_registry.cli.serve") as waitress:
        assert main() == 0
    assert waitress.call_args.kwargs["host"] == "192.168.1.10"
    assert waitress.call_args.kwargs["port"] == 8787


def test_sftp_list_outputs_metadata_without_credentials(tmp_path: Path, monkeypatch, capsys) -> None:
    registry = Registry(tmp_path / "equipment.db", tmp_path / "encryption.key")
    registry.initialize()
    registry.create(
        EquipmentInput("Supply-FTP", "sftp.example.test", 2222, "test", "SFTP", "admin", sftp_root="/")
    )
    monkeypatch.setenv("EQUIPMENT_REGISTRY_DATA_DIR", str(tmp_path))
    monkeypatch.setattr(
        sys,
        "argv",
        ["equipment-registry", "sftp-list", "Supply-FTP", "--path", "releases"],
    )
    entries = [SFTPEntry("supply.war", "releases/supply.war", "file", 2048, 1_700_000_001)]

    with patch("equipment_registry.cli.list_sftp", return_value=entries) as connector:
        assert main() == 0

    output = capsys.readouterr().out
    assert '"name": "supply.war"' in output
    assert '"size": 2048' in output
    assert "password" not in output.lower()
    assert connector.call_args.kwargs["relative_path"] == "releases"


def test_sftp_download_creates_private_file_and_outputs_hash(tmp_path: Path, monkeypatch, capsys) -> None:
    registry = Registry(tmp_path / "equipment.db", tmp_path / "encryption.key")
    registry.initialize()
    registry.create(
        EquipmentInput("Supply-FTP", "sftp.example.test", 2222, "test", "SFTP", "admin", sftp_root="/")
    )
    output = tmp_path / "supply.war"
    monkeypatch.setenv("EQUIPMENT_REGISTRY_DATA_DIR", str(tmp_path))
    monkeypatch.setattr(
        sys,
        "argv",
        [
            "equipment-registry",
            "sftp-download",
            "Supply-FTP",
            "supply.war",
            "--output",
            str(output),
            "--max-bytes",
            "4096",
        ],
    )

    def download(*args, **kwargs):
        args[4].write(b"war-data")
        return SFTPDownloadResult(8, "sha256-test")

    with patch("equipment_registry.cli.download_sftp", side_effect=download) as connector:
        assert main() == 0

    assert output.read_bytes() == b"war-data"
    assert output.stat().st_mode & 0o777 == 0o600
    payload = json.loads(capsys.readouterr().out)
    assert payload == {"output": str(output), "size": 8, "sha256": "sha256-test"}
    assert connector.call_args.args[3] == "supply.war"
    assert connector.call_args.kwargs["max_bytes"] == 4096


def test_sftp_download_removes_partial_file_on_failure(tmp_path: Path, monkeypatch) -> None:
    registry = Registry(tmp_path / "equipment.db", tmp_path / "encryption.key")
    registry.initialize()
    registry.create(
        EquipmentInput("Supply-FTP", "sftp.example.test", 2222, "test", "SFTP", "admin", sftp_root="/")
    )
    output = tmp_path / "partial.war"
    monkeypatch.setenv("EQUIPMENT_REGISTRY_DATA_DIR", str(tmp_path))
    monkeypatch.setattr(
        sys,
        "argv",
        [
            "equipment-registry",
            "sftp-download",
            "Supply-FTP",
            "supply.war",
            "--output",
            str(output),
        ],
    )

    def fail_after_partial_write(*args, **kwargs):
        args[4].write(b"partial")
        raise RegistryError("transfer failed")

    with (
        patch("equipment_registry.cli.download_sftp", side_effect=fail_after_partial_write),
        pytest.raises(RegistryError, match="transfer failed"),
    ):
        main()

    assert not output.exists()


@pytest.mark.parametrize("use_symlink", [False, True])
def test_sftp_download_refuses_existing_file_or_symlink(
    tmp_path: Path, monkeypatch, use_symlink: bool
) -> None:
    registry = Registry(tmp_path / "equipment.db", tmp_path / "encryption.key")
    registry.initialize()
    registry.create(
        EquipmentInput("Supply-FTP", "sftp.example.test", 2222, "test", "SFTP", "admin", sftp_root="/")
    )
    output = tmp_path / "supply.war"
    protected = tmp_path / "protected.war"
    protected.write_bytes(b"keep")
    if use_symlink:
        output.symlink_to(protected)
    else:
        output.write_bytes(b"keep")
    monkeypatch.setenv("EQUIPMENT_REGISTRY_DATA_DIR", str(tmp_path))
    monkeypatch.setattr(
        sys,
        "argv",
        [
            "equipment-registry",
            "sftp-download",
            "Supply-FTP",
            "supply.war",
            "--output",
            str(output),
        ],
    )

    with (
        patch("equipment_registry.cli.download_sftp") as connector,
        pytest.raises(SystemExit) as refusal,
    ):
        main()

    assert refusal.value.code == 2
    connector.assert_not_called()
    assert protected.read_bytes() == b"keep"
    if not use_symlink:
        assert output.read_bytes() == b"keep"


def test_sftp_download_refuses_symlink_in_output_parent(tmp_path: Path, monkeypatch) -> None:
    registry = Registry(tmp_path / "equipment.db", tmp_path / "encryption.key")
    registry.initialize()
    registry.create(
        EquipmentInput("Supply-FTP", "sftp.example.test", 2222, "test", "SFTP", "admin", sftp_root="/")
    )
    real_parent = tmp_path / "real-parent"
    real_parent.mkdir()
    linked_parent = tmp_path / "linked-parent"
    linked_parent.symlink_to(real_parent, target_is_directory=True)
    output = linked_parent / "supply.war"
    monkeypatch.setenv("EQUIPMENT_REGISTRY_DATA_DIR", str(tmp_path))
    monkeypatch.setattr(
        sys,
        "argv",
        [
            "equipment-registry",
            "sftp-download",
            "Supply-FTP",
            "supply.war",
            "--output",
            str(output),
        ],
    )

    with (
        patch(
            "equipment_registry.cli.download_sftp",
            return_value=SFTPDownloadResult(0, "empty"),
        ) as connector,
        pytest.raises(SystemExit) as refusal,
    ):
        main()

    assert refusal.value.code == 2
    connector.assert_not_called()
    assert not (real_parent / "supply.war").exists()


def test_sftp_download_cleanup_never_unlinks_replaced_path(tmp_path: Path, monkeypatch) -> None:
    registry = Registry(tmp_path / "equipment.db", tmp_path / "encryption.key")
    registry.initialize()
    registry.create(
        EquipmentInput("Supply-FTP", "sftp.example.test", 2222, "test", "SFTP", "admin", sftp_root="/")
    )
    output = tmp_path / "supply.war"
    moved = tmp_path / "moved-partial.war"
    monkeypatch.setenv("EQUIPMENT_REGISTRY_DATA_DIR", str(tmp_path))
    monkeypatch.setattr(
        sys,
        "argv",
        [
            "equipment-registry",
            "sftp-download",
            "Supply-FTP",
            "supply.war",
            "--output",
            str(output),
        ],
    )

    def replace_path_then_fail(*args, **kwargs):
        args[4].write(b"partial")
        args[4].flush()
        output.rename(moved)
        output.write_bytes(b"replacement")
        raise RegistryError("transfer failed")

    with (
        patch("equipment_registry.cli.download_sftp", side_effect=replace_path_then_fail),
        pytest.raises(RegistryError, match="transfer failed"),
    ):
        main()

    assert output.read_bytes() == b"replacement"
    assert moved.read_bytes() == b"partial"


def test_sftp_download_rejects_path_replaced_before_success(tmp_path: Path, monkeypatch) -> None:
    registry = Registry(tmp_path / "equipment.db", tmp_path / "encryption.key")
    registry.initialize()
    registry.create(
        EquipmentInput("Supply-FTP", "sftp.example.test", 2222, "test", "SFTP", "admin", sftp_root="/")
    )
    output = tmp_path / "supply.war"
    moved = tmp_path / "moved-complete.war"
    monkeypatch.setenv("EQUIPMENT_REGISTRY_DATA_DIR", str(tmp_path))
    monkeypatch.setattr(
        sys,
        "argv",
        [
            "equipment-registry",
            "sftp-download",
            "Supply-FTP",
            "supply.war",
            "--output",
            str(output),
        ],
    )

    def replace_path_then_succeed(*args, **kwargs):
        args[4].write(b"war-data")
        args[4].flush()
        output.rename(moved)
        output.write_bytes(b"replacement")
        return SFTPDownloadResult(8, "sha256-test")

    with (
        patch("equipment_registry.cli.download_sftp", side_effect=replace_path_then_succeed),
        pytest.raises(RegistryError, match="destino local foi alterado"),
    ):
        main()

    assert output.read_bytes() == b"replacement"
    assert moved.read_bytes() == b"war-data"
