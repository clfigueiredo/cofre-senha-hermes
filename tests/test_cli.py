from __future__ import annotations

import sys
from pathlib import Path
from unittest.mock import patch

import pytest

from equipment_registry.auth import create_admin
from equipment_registry.cli import main
from equipment_registry.connector import CommandResult
from equipment_registry.storage import EquipmentInput, Registry


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
