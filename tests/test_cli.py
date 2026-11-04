from __future__ import annotations

import sys
from pathlib import Path
from unittest.mock import patch

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


def test_serve_listens_on_all_interfaces_by_default(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.setenv("EQUIPMENT_REGISTRY_DATA_DIR", str(tmp_path))
    monkeypatch.setattr(sys, "argv", ["equipment-registry", "serve"])
    with patch("equipment_registry.cli.serve") as waitress:
        assert main() == 0
    assert waitress.call_args.kwargs["host"] == "0.0.0.0"
    assert waitress.call_args.kwargs["port"] == 8787


def test_serve_accepts_explicit_lan_host(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.setenv("EQUIPMENT_REGISTRY_DATA_DIR", str(tmp_path))
    monkeypatch.setattr(
        sys, "argv", ["equipment-registry", "serve", "--host", "192.168.1.10", "--port", "9000"]
    )
    with patch("equipment_registry.cli.serve") as waitress:
        assert main() == 0
    assert waitress.call_args.kwargs["host"] == "192.168.1.10"
    assert waitress.call_args.kwargs["port"] == 9000
