from __future__ import annotations

import importlib.util
from pathlib import Path

INSTALLER = Path(__file__).parents[1] / "scripts" / "install.py"
spec = importlib.util.spec_from_file_location("cofre_installer", INSTALLER)
assert spec and spec.loader
installer = importlib.util.module_from_spec(spec)
spec.loader.exec_module(installer)


def test_policy_install_is_idempotent_and_creates_backup(tmp_path: Path) -> None:
    hermes_home = tmp_path / ".hermes"
    hermes_home.mkdir()
    soul = hermes_home / "SOUL.md"
    soul.write_text("# Existing policy\n", encoding="utf-8")

    installer.install_policy(hermes_home)
    first = soul.read_text(encoding="utf-8")
    installer.install_policy(hermes_home)
    second = soul.read_text(encoding="utf-8")

    assert first == second
    assert first.count(installer.POLICY_START) == 1
    assert first.count(installer.POLICY_END) == 1
    assert list(hermes_home.glob("SOUL.md.backup-*"))


def test_private_remote_host_validation_logic() -> None:
    import ipaddress

    assert ipaddress.ip_address("10.0.0.10").is_private
    assert not ipaddress.ip_address("8.8.8.8").is_private
    assert ipaddress.ip_address("0.0.0.0").is_unspecified
    assert ipaddress.ip_address("::").is_unspecified


def test_systemd_quote_escapes_values_and_rejects_newlines() -> None:
    import pytest

    assert installer.systemd_quote('/home/Test User/"vault"') == '"/home/Test User/\\"vault\\""'
    with pytest.raises(SystemExit, match="Valor inválido"):
        installer.systemd_quote("safe\nInjected=1")
