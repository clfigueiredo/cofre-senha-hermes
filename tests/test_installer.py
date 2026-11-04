from __future__ import annotations

import importlib.util
from pathlib import Path

INSTALLER = Path(__file__).parents[1] / "scripts" / "install.py"
spec = importlib.util.spec_from_file_location("cofre_installer", INSTALLER)
assert spec and spec.loader
installer = importlib.util.module_from_spec(spec)
spec.loader.exec_module(installer)


def test_installer_does_not_touch_soul_md() -> None:
    source = INSTALLER.read_text(encoding="utf-8")
    assert "SOUL.md" not in source
    assert not hasattr(installer, "install_policy")


def test_skill_install_copies_skill_and_backs_up_previous(tmp_path: Path) -> None:
    root = Path(__file__).parents[1]
    hermes_home = tmp_path / ".hermes"
    installer.install_skill(root, hermes_home)
    installer.install_skill(root, hermes_home)
    skill = hermes_home / "skills" / "forumtelecom" / "equipment-registry-ops" / "SKILL.md"
    assert skill.is_file()
    assert list((hermes_home / "backups" / "cofre-senhas-hermes").iterdir())
    assert not (hermes_home / "SOUL.md").exists()


def test_systemd_quote_escapes_values_and_rejects_newlines() -> None:
    import pytest

    assert installer.systemd_quote('/home/Test User/"vault"') == '"/home/Test User/\\"vault\\""'
    with pytest.raises(SystemExit, match="Valor inválido"):
        installer.systemd_quote("safe\nInjected=1")
