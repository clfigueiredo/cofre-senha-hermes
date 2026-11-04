from __future__ import annotations

import importlib.util
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

import pytest

UNINSTALLER = Path(__file__).parents[1] / "scripts" / "uninstall.py"
spec = importlib.util.spec_from_file_location("cofre_uninstaller", UNINSTALLER)
assert spec and spec.loader
uninstaller = importlib.util.module_from_spec(spec)
spec.loader.exec_module(uninstaller)


def test_uv_success_does_not_hide_stale_executable(tmp_path: Path) -> None:
    executable = tmp_path / ".local" / "bin" / "equipment-registry"
    executable.parent.mkdir(parents=True)
    executable.write_text("stale", encoding="utf-8")
    with (
        patch("subprocess.run", return_value=SimpleNamespace(returncode=0)),
        pytest.raises(SystemExit, match="Falha ao desinstalar"),
    ):
        uninstaller.uninstall_command(tmp_path, "/usr/bin/uv")

def test_uninstall_removes_legacy_policy_block_only(tmp_path: Path) -> None:
    soul = tmp_path / "SOUL.md"
    legacy = f"{uninstaller.POLICY_START}\nantiga\n{uninstaller.POLICY_END}\n"
    soul.write_text(
        "# Minha alma\n\n" + legacy,
        encoding="utf-8",
    )
    uninstaller.remove_policy(tmp_path)
    content = soul.read_text(encoding="utf-8")
    assert "# Minha alma" in content
    assert uninstaller.POLICY_START not in content
