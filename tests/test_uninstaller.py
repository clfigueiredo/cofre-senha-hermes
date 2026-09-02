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