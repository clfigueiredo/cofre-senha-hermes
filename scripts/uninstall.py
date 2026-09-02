#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import os
import shutil
import subprocess  # nosec B404
import tempfile
from datetime import UTC, datetime
from pathlib import Path

POLICY_START = "<!-- cofre-senhas-hermes:policy:start -->"
POLICY_END = "<!-- cofre-senhas-hermes:policy:end -->"


def run_checked(command: list[str]) -> None:
    subprocess.run(command, check=True)  # nosec B603


def uninstall_command(home: Path, uv: str) -> None:
    executable = home / ".local" / "bin" / "equipment-registry"
    result = subprocess.run(  # nosec B603
        [uv, "tool", "uninstall", "cofre-senhas-hermes"], check=False
    )
    if executable.exists():
        detail = f" (uv retornou {result.returncode})" if result.returncode else ""
        raise SystemExit(f"Falha ao desinstalar o comando equipment-registry{detail}.")


def remove_policy(hermes_home: Path) -> None:
    soul = hermes_home / "SOUL.md"
    if not soul.exists():
        return
    content = soul.read_text(encoding="utf-8")
    if POLICY_START not in content or POLICY_END not in content:
        return
    before, remainder = content.split(POLICY_START, 1)
    _, after = remainder.split(POLICY_END, 1)
    stamp = datetime.now(UTC).strftime("%Y%m%dT%H%M%S%fZ")
    shutil.copy2(soul, soul.with_name(f"SOUL.md.backup-{stamp}"))
    temporary = soul.with_suffix(".tmp")
    temporary.write_text(before.rstrip() + "\n" + after.lstrip("\n"), encoding="utf-8")
    os.chmod(temporary, 0o600)
    temporary.replace(soul)


def main() -> int:
    parser = argparse.ArgumentParser(description="Desinstalar o Cofre de Senhas Hermes")
    parser.add_argument("--purge-data", action="store_true")
    parser.add_argument("--confirm", help="Confirmação literal exigida para apagar os dados")
    args = parser.parse_args()
    if args.purge_data and args.confirm != "PURGE EQUIPMENT REGISTRY":
        parser.error("A purga exige --confirm 'PURGE EQUIPMENT REGISTRY'.")

    home = Path.home()
    hermes_home = Path(os.environ.get("HERMES_HOME", home / ".hermes")).expanduser()
    manifest = hermes_home / "cofre-senhas-hermes.json"
    if manifest.exists():
        try:
            metadata = json.loads(manifest.read_text(encoding="utf-8"))
            data_dir = Path(metadata["data_dir"]).expanduser()
        except (OSError, KeyError, TypeError, json.JSONDecodeError) as exc:
            raise SystemExit("Manifesto de instalação inválido; desinstalação interrompida.") from exc
    else:
        data_dir = home / ".local" / "share" / "equipment-registry"
    unit = home / ".config" / "systemd" / "user" / "cofre-senhas-hermes.service"
    if unit.exists():
        systemctl = shutil.which("systemctl")
        if not systemctl:
            raise SystemExit("systemctl não encontrado; serviço não foi removido.")
        run_checked([systemctl, "--user", "disable", "--now", unit.name])
        unit.unlink()
        run_checked([systemctl, "--user", "daemon-reload"])
        active = subprocess.run(  # nosec B603
            [systemctl, "--user", "is-active", "--quiet", unit.name], check=False
        )
        if active.returncode == 0:
            raise SystemExit("O serviço ainda está ativo; desinstalação interrompida.")

    uv = shutil.which("uv") or str(home / ".hermes" / "bin" / "uv")
    executable = home / ".local" / "bin" / "equipment-registry"
    if Path(uv).is_file():
        uninstall_command(home, uv)
    elif executable.exists():
        raise SystemExit("uv não encontrado; o comando equipment-registry não foi removido.")

    skill = hermes_home / "skills" / "forumtelecom" / "equipment-registry-ops"
    if skill.exists():
        stamp = datetime.now(UTC).strftime("%Y%m%dT%H%M%S%fZ")
        backup = hermes_home / "backups" / "cofre-senhas-hermes" / stamp / "equipment-registry-ops"
        backup.parent.mkdir(parents=True, exist_ok=True)
        shutil.move(skill, backup)
    remove_policy(hermes_home)
    if skill.exists():
        raise SystemExit("Falha ao remover a skill instalada.")
    soul = hermes_home / "SOUL.md"
    if soul.exists() and POLICY_START in soul.read_text(encoding="utf-8"):
        raise SystemExit("Falha ao remover a política instalada.")

    if args.purge_data and data_dir.exists():
        resolved = data_dir.resolve()
        forbidden = {
            Path("/"),
            home.resolve(),
            home.parent.resolve(),
            Path(tempfile.gettempdir()).resolve(),
            Path("/var"),
        }
        if resolved in forbidden or not (resolved / "equipment.db").exists():
            raise SystemExit(f"Purga recusada para caminho inseguro ou inesperado: {resolved}")
        shutil.rmtree(data_dir)
        print(f"Dados removidos: {data_dir}")
    elif data_dir.exists():
        print(f"Dados preservados: {data_dir}")
    if args.purge_data and manifest.exists():
        manifest.unlink()
    print("UNINSTALL_OK")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
