#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import os
import shutil

# All subprocess calls use fixed executable paths and argv lists without a shell.
import subprocess  # nosec B404
from datetime import UTC, datetime
from pathlib import Path

# Interface web acessível na rede local por padrão (cadastro pelo navegador).
DEFAULT_HOST = "0.0.0.0"  # nosec B104


def run(command: list[str], *, cwd: Path | None = None, env: dict[str, str] | None = None) -> None:
    subprocess.run(command, cwd=cwd, env=env, check=True)  # nosec B603


def find_uv() -> str:
    candidates = [shutil.which("uv"), str(Path.home() / ".hermes" / "bin" / "uv")]
    for candidate in candidates:
        if candidate and Path(candidate).is_file():
            return candidate
    raise SystemExit("uv não encontrado. Instale o Hermes Agent ou o uv antes de continuar.")


def systemd_quote(value: str) -> str:
    if any(character in value for character in ("\n", "\r", "\x00")):
        raise SystemExit("Valor inválido para a unidade systemd.")
    return '"' + value.replace("\\", "\\\\").replace('"', '\\"') + '"'


def install_skill(root: Path, hermes_home: Path) -> None:
    source = root / "skill" / "equipment-registry-ops"
    destination = hermes_home / "skills" / "forumtelecom" / "equipment-registry-ops"
    if destination.exists():
        stamp = datetime.now(UTC).strftime("%Y%m%dT%H%M%S%fZ")
        backup = hermes_home / "backups" / "cofre-senhas-hermes" / stamp / "equipment-registry-ops"
        backup.parent.mkdir(parents=True, exist_ok=True)
        shutil.move(destination, backup)
    destination.parent.mkdir(parents=True, exist_ok=True)
    shutil.copytree(source, destination)


def install_service(host: str, port: int, data_dir: Path) -> None:
    systemd_dir = Path.home() / ".config" / "systemd" / "user"
    systemd_dir.mkdir(parents=True, exist_ok=True)
    unit = f"""[Unit]
Description=Cofre de Senhas Hermes
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
Environment={systemd_quote(f"EQUIPMENT_REGISTRY_DATA_DIR={data_dir}")}
ExecStart={systemd_quote(str(Path.home() / ".local/bin/equipment-registry"))} serve --host {host} --port {port}
Restart=on-failure
RestartSec=3
NoNewPrivileges=true
PrivateTmp=true
ProtectSystem=strict
ReadWritePaths={systemd_quote(str(data_dir))}

[Install]
WantedBy=default.target
"""
    path = systemd_dir / "cofre-senhas-hermes.service"
    path.write_text(unit, encoding="utf-8")
    run(["systemctl", "--user", "daemon-reload"])
    run(["systemctl", "--user", "enable", "--now", path.name])


def main() -> int:
    parser = argparse.ArgumentParser(description="Instalar o Cofre de Senhas Hermes")
    parser.add_argument(
        "--host",
        default=DEFAULT_HOST,
        help="Endereço de escuta da interface web (padrão: todas as interfaces)",
    )
    parser.add_argument("--port", type=int, default=8787)
    parser.add_argument("--service", action="store_true", help="Criar e iniciar serviço systemd do usuário")
    parser.add_argument("--skip-tests", action="store_true")
    args = parser.parse_args()
    if not 1 <= args.port <= 65535:
        parser.error("A porta deve estar entre 1 e 65535.")

    root = Path(__file__).resolve().parents[1]
    hermes_home = Path(os.environ.get("HERMES_HOME", Path.home() / ".hermes")).expanduser()
    uv = find_uv()
    run([uv, "sync", "--frozen", "--extra", "dev"], cwd=root)
    if not args.skip_tests:
        run([uv, "run", "pytest", "-q"], cwd=root)
    run([uv, "tool", "install", "--force", "."], cwd=root)

    data_dir = Path(
        os.environ.get(
            "EQUIPMENT_REGISTRY_DATA_DIR",
            Path.home() / ".local" / "share" / "equipment-registry",
        )
    ).expanduser()
    manifest = hermes_home / "cofre-senhas-hermes.json"
    if manifest.exists():
        try:
            installed_data_dir = Path(
                json.loads(manifest.read_text(encoding="utf-8"))["data_dir"]
            )
        except (OSError, KeyError, TypeError, json.JSONDecodeError) as exc:
            raise SystemExit("Manifesto de instalação existente é inválido.") from exc
        if installed_data_dir.resolve() != data_dir.resolve():
            raise SystemExit(
                f"Instalação existente usa {installed_data_dir}; "
                "desinstale ou mantenha o mesmo EQUIPMENT_REGISTRY_DATA_DIR."
            )
    env = os.environ.copy()
    env["EQUIPMENT_REGISTRY_DATA_DIR"] = str(data_dir)
    run([str(Path.home() / ".local" / "bin" / "equipment-registry"), "list"], env=env)
    install_skill(root, hermes_home)
    manifest.write_text(
        json.dumps({"version": "1.2.0", "data_dir": str(data_dir.resolve())}, indent=2) + "\n",
        encoding="utf-8",
    )
    os.chmod(manifest, 0o600)
    if args.service:
        install_service(args.host, args.port, data_dir)

    print("INSTALL_OK")
    print(f"Dados: {data_dir}")
    print(f"Skill: {hermes_home / 'skills/forumtelecom/equipment-registry-ops'}")
    print("Abra uma nova sessão do Hermes para carregar a skill.")
    shown_host = "<ip-deste-servidor>" if args.host in {DEFAULT_HOST, "::"} else args.host
    if args.service:
        print(f"Interface: http://{shown_host}:{args.port}/")
    else:
        print(f"Inicie: equipment-registry serve --host {args.host} --port {args.port}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
