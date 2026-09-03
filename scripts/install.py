#!/usr/bin/env python3
from __future__ import annotations

import argparse
import ipaddress
import json
import os
import shutil

# All subprocess calls use fixed executable paths and argv lists without a shell.
import subprocess  # nosec B404
from datetime import UTC, datetime
from pathlib import Path

POLICY_START = "<!-- cofre-senhas-hermes:policy:start -->"
POLICY_END = "<!-- cofre-senhas-hermes:policy:end -->"
POLICY = f"""{POLICY_START}
## Política obrigatória do inventário de equipamentos

Antes de qualquer tentativa de acessar, consultar, diagnosticar, configurar ou administrar um equipamento de infraestrutura, carregue e siga a skill `equipment-registry-ops` e resolva o alvo no inventário local. Não use credenciais lembradas do chat, histórico, memória, anotações ou acesso anterior para contornar o inventário. Se o alvo estiver ausente, ambíguo ou incompleto, interrompa o acesso e solicite o cadastro ou a correção.

Jamais revele, repita, retorne, registre ou persista senhas de equipamentos em mensagens, logs, memória ou argumentos de comandos. A senha só pode ser descriptografada dentro do conector autorizado durante a conexão e deve permanecer apenas na memória do processo pelo tempo necessário.
{POLICY_END}
"""


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


def install_policy(hermes_home: Path) -> None:
    soul = hermes_home / "SOUL.md"
    hermes_home.mkdir(parents=True, exist_ok=True, mode=0o700)
    original = soul.read_text(encoding="utf-8") if soul.exists() else ""
    if POLICY_START in original and POLICY_END in original:
        before, remainder = original.split(POLICY_START, 1)
        _, after = remainder.split(POLICY_END, 1)
        updated = before.rstrip() + "\n\n" + POLICY + after.lstrip("\n")
    else:
        updated = original.rstrip() + ("\n\n" if original.strip() else "") + POLICY
    if updated != original:
        if soul.exists():
            stamp = datetime.now(UTC).strftime("%Y%m%dT%H%M%S%fZ")
            shutil.copy2(soul, soul.with_name(f"SOUL.md.backup-{stamp}"))
        temporary = soul.with_suffix(".tmp")
        temporary.write_text(updated, encoding="utf-8")
        os.chmod(temporary, 0o600)
        temporary.replace(soul)


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


def install_service(host: str, port: int, data_dir: Path, insecure_private_lan: bool) -> None:
    systemd_dir = Path.home() / ".config" / "systemd" / "user"
    systemd_dir.mkdir(parents=True, exist_ok=True)
    allow_remote = "1" if host not in {"127.0.0.1", "::1", "localhost"} else "0"
    insecure_ack = "I_ACCEPT_PRIVATE_LAN_RISK" if insecure_private_lan else ""
    unit = f"""[Unit]
Description=Cofre de Senhas Hermes
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
Environment={systemd_quote(f"EQUIPMENT_REGISTRY_ALLOW_REMOTE={allow_remote}")}
Environment={systemd_quote(f"EQUIPMENT_REGISTRY_ALLOW_INSECURE_HTTP={insecure_ack}")}
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
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=8787)
    parser.add_argument("--service", action="store_true", help="Criar e iniciar serviço systemd do usuário")
    parser.add_argument(
        "--insecure-private-lan",
        action="store_true",
        help="Aceitar explicitamente HTTP sem TLS ao usar um IP privado",
    )
    parser.add_argument("--skip-tests", action="store_true")
    args = parser.parse_args()
    if not 1 <= args.port <= 65535:
        parser.error("A porta deve estar entre 1 e 65535.")
    if args.host not in {"127.0.0.1", "::1", "localhost"}:
        try:
            address = ipaddress.ip_address(args.host)
        except ValueError:
            parser.error("Use localhost ou um endereço IP literal válido.")
        if not address.is_private or address.is_unspecified:
            parser.error("O instalador só permite bind remoto em endereço IP privado.")
        if not args.insecure_private_lan:
            parser.error("Bind na LAN exige --insecure-private-lan para aceitar o risco sem TLS.")

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
    install_policy(hermes_home)
    manifest.write_text(
        json.dumps({"version": "1.1.0", "data_dir": str(data_dir.resolve())}, indent=2) + "\n",
        encoding="utf-8",
    )
    os.chmod(manifest, 0o600)
    if args.service:
        auth_path = data_dir / "auth.json"
        if args.host not in {"127.0.0.1", "::1", "localhost"} and not auth_path.exists():
            raise SystemExit(
                "Recusado: defina primeiro o administrador com 'equipment-registry init' "
                "antes de iniciar um serviço acessível pela rede privada."
            )
        install_service(args.host, args.port, data_dir, args.insecure_private_lan)

    print("INSTALL_OK")
    print(f"Dados: {data_dir}")
    print(f"Skill: {hermes_home / 'skills/forumtelecom/equipment-registry-ops'}")
    print("Abra uma nova sessão do Hermes para carregar a política e a skill.")
    if args.service:
        print(f"Interface: http://{args.host}:{args.port}/setup")
    else:
        remote = ""
        if args.host not in {"127.0.0.1", "::1", "localhost"}:
            remote = (
                "EQUIPMENT_REGISTRY_ALLOW_REMOTE=1 "
                "EQUIPMENT_REGISTRY_ALLOW_INSECURE_HTTP=I_ACCEPT_PRIVATE_LAN_RISK "
            )
        print(f"Inicie: {remote}equipment-registry serve --host {args.host} --port {args.port}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
