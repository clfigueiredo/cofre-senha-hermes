from __future__ import annotations

import argparse
import getpass
import ipaddress
import json
import os
import shutil
import sys
from dataclasses import asdict
from pathlib import Path

from waitress import serve

from .app import create_app
from .auth import create_admin
from .connector import fingerprint_host, run_command, trust_host
from .storage import Registry


def data_dir() -> Path:
    return Path(os.environ.get("EQUIPMENT_REGISTRY_DATA_DIR", "~/.local/share/equipment-registry")).expanduser()


def main() -> int:
    parser = argparse.ArgumentParser(description="Cadastro seguro de equipamentos")
    subparsers = parser.add_subparsers(dest="action", required=True)
    init_parser = subparsers.add_parser("init", help="Inicializar banco, chaves e administrador")
    init_parser.add_argument(
        "--force", action="store_true", help="Substituir deliberadamente o administrador existente"
    )
    serve_parser = subparsers.add_parser("serve", help="Iniciar interface web local")
    serve_parser.add_argument("--host", default="127.0.0.1")
    serve_parser.add_argument("--port", type=int, default=8787)
    subparsers.add_parser("list", help="Listar equipamentos sem revelar senhas")
    backup_parser = subparsers.add_parser("backup", help="Criar backup SQLite consistente")
    backup_parser.add_argument("--output", required=True, type=Path, help="Novo diretório de backup")
    fingerprint_parser = subparsers.add_parser(
        "fingerprint", help="Consultar a chave SSH apresentada pelo equipamento"
    )
    fingerprint_parser.add_argument("target", help="Nome ou UUID exato no inventário")
    trust_parser = subparsers.add_parser(
        "trust-host-key", help="Confiar numa chave SSH após validar o fingerprint"
    )
    trust_parser.add_argument("target", help="Nome ou UUID exato no inventário")
    trust_parser.add_argument("--fingerprint", required=True, help="Fingerprint SHA256 esperado")
    run_parser = subparsers.add_parser(
        "run", help="Executar comando SSH usando a credencial sem revelá-la"
    )
    run_parser.add_argument("target", help="Nome ou UUID exato no inventário")
    run_parser.add_argument("--command", required=True, help="Comando remoto")
    args = parser.parse_args()

    directory = data_dir()
    registry = Registry(directory / "equipment.db", directory / "encryption.key")
    registry.initialize()

    if args.action == "init":
        if (directory / "auth.json").exists() and not args.force:
            parser.error("Administrador já existe. Use --force somente para uma redefinição deliberada.")
        password = getpass.getpass("Nova senha administrativa: ")
        confirmation = getpass.getpass("Confirme a senha administrativa: ")
        if password != confirmation:
            parser.error("As senhas não conferem.")
        create_admin(directory / "auth.json", password)
        print(f"Inicializado em {directory}")
        return 0
    if args.action == "list":
        print(json.dumps([asdict(item) for item in registry.list_equipment()], ensure_ascii=False, indent=2))
        return 0
    if args.action == "backup":
        output = args.output.expanduser()
        if output.exists():
            parser.error("O diretório de backup já existe; escolha um caminho novo.")
        output.mkdir(parents=True, mode=0o700)
        registry.backup_database(output / "equipment.db")
        for filename in ("encryption.key", "auth.json", "session.key", "known_hosts"):
            source = directory / filename
            if source.exists():
                shutil.copy2(source, output / filename)
                os.chmod(output / filename, 0o600)
        print(f"Backup consistente criado em {output}")
        return 0
    if args.action == "fingerprint":
        item = registry.resolve(args.target)
        print(fingerprint_host(item))
        return 0
    if args.action == "trust-host-key":
        item = registry.resolve(args.target)
        trust_host(item, directory / "known_hosts", args.fingerprint)
        print(f"Chave SSH registrada para {item.name}.")
        return 0
    if args.action == "run":
        item = registry.resolve(args.target)
        result = run_command(
            item,
            registry.get_password(item.id),
            directory / "known_hosts",
            args.command,
        )
        if result.stdout:
            print(result.stdout, end="" if result.stdout.endswith("\n") else "\n")
        if result.stderr:
            print(result.stderr, end="" if result.stderr.endswith("\n") else "\n", file=sys.stderr)
        return result.exit_status
    if args.host not in {"127.0.0.1", "::1", "localhost"}:
        try:
            address = ipaddress.ip_address(args.host)
        except ValueError:
            parser.error("Use localhost ou um endereço IP literal válido.")
        if not address.is_private or address.is_unspecified:
            parser.error("O bind remoto só pode usar um endereço IP privado específico.")
        if os.environ.get("EQUIPMENT_REGISTRY_ALLOW_REMOTE") != "1":
            parser.error("Acesso à LAN exige EQUIPMENT_REGISTRY_ALLOW_REMOTE=1.")
        if os.environ.get("EQUIPMENT_REGISTRY_ALLOW_INSECURE_HTTP") != (
            "I_ACCEPT_PRIVATE_LAN_RISK"
        ):
            parser.error(
                "HTTP na LAN exige confirmação explícita do risco com "
                "EQUIPMENT_REGISTRY_ALLOW_INSECURE_HTTP=I_ACCEPT_PRIVATE_LAN_RISK."
            )
        if not (directory / "auth.json").exists():
            parser.error("Crie o administrador localmente antes de liberar acesso pela LAN.")
    application = create_app()
    serve(application, host=args.host, port=args.port, threads=4)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
