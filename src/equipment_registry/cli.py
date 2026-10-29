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
from .connector import download_sftp, list_sftp, require_ssh, run_command
from .storage import Registry, RegistryError


def data_dir() -> Path:
    return Path(os.environ.get("EQUIPMENT_REGISTRY_DATA_DIR", "~/.local/share/equipment-registry")).expanduser()


def _open_output_parent(path: Path) -> tuple[int, str, Path]:
    absolute = Path(os.path.abspath(path))
    if absolute.name in {"", ".", ".."}:
        raise OSError("Caminho de saída inválido.")
    descriptor = os.open("/", os.O_RDONLY | os.O_DIRECTORY)
    try:
        for component in absolute.parent.parts[1:]:
            next_descriptor = os.open(
                component,
                os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW,
                dir_fd=descriptor,
            )
            os.close(descriptor)
            descriptor = next_descriptor
    except BaseException:
        os.close(descriptor)
        raise
    return descriptor, absolute.name, absolute


def _unlink_output_if_same(parent_descriptor: int, name: str, identity: tuple[int, int]) -> None:
    try:
        current = os.stat(name, dir_fd=parent_descriptor, follow_symlinks=False)
    except FileNotFoundError:
        return
    if (current.st_dev, current.st_ino) == identity:
        os.unlink(name, dir_fd=parent_descriptor)


def _output_path_is_same(
    parent_descriptor: int,
    name: str,
    output: Path,
    identity: tuple[int, int],
) -> bool:
    original_parent = os.fstat(parent_descriptor)
    try:
        reopened_parent, reopened_name, _ = _open_output_parent(output)
    except OSError:
        return False
    try:
        current_parent = os.fstat(reopened_parent)
        current_file = os.stat(reopened_name, dir_fd=reopened_parent, follow_symlinks=False)
    except FileNotFoundError:
        return False
    finally:
        os.close(reopened_parent)
    return (
        (current_parent.st_dev, current_parent.st_ino)
        == (original_parent.st_dev, original_parent.st_ino)
        and (current_file.st_dev, current_file.st_ino) == identity
        and reopened_name == name
    )


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
    subparsers.add_parser(
        "monitor-list", help="Listar alvos autorizados de monitoramento sem credenciais"
    )
    backup_parser = subparsers.add_parser("backup", help="Criar backup SQLite consistente")
    backup_parser.add_argument("--output", required=True, type=Path, help="Novo diretório de backup")
    run_parser = subparsers.add_parser(
        "run", help="Executar comando SSH usando a credencial sem revelá-la"
    )
    run_parser.add_argument("target", help="Nome ou UUID exato no inventário")
    run_parser.add_argument("--command", required=True, help="Comando remoto")
    run_parser.add_argument(
        "--timeout",
        type=int,
        default=30,
        help="Timeout SSH em segundos (1 a 600; padrão: 30)",
    )
    sftp_list_parser = subparsers.add_parser(
        "sftp-list", help="Listar metadados SFTP sem revelar credenciais"
    )
    sftp_list_parser.add_argument("target", help="Nome ou UUID exato no inventário")
    sftp_list_parser.add_argument("--path", default="", help="Diretório relativo à raiz SFTP")
    sftp_download_parser = subparsers.add_parser(
        "sftp-download", help="Baixar arquivo SFTP para um destino local novo"
    )
    sftp_download_parser.add_argument("target", help="Nome ou UUID exato no inventário")
    sftp_download_parser.add_argument("remote_file", help="Arquivo relativo à raiz SFTP")
    sftp_download_parser.add_argument("--output", required=True, type=Path)
    sftp_download_parser.add_argument("--max-bytes", type=int, default=2 * 1024 * 1024 * 1024)
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
    if args.action == "monitor-list":
        print(
            json.dumps(
                [asdict(item) for item in registry.list_monitor_targets()],
                ensure_ascii=False,
                indent=2,
            )
        )
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
    if args.action == "sftp-list":
        item = registry.resolve(args.target)
        require_ssh(item)
        entries = list_sftp(
            item,
            registry.get_password(item.id),
            directory / "known_hosts",
            relative_path=args.path,
        )
        print(json.dumps([asdict(entry) for entry in entries], ensure_ascii=False, indent=2))
        return 0
    if args.action == "sftp-download":
        if args.max_bytes <= 0:
            parser.error("--max-bytes deve ser maior que zero.")
        item = registry.resolve(args.target)
        require_ssh(item)
        try:
            parent_descriptor, output_name, output = _open_output_parent(args.output.expanduser())
        except OSError:
            parser.error("O diretório de saída deve existir e não pode conter symlinks.")
        flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW
        try:
            descriptor = os.open(output_name, flags, 0o600, dir_fd=parent_descriptor)
        except FileExistsError:
            os.close(parent_descriptor)
            parser.error("O arquivo de saída já existe; a sobrescrita foi recusada.")
        identity = os.fstat(descriptor)
        created_identity = (identity.st_dev, identity.st_ino)
        try:
            os.fchmod(descriptor, 0o600)
            destination = os.fdopen(descriptor, "wb")
            descriptor = -1
            with destination:
                result = download_sftp(
                    item,
                    registry.get_password(item.id),
                    directory / "known_hosts",
                    args.remote_file,
                    destination,
                    max_bytes=args.max_bytes,
                )
            if not _output_path_is_same(
                parent_descriptor, output_name, output, created_identity
            ):
                raise RegistryError("O destino local foi alterado durante o download.")
        except BaseException:
            if descriptor >= 0:
                os.close(descriptor)
            _unlink_output_if_same(parent_descriptor, output_name, created_identity)
            raise
        finally:
            os.close(parent_descriptor)
        print(
            json.dumps(
                {"output": str(output), "size": result.size, "sha256": result.sha256},
                ensure_ascii=False,
            )
        )
        return 0
    if args.action == "run":
        if not 1 <= args.timeout <= 600:
            parser.error("--timeout deve estar entre 1 e 600 segundos")
        item = registry.resolve(args.target)
        require_ssh(item)
        result = run_command(
            item,
            registry.get_password(item.id),
            directory / "known_hosts",
            args.command,
            timeout=args.timeout,
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
