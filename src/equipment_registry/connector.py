from __future__ import annotations

import asyncio
import fcntl
import hashlib
import os
import time
from collections.abc import Iterator
from contextlib import contextmanager
from dataclasses import dataclass
from pathlib import Path, PurePosixPath
from typing import BinaryIO

import asyncssh

from .storage import Equipment, RegistryError


@dataclass(frozen=True, slots=True)
class CommandResult:
    exit_status: int
    stdout: str
    stderr: str


@dataclass(frozen=True, slots=True)
class SFTPEntry:
    name: str
    relative_path: str
    kind: str
    size: int | None
    modified_at: int | None


@dataclass(frozen=True, slots=True)
class SFTPDownloadResult:
    size: int
    sha256: str


def _host_label(item: Equipment) -> str:
    return item.ip if item.ssh_port == 22 else f"[{item.ip}]:{item.ssh_port}"


def known_host_alias(item: Equipment) -> str:
    """Keep the logical target identity stable while AsyncSSH scopes the transport port."""
    return item.ip


def require_ssh(item: Equipment) -> None:
    """Fail closed before credentials, TOFU, relay or any network operation."""
    if item.access_type != "ssh":
        raise RegistryError("Equipamento offline: use somente o console local; SSH/SFTP bloqueado.")


def connection_endpoint(item: Equipment) -> tuple[str, int]:
    """Return the approved transport endpoint without changing target identity."""
    require_ssh(item)
    if item.relay_host is not None and item.relay_port is not None:
        return item.relay_host, item.relay_port
    return item.ip, item.ssh_port


def _known_hosts_for_target(item: Equipment, known_hosts_path: Path):
    """Load only the key pinned for the exact logical equipment identity."""
    label = _host_label(item)
    content = known_hosts_path.read_text(encoding="ascii")
    exact_lines = [
        line
        for line in content.splitlines()
        if line.strip() and line.split(None, 1)[0] == label
    ]
    if not exact_lines:
        raise RegistryError("A chave SSH fixada do equipamento não foi encontrada.")

    known_hosts = asyncssh.import_known_hosts("\n".join(exact_lines) + "\n")
    logical_port = item.ssh_port if item.ssh_port != 22 else None
    matched = known_hosts.match(item.ip, "", logical_port)
    if not matched[0]:
        raise RegistryError("A chave SSH fixada do equipamento não foi encontrada.")
    return matched


@contextmanager
def _host_key_lock(known_hosts_path: Path) -> Iterator[None]:
    known_hosts_path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    lock_path = known_hosts_path.with_suffix(".lock")
    descriptor = os.open(lock_path, os.O_CREAT | os.O_RDWR, 0o600)
    try:
        os.fchmod(descriptor, 0o600)
        fcntl.flock(descriptor, fcntl.LOCK_EX)
        yield
    finally:
        fcntl.flock(descriptor, fcntl.LOCK_UN)
        os.close(descriptor)


async def _fetch_host_key(item: Equipment) -> asyncssh.SSHKey:
    host, port = connection_endpoint(item)
    key = await asyncssh.get_server_host_key(host, port)
    if key is None:
        raise RegistryError("O equipamento não apresentou uma chave SSH.")
    return key


def trust_host_on_first_use(
    item: Equipment,
    known_hosts_path: Path,
    *,
    timeout: float = 30,
) -> None:
    """Register an unknown host key once and pin it for later connections."""
    require_ssh(item)
    label = _host_label(item)
    existing = known_hosts_path.read_text(encoding="ascii") if known_hosts_path.exists() else ""
    if any(line.split(" ", 1)[0] == label for line in existing.splitlines() if line.strip()):
        return

    key = asyncio.run(asyncio.wait_for(_fetch_host_key(item), timeout))
    with _host_key_lock(known_hosts_path):
        existing = known_hosts_path.read_text(encoding="ascii") if known_hosts_path.exists() else ""
        if any(line.split(" ", 1)[0] == label for line in existing.splitlines() if line.strip()):
            return

        line = f"{label} {key.export_public_key('openssh').decode('ascii').strip()}\n"
        temporary = known_hosts_path.with_suffix(".tmp")
        temporary.write_text(
            existing.rstrip("\n") + ("\n" if existing else "") + line,
            encoding="ascii",
        )
        os.chmod(temporary, 0o600)
        temporary.replace(known_hosts_path)
        os.chmod(known_hosts_path, 0o600)


async def _run_command(
    item: Equipment,
    password: str,
    known_hosts_path: Path,
    command: str,
    timeout: float,
) -> CommandResult:
    host, port = connection_endpoint(item)
    trusted_host_keys = _known_hosts_for_target(item, known_hosts_path)
    async with asyncssh.connect(
        host,
        port=port,
        username=item.username,
        password=password,
        known_hosts=trusted_host_keys,
        host_key_alias=known_host_alias(item),
        client_keys=[],
        agent_path=None,
        connect_timeout=timeout,
        login_timeout=timeout,
    ) as connection:
        result = await connection.run(command, check=False, timeout=timeout)
    status = result.exit_status if result.exit_status is not None else 255
    return CommandResult(status, str(result.stdout), str(result.stderr))


def run_command(
    item: Equipment,
    password: str,
    known_hosts_path: Path,
    command: str,
    *,
    timeout: float = 30,
) -> CommandResult:
    require_ssh(item)
    if not command.strip():
        raise RegistryError("O comando remoto não pode ser vazio.")
    trust_host_on_first_use(item, known_hosts_path, timeout=timeout)
    return asyncio.run(_run_command(item, password, known_hosts_path, command, timeout))


def _validate_relative_sftp_path(value: str) -> PurePosixPath:
    if value == "":
        return PurePosixPath(".")
    components = value.split("/")
    if (
        len(value) > 1024
        or value.startswith("/")
        or "\\" in value
        or any(ord(character) < 32 or ord(character) == 127 for character in value)
        or any(component in {"", ".", ".."} for component in components)
    ):
        raise RegistryError("Informe um caminho SFTP relativo e seguro.")
    return PurePosixPath(*components)


async def _list_sftp(
    item: Equipment,
    password: str,
    known_hosts_path: Path,
    relative_path: PurePosixPath,
    timeout: float,
    max_entries: int,
) -> list[SFTPEntry]:
    host, port = connection_endpoint(item)
    trusted_host_keys = _known_hosts_for_target(item, known_hosts_path)
    async with asyncssh.connect(
        host,
        port=port,
        username=item.username,
        password=password,
        known_hosts=trusted_host_keys,
        host_key_alias=known_host_alias(item),
        client_keys=[],
        agent_path=None,
        connect_timeout=timeout,
        login_timeout=timeout,
    ) as connection, connection.start_sftp_client(
        path_encoding="utf-8", path_errors="strict"
    ) as sftp:
        configured_root_attrs = await sftp.lstat(item.sftp_root)
        if configured_root_attrs.type != asyncssh.FILEXFER_TYPE_DIRECTORY:
            raise RegistryError("A raiz SFTP configurada não é um diretório seguro.")
        root_value = await sftp.realpath(item.sftp_root)
        if not isinstance(root_value, str):
            raise RegistryError("O servidor SFTP retornou um caminho inválido.")
        root = PurePosixPath(root_value)

        requested = root
        requested_attrs = configured_root_attrs
        if relative_path != PurePosixPath("."):
            for component in relative_path.parts:
                requested /= component
                requested_attrs = await sftp.lstat(str(requested))
                if requested_attrs.type == asyncssh.FILEXFER_TYPE_SYMLINK:
                    raise RegistryError("O caminho SFTP não pode atravessar um symlink.")

        target_value = await sftp.realpath(str(requested))
        if not isinstance(target_value, str):
            raise RegistryError("O servidor SFTP retornou um caminho inválido.")
        target = PurePosixPath(target_value)
        if target != root and not target.is_relative_to(root):
            raise RegistryError("O caminho solicitado está fora da raiz SFTP permitida.")
        target_attrs = (
            requested_attrs if target == requested else await sftp.lstat(str(target))
        )
        if target_attrs.type != asyncssh.FILEXFER_TYPE_DIRECTORY:
            raise RegistryError("O caminho SFTP solicitado não é um diretório seguro.")

        entries: list[SFTPEntry] = []
        async for entry in sftp.scandir(str(target)):
            if len(entries) >= max_entries:
                raise RegistryError("O diretório SFTP excede o limite de entradas permitido.")
            name = entry.filename
            if (
                not isinstance(name, str)
                or name in {"", ".", ".."}
                or "/" in name
                or "\\" in name
                or any(ord(character) < 32 or ord(character) == 127 for character in name)
            ):
                raise RegistryError("O servidor SFTP retornou um nome de arquivo inválido.")
            kind = {
                asyncssh.FILEXFER_TYPE_REGULAR: "file",
                asyncssh.FILEXFER_TYPE_DIRECTORY: "directory",
                asyncssh.FILEXFER_TYPE_SYMLINK: "symlink",
            }.get(entry.attrs.type, "other")
            child_path = relative_path / name
            entries.append(
                SFTPEntry(
                    name,
                    name if relative_path == PurePosixPath(".") else str(child_path),
                    kind,
                    entry.attrs.size,
                    entry.attrs.mtime,
                )
            )
    return entries


def list_sftp(
    item: Equipment,
    password: str,
    known_hosts_path: Path,
    *,
    relative_path: str = "",
    timeout: float = 30,
    max_entries: int = 1000,
) -> list[SFTPEntry]:
    require_ssh(item)
    if item.sftp_root is None:
        raise RegistryError("SFTP não está habilitado para este equipamento.")
    safe_path = _validate_relative_sftp_path(relative_path)
    deadline = time.monotonic() + timeout
    try:
        trust_host_on_first_use(item, known_hosts_path, timeout=timeout)
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise TimeoutError
        return asyncio.run(
            asyncio.wait_for(
                _list_sftp(item, password, known_hosts_path, safe_path, timeout, max_entries),
                timeout=remaining,
            )
        )
    except TimeoutError as exc:
        raise RegistryError("A operação SFTP excedeu o tempo limite permitido.") from exc


async def _download_sftp(
    item: Equipment,
    password: str,
    known_hosts_path: Path,
    relative_path: PurePosixPath,
    destination: BinaryIO,
    max_bytes: int,
    timeout: float,
) -> SFTPDownloadResult:
    host, port = connection_endpoint(item)
    trusted_host_keys = _known_hosts_for_target(item, known_hosts_path)
    async with asyncssh.connect(
        host,
        port=port,
        username=item.username,
        password=password,
        known_hosts=trusted_host_keys,
        host_key_alias=known_host_alias(item),
        client_keys=[],
        agent_path=None,
        connect_timeout=timeout,
        login_timeout=timeout,
    ) as connection, connection.start_sftp_client(
        path_encoding="utf-8", path_errors="strict"
    ) as sftp:
        configured_root_attrs = await sftp.lstat(item.sftp_root)
        if configured_root_attrs.type != asyncssh.FILEXFER_TYPE_DIRECTORY:
            raise RegistryError("A raiz SFTP configurada não é um diretório seguro.")
        root_value = await sftp.realpath(item.sftp_root)
        if not isinstance(root_value, str):
            raise RegistryError("O servidor SFTP retornou um caminho inválido.")
        root = PurePosixPath(root_value)

        requested = root
        requested_attrs = configured_root_attrs
        for index, component in enumerate(relative_path.parts):
            requested /= component
            requested_attrs = await sftp.lstat(str(requested))
            if requested_attrs.type == asyncssh.FILEXFER_TYPE_SYMLINK:
                raise RegistryError("O arquivo SFTP não pode atravessar um symlink.")
            if (
                index < len(relative_path.parts) - 1
                and requested_attrs.type != asyncssh.FILEXFER_TYPE_DIRECTORY
            ):
                raise RegistryError("O caminho SFTP intermediário não é um diretório.")

        target_value = await sftp.realpath(str(requested))
        if not isinstance(target_value, str):
            raise RegistryError("O servidor SFTP retornou um caminho inválido.")
        target = PurePosixPath(target_value)
        if target != root and not target.is_relative_to(root):
            raise RegistryError("O arquivo solicitado está fora da raiz SFTP permitida.")
        target_attrs = (
            requested_attrs if target == requested else await sftp.lstat(str(target))
        )
        if target_attrs.type != asyncssh.FILEXFER_TYPE_REGULAR:
            raise RegistryError("O caminho SFTP solicitado não é um arquivo regular.")
        if target_attrs.size is not None and target_attrs.size > max_bytes:
            raise RegistryError("O arquivo SFTP excede o limite de tamanho permitido.")

        digest = hashlib.sha256()
        total = 0
        async with sftp.open(str(target), "rb") as remote_file:
            opened_attrs = await remote_file.stat()
            if opened_attrs.type != asyncssh.FILEXFER_TYPE_REGULAR:
                raise RegistryError("O arquivo SFTP deixou de ser um arquivo regular.")
            if opened_attrs.size is not None and opened_attrs.size > max_bytes:
                raise RegistryError("O arquivo SFTP excede o limite de tamanho permitido.")
            while True:
                chunk = await remote_file.read(min(1024 * 1024, max_bytes - total + 1))
                if not isinstance(chunk, bytes):
                    raise RegistryError("O servidor SFTP retornou conteúdo binário inválido.")
                if not chunk:
                    break
                total += len(chunk)
                if total > max_bytes:
                    raise RegistryError("O arquivo SFTP excede o limite de tamanho permitido.")
                destination.write(chunk)
                digest.update(chunk)
    return SFTPDownloadResult(total, digest.hexdigest())


def download_sftp(
    item: Equipment,
    password: str,
    known_hosts_path: Path,
    relative_path: str,
    destination: BinaryIO,
    *,
    max_bytes: int,
    timeout: float = 30,
) -> SFTPDownloadResult:
    require_ssh(item)
    if item.sftp_root is None:
        raise RegistryError("SFTP não está habilitado para este equipamento.")
    if max_bytes <= 0:
        raise RegistryError("O limite de tamanho SFTP deve ser maior que zero.")
    safe_path = _validate_relative_sftp_path(relative_path)
    if safe_path == PurePosixPath("."):
        raise RegistryError("Informe um arquivo SFTP relativo e seguro.")
    deadline = time.monotonic() + timeout
    try:
        trust_host_on_first_use(item, known_hosts_path, timeout=timeout)
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise TimeoutError
        return asyncio.run(
            asyncio.wait_for(
                _download_sftp(
                    item,
                    password,
                    known_hosts_path,
                    safe_path,
                    destination,
                    max_bytes,
                    timeout,
                ),
                timeout=remaining,
            )
        )
    except TimeoutError as exc:
        raise RegistryError("A operação SFTP excedeu o tempo limite permitido.") from exc
