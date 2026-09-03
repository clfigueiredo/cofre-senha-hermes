from __future__ import annotations

import asyncio
import fcntl
import os
from collections.abc import Iterator
from contextlib import contextmanager
from dataclasses import dataclass
from pathlib import Path

import asyncssh

from .storage import Equipment, RegistryError


@dataclass(frozen=True, slots=True)
class CommandResult:
    exit_status: int
    stdout: str
    stderr: str


def _host_label(item: Equipment) -> str:
    return item.ip if item.ssh_port == 22 else f"[{item.ip}]:{item.ssh_port}"


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
    key = await asyncssh.get_server_host_key(item.ip, item.ssh_port)
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
    async with asyncssh.connect(
        item.ip,
        port=item.ssh_port,
        username=item.username,
        password=password,
        known_hosts=str(known_hosts_path),
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
    if not command.strip():
        raise RegistryError("O comando remoto não pode ser vazio.")
    trust_host_on_first_use(item, known_hosts_path, timeout=timeout)
    return asyncio.run(_run_command(item, password, known_hosts_path, command, timeout))
