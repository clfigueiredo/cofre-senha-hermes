from __future__ import annotations

import asyncio
import hmac
import os
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


async def _fetch_host_key(item: Equipment) -> asyncssh.SSHKey:
    key = await asyncssh.get_server_host_key(item.ip, item.ssh_port)
    if key is None:
        raise RegistryError("O equipamento não apresentou uma chave SSH.")
    return key


def _fingerprint(key: asyncssh.SSHKey) -> str:
    return key.get_fingerprint("sha256")


def fingerprint_host(item: Equipment) -> str:
    key = asyncio.run(_fetch_host_key(item))
    return f"{item.name} {_host_label(item)} {key.get_algorithm()} {_fingerprint(key)}"


def trust_host(item: Equipment, known_hosts_path: Path, expected_fingerprint: str) -> None:
    key = asyncio.run(_fetch_host_key(item))
    actual = _fingerprint(key)
    if not hmac.compare_digest(actual, expected_fingerprint.strip()):
        raise RegistryError(
            "Fingerprint divergente. A chave SSH não foi registrada; valide o equipamento e tente novamente."
        )
    known_hosts_path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    line = f"{_host_label(item)} {key.export_public_key('openssh').decode('ascii').strip()}\n"
    existing = known_hosts_path.read_text(encoding="ascii") if known_hosts_path.exists() else ""
    retained = [
        current
        for current in existing.splitlines()
        if current.split(" ", 1)[0] != _host_label(item)
    ]
    temporary = known_hosts_path.with_suffix(".tmp")
    temporary.write_text("\n".join([*retained, line.rstrip()]) + "\n", encoding="ascii")
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
    if not known_hosts_path.exists():
        raise RegistryError(
            "Chave SSH ainda não confiada. Consulte o fingerprint e valide-o antes do acesso."
        )
    return asyncio.run(_run_command(item, password, known_hosts_path, command, timeout))
