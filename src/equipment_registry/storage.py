from __future__ import annotations

import ipaddress
import os
import re
import sqlite3
import stat
import uuid
from dataclasses import dataclass, replace
from datetime import UTC, datetime
from pathlib import Path

from cryptography.hazmat.primitives.ciphers.aead import AESGCM


class RegistryError(Exception):
    """Base registry error."""


class ValidationError(RegistryError):
    """Invalid equipment data."""


class NotFoundError(RegistryError):
    """Equipment does not exist."""


_HOSTNAME_LABEL = re.compile(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?")
_ENDPOINT_ERROR = "Informe um IPv4, IPv6 ou nome DNS válido."


def _normalize_endpoint(value: str) -> str:
    if any(ord(character) < 32 or ord(character) == 127 for character in value):
        raise ValidationError(_ENDPOINT_ERROR)
    endpoint = value.strip(" ").lower()
    if "%" in endpoint or any(
        character.isspace() or not 33 <= ord(character) <= 126 for character in endpoint
    ):
        raise ValidationError(_ENDPOINT_ERROR)
    try:
        return str(ipaddress.ip_address(endpoint))
    except ValueError:
        pass

    if endpoint.endswith(".."):
        raise ValidationError(_ENDPOINT_ERROR)
    if endpoint.endswith("."):
        endpoint = endpoint[:-1]
        try:
            ipaddress.ip_address(endpoint)
        except ValueError:
            pass
        else:
            raise ValidationError(_ENDPOINT_ERROR)

    labels = endpoint.split(".")
    if (
        not 1 <= len(endpoint) <= 253
        or len(labels) < 2
        or all(label.isdigit() for label in labels)
        or any(not _HOSTNAME_LABEL.fullmatch(label) for label in labels)
    ):
        raise ValidationError(_ENDPOINT_ERROR)
    return endpoint


@dataclass(frozen=True, slots=True)
class EquipmentInput:
    name: str
    ip: str | None
    ssh_port: int | None
    password: str | None
    brand: str
    username: str | None = "root"
    relay_host: str | None = None
    relay_port: int | None = None
    sftp_root: str | None = None
    access_type: str = "ssh"
    client: str | None = None
    parent_host: str | None = None
    console_type: str | None = None
    network_state: str | None = None


@dataclass(frozen=True, slots=True)
class Equipment:
    id: str
    name: str
    ip: str | None
    ssh_port: int | None
    brand: str
    username: str | None
    created_at: str
    updated_at: str
    relay_host: str | None = None
    relay_port: int | None = None
    sftp_root: str | None = None
    access_type: str = "ssh"
    client: str | None = None
    parent_host: str | None = None
    console_type: str | None = None
    network_state: str | None = None


@dataclass(frozen=True, slots=True)
class MonitorTargetInput:
    name: str
    endpoint: str
    protocol: str
    port: int
    brand: str


@dataclass(frozen=True, slots=True)
class MonitorTarget:
    id: str
    name: str
    endpoint: str
    protocol: str
    port: int
    brand: str
    created_at: str
    updated_at: str


class Registry:
    def __init__(self, database_path: Path, key_path: Path) -> None:
        self.database_path = Path(database_path)
        self.key_path = Path(key_path)

    def initialize(self) -> None:
        self._ensure_private_directory(self.database_path.parent)
        self._ensure_private_directory(self.key_path.parent)
        self._load_or_create_key()
        with self._connect() as connection:
            connection.executescript(
                """
                CREATE TABLE IF NOT EXISTS equipment (
                    id TEXT PRIMARY KEY,
                    name TEXT NOT NULL COLLATE NOCASE UNIQUE,
                    ip TEXT NOT NULL,
                    ssh_port INTEGER NOT NULL CHECK (ssh_port BETWEEN 1 AND 65535),
                    brand TEXT NOT NULL,
                    username TEXT NOT NULL DEFAULT 'root',
                    relay_host TEXT,
                    relay_port INTEGER,
                    sftp_root TEXT,
                    password_ciphertext BLOB NOT NULL,
                    created_at TEXT NOT NULL,
                    updated_at TEXT NOT NULL
                );
                CREATE TABLE IF NOT EXISTS offline_equipment (
                    id TEXT PRIMARY KEY,
                    name TEXT NOT NULL COLLATE NOCASE UNIQUE,
                    brand TEXT NOT NULL,
                    client TEXT NOT NULL,
                    parent_host TEXT NOT NULL,
                    console_type TEXT NOT NULL,
                    network_state TEXT NOT NULL CHECK (network_state = 'disconnected'),
                    created_at TEXT NOT NULL,
                    updated_at TEXT NOT NULL
                );
                CREATE TABLE IF NOT EXISTS audit_log (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    equipment_id TEXT,
                    action TEXT NOT NULL,
                    created_at TEXT NOT NULL
                );
                CREATE TABLE IF NOT EXISTS monitor_target (
                    id TEXT PRIMARY KEY,
                    name TEXT NOT NULL COLLATE NOCASE UNIQUE,
                    endpoint TEXT NOT NULL,
                    protocol TEXT NOT NULL CHECK (protocol IN ('icmp', 'tcp', 'snmp')),
                    port INTEGER NOT NULL CHECK (port BETWEEN 1 AND 65535),
                    brand TEXT NOT NULL,
                    created_at TEXT NOT NULL,
                    updated_at TEXT NOT NULL
                );
                """
            )
            columns = {
                row["name"] for row in connection.execute("PRAGMA table_info(equipment)")
            }
            if "username" not in columns:
                connection.execute(
                    "ALTER TABLE equipment ADD COLUMN username TEXT NOT NULL DEFAULT 'root'"
                )
            if "relay_host" not in columns:
                connection.execute("ALTER TABLE equipment ADD COLUMN relay_host TEXT")
            if "relay_port" not in columns:
                connection.execute("ALTER TABLE equipment ADD COLUMN relay_port INTEGER")
            if "sftp_root" not in columns:
                connection.execute("ALTER TABLE equipment ADD COLUMN sftp_root TEXT")
            duplicate = connection.execute(
                """SELECT name FROM equipment
                GROUP BY name COLLATE NOCASE HAVING COUNT(*) > 1 LIMIT 1"""
            ).fetchone()
            if duplicate is not None:
                raise RegistryError(
                    "A migração encontrou nomes duplicados sem diferenciar maiúsculas; "
                    "corrija o banco antes de continuar."
                )
            connection.execute(
                """CREATE UNIQUE INDEX IF NOT EXISTS idx_equipment_name_nocase
                ON equipment(name COLLATE NOCASE)"""
            )
            # Enforce one equipment namespace atomically, including writes by older clients.
            for statement in (
                """CREATE TRIGGER IF NOT EXISTS unique_equipment_insert
                BEFORE INSERT ON equipment
                WHEN EXISTS (SELECT 1 FROM offline_equipment
                             WHERE name = NEW.name COLLATE NOCASE OR id = NEW.id)
                BEGIN SELECT RAISE(ABORT, 'Equipment identity already exists'); END""",
                """CREATE TRIGGER IF NOT EXISTS unique_equipment_update
                BEFORE UPDATE ON equipment
                WHEN EXISTS (SELECT 1 FROM offline_equipment
                             WHERE name = NEW.name COLLATE NOCASE OR id = NEW.id)
                BEGIN SELECT RAISE(ABORT, 'Equipment identity already exists'); END""",
                """CREATE TRIGGER IF NOT EXISTS unique_offline_equipment_insert
                BEFORE INSERT ON offline_equipment
                WHEN EXISTS (SELECT 1 FROM equipment
                             WHERE name = NEW.name COLLATE NOCASE OR id = NEW.id)
                BEGIN SELECT RAISE(ABORT, 'Equipment identity already exists'); END""",
                """CREATE TRIGGER IF NOT EXISTS unique_offline_equipment_update
                BEFORE UPDATE ON offline_equipment
                WHEN EXISTS (SELECT 1 FROM equipment
                             WHERE name = NEW.name COLLATE NOCASE OR id = NEW.id)
                BEGIN SELECT RAISE(ABORT, 'Equipment identity already exists'); END""",
            ):
                connection.execute(statement)
        os.chmod(self.database_path, 0o600)
        os.chmod(self.key_path, 0o600)

    def create(self, item: EquipmentInput) -> Equipment:
        clean = self._validate(item, require_password=True)
        equipment_id = str(uuid.uuid4())
        now = self._now()
        if clean.access_type == "offline":
            try:
                with self._connect() as connection:
                    connection.execute(
                        """INSERT INTO offline_equipment
                        (id, name, brand, client, parent_host, console_type, network_state,
                         created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                        (equipment_id, clean.name, clean.brand, clean.client, clean.parent_host,
                         clean.console_type, clean.network_state, now, now),
                    )
                    self._audit(connection, equipment_id, "equipment.created")
            except sqlite3.IntegrityError as exc:
                raise ValidationError("Já existe um equipamento com esse nome.") from exc
            return self.get(equipment_id)
        ciphertext = self._encrypt(clean.password or "", equipment_id)
        try:
            with self._connect() as connection:
                connection.execute(
                    """INSERT INTO equipment
                    (id, name, ip, ssh_port, brand, username, relay_host, relay_port, sftp_root,
                     password_ciphertext, created_at, updated_at)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                    (
                        equipment_id,
                        clean.name,
                        clean.ip,
                        clean.ssh_port,
                        clean.brand,
                        clean.username,
                        clean.relay_host,
                        clean.relay_port,
                        clean.sftp_root,
                        ciphertext,
                        now,
                        now,
                    ),
                )
                self._audit(connection, equipment_id, "equipment.created")
        except sqlite3.IntegrityError as exc:
            raise ValidationError("Já existe um equipamento com esse nome.") from exc
        return self.get(equipment_id)

    def list_equipment(self) -> list[Equipment]:
        with self._connect() as connection:
            rows = connection.execute(
                """SELECT id, name, ip, ssh_port, brand, username, relay_host, relay_port, sftp_root,
                created_at, updated_at
                FROM equipment ORDER BY name COLLATE NOCASE"""
            ).fetchall()
            offline_rows = connection.execute("SELECT * FROM offline_equipment").fetchall()
        return sorted(
            [self._row_to_equipment(row) for row in rows]
            + [self._row_to_offline(row) for row in offline_rows],
            key=lambda item: item.name.casefold(),
        )

    def create_monitor_target(self, item: MonitorTargetInput) -> MonitorTarget:
        clean = self._validate_monitor_target(item)
        target_id = str(uuid.uuid4())
        now = self._now()
        try:
            with self._connect() as connection:
                connection.execute(
                    """INSERT INTO monitor_target
                    (id, name, endpoint, protocol, port, brand, created_at, updated_at)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?)""",
                    (
                        target_id,
                        clean.name,
                        clean.endpoint,
                        clean.protocol,
                        clean.port,
                        clean.brand,
                        now,
                        now,
                    ),
                )
                self._audit(connection, target_id, "monitor_target.created")
        except sqlite3.IntegrityError as exc:
            raise ValidationError("Já existe um alvo de monitoramento com esse nome.") from exc
        return self.get_monitor_target(target_id)

    def list_monitor_targets(self) -> list[MonitorTarget]:
        with self._connect() as connection:
            rows = connection.execute(
                """SELECT id, name, endpoint, protocol, port, brand, created_at, updated_at
                FROM monitor_target ORDER BY name COLLATE NOCASE"""
            ).fetchall()
        return [self._row_to_monitor_target(row) for row in rows]

    def get_monitor_target(self, target_id: str) -> MonitorTarget:
        with self._connect() as connection:
            row = connection.execute(
                """SELECT id, name, endpoint, protocol, port, brand, created_at, updated_at
                FROM monitor_target WHERE id = ?""",
                (target_id,),
            ).fetchone()
        if row is None:
            raise NotFoundError("Alvo de monitoramento não encontrado.")
        return self._row_to_monitor_target(row)

    def get(self, equipment_id: str) -> Equipment:
        with self._connect() as connection:
            offline_row = connection.execute(
                "SELECT * FROM offline_equipment WHERE id = ?", (equipment_id,)
            ).fetchone()
            if offline_row is not None:
                return self._row_to_offline(offline_row)
            row = connection.execute(
                """SELECT id, name, ip, ssh_port, brand, username, relay_host, relay_port, sftp_root,
                created_at, updated_at
                FROM equipment WHERE id = ?""",
                (equipment_id,),
            ).fetchone()
        if row is None:
            raise NotFoundError("Equipamento não encontrado.")
        return self._row_to_equipment(row)

    def resolve(self, target: str) -> Equipment:
        with self._connect() as connection:
            rows = connection.execute(
                """SELECT id, name, ip, ssh_port, brand, username, relay_host, relay_port, sftp_root,
                created_at, updated_at
                FROM equipment WHERE id = ? OR name = ? COLLATE NOCASE""",
                (target, target),
            ).fetchall()
            offline_rows = connection.execute(
                "SELECT * FROM offline_equipment WHERE id = ? OR name = ? COLLATE NOCASE",
                (target, target),
            ).fetchall()
        if len(rows) + len(offline_rows) > 1:
            raise RegistryError("Alvo ambíguo no inventário.")
        if offline_rows:
            return self._row_to_offline(offline_rows[0])
        if not rows:
            raise NotFoundError("Equipamento não encontrado no inventário.")
        if len(rows) != 1:
            raise RegistryError("Alvo ambíguo no inventário.")
        return self._row_to_equipment(rows[0])

    def get_password(self, equipment_id: str) -> str:
        if self.get(equipment_id).access_type != "ssh":
            raise RegistryError("Equipamento offline não possui credencial SSH.")
        with self._connect() as connection:
            row = connection.execute(
                "SELECT password_ciphertext FROM equipment WHERE id = ?", (equipment_id,)
            ).fetchone()
        if row is None:
            raise NotFoundError("Equipamento não encontrado.")
        return self._decrypt(bytes(row[0]), equipment_id)

    def update(self, equipment_id: str, item: EquipmentInput) -> Equipment:
        existing = self.get(equipment_id)
        if existing.access_type != item.access_type:
            raise ValidationError("Não é permitido alterar o tipo de acesso de um cadastro.")
        clean = self._validate(item, require_password=False)
        now = self._now()
        if existing.access_type == "offline":
            try:
                with self._connect() as connection:
                    connection.execute(
                        """UPDATE offline_equipment SET name = ?, brand = ?, client = ?,
                        parent_host = ?, console_type = ?, network_state = ?, updated_at = ?
                        WHERE id = ?""",
                        (clean.name, clean.brand, clean.client, clean.parent_host,
                         clean.console_type, clean.network_state, now, equipment_id),
                    )
                    self._audit(connection, equipment_id, "equipment.updated")
            except sqlite3.IntegrityError as exc:
                raise ValidationError("Já existe um equipamento com esse nome.") from exc
            return self.get(equipment_id)
        try:
            with self._connect() as connection:
                if clean.password is None:
                    cursor = connection.execute(
                        """UPDATE equipment SET name = ?, ip = ?, ssh_port = ?, brand = ?,
                        username = ?, relay_host = ?, relay_port = ?, sftp_root = ?,
                        updated_at = ? WHERE id = ?""",
                        (
                            clean.name,
                            clean.ip,
                            clean.ssh_port,
                            clean.brand,
                            clean.username,
                            clean.relay_host,
                            clean.relay_port,
                            clean.sftp_root,
                            now,
                            equipment_id,
                        ),
                    )
                else:
                    cursor = connection.execute(
                        """UPDATE equipment SET name = ?, ip = ?, ssh_port = ?, brand = ?,
                        username = ?, relay_host = ?, relay_port = ?, password_ciphertext = ?,
                        sftp_root = ?, updated_at = ? WHERE id = ?""",
                        (
                            clean.name,
                            clean.ip,
                            clean.ssh_port,
                            clean.brand,
                            clean.username,
                            clean.relay_host,
                            clean.relay_port,
                            self._encrypt(clean.password, equipment_id),
                            clean.sftp_root,
                            now,
                            equipment_id,
                        ),
                    )
                if cursor.rowcount != 1:
                    raise NotFoundError("Equipamento não encontrado.")
                self._audit(connection, equipment_id, "equipment.updated")
        except sqlite3.IntegrityError as exc:
            raise ValidationError("Já existe um equipamento com esse nome.") from exc
        return self.get(equipment_id)

    def delete(self, equipment_id: str) -> None:
        with self._connect() as connection:
            cursor = connection.execute("DELETE FROM equipment WHERE id = ?", (equipment_id,))
            if cursor.rowcount == 0:
                cursor = connection.execute(
                    "DELETE FROM offline_equipment WHERE id = ?", (equipment_id,)
                )
            if cursor.rowcount != 1:
                raise NotFoundError("Equipamento não encontrado.")
            self._audit(connection, equipment_id, "equipment.deleted")

    def health(self) -> bool:
        with self._connect() as connection:
            return connection.execute("SELECT 1").fetchone()[0] == 1

    def backup_database(self, destination: Path) -> None:
        destination = Path(destination)
        if destination.exists():
            raise RegistryError("O arquivo de backup já existe.")
        with self._connect() as source, sqlite3.connect(destination) as target:
            source.backup(target)
        os.chmod(destination, 0o600)

    def _connect(self) -> sqlite3.Connection:
        connection = sqlite3.connect(self.database_path, timeout=10)
        connection.row_factory = sqlite3.Row
        connection.execute("PRAGMA foreign_keys = ON")
        connection.execute("PRAGMA secure_delete = ON")
        connection.execute("PRAGMA journal_mode = WAL")
        return connection

    def _load_or_create_key(self) -> bytes:
        try:
            descriptor = os.open(self.key_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        except FileExistsError:
            pass
        else:
            with os.fdopen(descriptor, "wb") as stream:
                stream.write(AESGCM.generate_key(bit_length=256))
        os.chmod(self.key_path, 0o600)
        key = self.key_path.read_bytes()
        if len(key) != 32:
            raise RegistryError("A chave de criptografia deve ter exatamente 32 bytes.")
        return key

    @staticmethod
    def _ensure_private_directory(path: Path) -> None:
        if path.is_symlink():
            raise RegistryError("O diretório de dados não pode ser um link simbólico.")
        if not path.exists():
            path.mkdir(parents=True, mode=0o700)
        if not path.is_dir():
            raise RegistryError("O caminho de dados precisa ser um diretório.")
        mode = stat.S_IMODE(path.stat().st_mode)
        if mode & 0o077:
            raise RegistryError(
                f"Diretório de dados inseguro ({mode:o}); ajuste-o manualmente para 0700."
            )

    def _encrypt(self, plaintext: str, equipment_id: str) -> bytes:
        nonce = os.urandom(12)
        encrypted = AESGCM(self._load_or_create_key()).encrypt(
            nonce, plaintext.encode("utf-8"), equipment_id.encode("ascii")
        )
        return nonce + encrypted

    def _decrypt(self, payload: bytes, equipment_id: str) -> str:
        if len(payload) < 29:
            raise RegistryError("Credencial criptografada inválida.")
        plaintext = AESGCM(self._load_or_create_key()).decrypt(
            payload[:12], payload[12:], equipment_id.encode("ascii")
        )
        return plaintext.decode("utf-8")

    @staticmethod
    def _validate(item: EquipmentInput, *, require_password: bool) -> EquipmentInput:
        name = item.name.strip()
        brand = item.brand.strip()
        if item.access_type not in {"ssh", "offline"}:
            raise ValidationError("Tipo de acesso inválido.")
        if item.access_type == "offline":
            if any(value not in (None, "") for value in (
                item.ip, item.ssh_port, item.username, item.password,
                item.relay_host, item.relay_port, item.sftp_root,
            )):
                raise ValidationError("Equipamento offline não aceita endereço, porta ou credenciais.")
            if item.network_state != "disconnected":
                raise ValidationError("Equipamento offline exige rede desconectada.")
            fields = {"name": name, "brand": brand, "client": item.client,
                      "parent_host": item.parent_host, "console_type": item.console_type}
            for field, value in fields.items():
                if (not isinstance(value, str) or not value.strip() or len(value) > 100
                        or any(ord(char) < 32 or ord(char) == 127 for char in value)):
                    raise ValidationError(
                        "Nome, marca, cliente, host pai e tipo de console são obrigatórios "
                        "e devem ter até 100 caracteres sem controles."
                    )
                fields[field] = value.strip()
            return replace(item, **fields, ip=None, ssh_port=None, username=None,
                           password=None, relay_host=None, relay_port=None, sftp_root=None)
        username = (item.username or "").strip()
        endpoint = item.ip or ""
        if not name or len(name) > 100:
            raise ValidationError("Nome é obrigatório e deve ter até 100 caracteres.")
        if not brand or len(brand) > 100:
            raise ValidationError("Marca é obrigatória e deve ter até 100 caracteres.")
        if not username or len(username) > 64:
            raise ValidationError("Usuário SSH é obrigatório e deve ter até 64 caracteres.")
        if any(character.isspace() or ord(character) < 33 for character in username):
            raise ValidationError("Usuário SSH não pode conter espaços ou controles.")
        endpoint = _normalize_endpoint(endpoint)
        if not isinstance(item.ssh_port, int) or not 1 <= item.ssh_port <= 65535:
            raise ValidationError("A porta SSH deve estar entre 1 e 65535.")
        if require_password and not item.password:
            raise ValidationError("Senha é obrigatória.")
        if item.password is not None and not 1 <= len(item.password) <= 4096:
            raise ValidationError("A senha deve ter entre 1 e 4096 caracteres.")
        relay_host = item.relay_host.strip() if item.relay_host else None
        relay_port = item.relay_port
        if (relay_host is None) != (relay_port is None):
            raise ValidationError("Host e porta do relay SSH devem ser informados juntos.")
        if relay_host is not None:
            if relay_host not in {"127.0.0.1", "::1"}:
                raise ValidationError("O relay SSH deve usar um endereço loopback local.")
            if not isinstance(relay_port, int) or not 1 <= relay_port <= 65535:
                raise ValidationError("A porta do relay SSH deve estar entre 1 e 65535.")
        sftp_root = Registry._validate_sftp_root(item.sftp_root)
        return EquipmentInput(
            name,
            endpoint,
            item.ssh_port,
            item.password,
            brand,
            username,
            relay_host,
            relay_port,
            sftp_root,
        )

    @staticmethod
    def _validate_sftp_root(value: str | None) -> str | None:
        if value is None or value == "":
            return None
        if (
            len(value) > 1024
            or not value.startswith("/")
            or "\\" in value
            or any(ord(character) < 32 or ord(character) == 127 for character in value)
        ):
            raise ValidationError("Informe uma raiz SFTP POSIX absoluta e segura.")
        if value == "/":
            return value
        components = value[1:].split("/")
        if any(component in {"", ".", ".."} for component in components):
            raise ValidationError("Informe uma raiz SFTP POSIX absoluta e segura.")
        return value

    @staticmethod
    def _validate_monitor_target(item: MonitorTargetInput) -> MonitorTargetInput:
        name = item.name.strip()
        endpoint = item.endpoint
        protocol = item.protocol.strip().lower()
        brand = item.brand.strip()
        if not name or len(name) > 100:
            raise ValidationError("Nome é obrigatório e deve ter até 100 caracteres.")
        if not brand or len(brand) > 100:
            raise ValidationError("Marca é obrigatória e deve ter até 100 caracteres.")
        if protocol not in {"icmp", "tcp", "snmp"}:
            raise ValidationError("Protocolo permitido: icmp, tcp ou snmp.")
        if not isinstance(item.port, int) or not 1 <= item.port <= 65535:
            raise ValidationError("A porta deve estar entre 1 e 65535.")
        endpoint = _normalize_endpoint(endpoint)
        return MonitorTargetInput(name, endpoint, protocol, item.port, brand)

    @staticmethod
    def _row_to_equipment(row: sqlite3.Row) -> Equipment:
        return Equipment(
            id=row["id"],
            name=row["name"],
            ip=row["ip"],
            ssh_port=row["ssh_port"],
            brand=row["brand"],
            username=row["username"],
            created_at=row["created_at"],
            updated_at=row["updated_at"],
            relay_host=row["relay_host"],
            relay_port=row["relay_port"],
            sftp_root=row["sftp_root"],
        )

    @staticmethod
    def _row_to_offline(row: sqlite3.Row) -> Equipment:
        return Equipment(
            id=row["id"], name=row["name"], ip=None, ssh_port=None, username=None,
            brand=row["brand"], created_at=row["created_at"], updated_at=row["updated_at"],
            access_type="offline", client=row["client"], parent_host=row["parent_host"],
            console_type=row["console_type"], network_state=row["network_state"],
        )

    @staticmethod
    def _row_to_monitor_target(row: sqlite3.Row) -> MonitorTarget:
        return MonitorTarget(
            id=row["id"],
            name=row["name"],
            endpoint=row["endpoint"],
            protocol=row["protocol"],
            port=row["port"],
            brand=row["brand"],
            created_at=row["created_at"],
            updated_at=row["updated_at"],
        )

    @staticmethod
    def _audit(connection: sqlite3.Connection, equipment_id: str, action: str) -> None:
        connection.execute(
            "INSERT INTO audit_log (equipment_id, action, created_at) VALUES (?, ?, ?)",
            (equipment_id, action, Registry._now()),
        )

    @staticmethod
    def _now() -> str:
        return datetime.now(UTC).isoformat(timespec="seconds")
