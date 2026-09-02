from __future__ import annotations

import ipaddress
import os
import sqlite3
import stat
import uuid
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path

from cryptography.hazmat.primitives.ciphers.aead import AESGCM


class RegistryError(Exception):
    """Base registry error."""


class ValidationError(RegistryError):
    """Invalid equipment data."""


class NotFoundError(RegistryError):
    """Equipment does not exist."""


@dataclass(frozen=True, slots=True)
class EquipmentInput:
    name: str
    ip: str
    ssh_port: int
    password: str | None
    brand: str
    username: str = "root"


@dataclass(frozen=True, slots=True)
class Equipment:
    id: str
    name: str
    ip: str
    ssh_port: int
    brand: str
    username: str
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
                    password_ciphertext BLOB NOT NULL,
                    created_at TEXT NOT NULL,
                    updated_at TEXT NOT NULL
                );
                CREATE TABLE IF NOT EXISTS audit_log (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    equipment_id TEXT,
                    action TEXT NOT NULL,
                    created_at TEXT NOT NULL
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
        os.chmod(self.database_path, 0o600)
        os.chmod(self.key_path, 0o600)

    def create(self, item: EquipmentInput) -> Equipment:
        clean = self._validate(item, require_password=True)
        equipment_id = str(uuid.uuid4())
        now = self._now()
        ciphertext = self._encrypt(clean.password or "", equipment_id)
        try:
            with self._connect() as connection:
                connection.execute(
                    """INSERT INTO equipment
                    (id, name, ip, ssh_port, brand, username, password_ciphertext,
                     created_at, updated_at)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                    (
                        equipment_id,
                        clean.name,
                        clean.ip,
                        clean.ssh_port,
                        clean.brand,
                        clean.username,
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
                """SELECT id, name, ip, ssh_port, brand, username, created_at, updated_at
                FROM equipment ORDER BY name COLLATE NOCASE"""
            ).fetchall()
        return [self._row_to_equipment(row) for row in rows]

    def get(self, equipment_id: str) -> Equipment:
        with self._connect() as connection:
            row = connection.execute(
                """SELECT id, name, ip, ssh_port, brand, username, created_at, updated_at
                FROM equipment WHERE id = ?""",
                (equipment_id,),
            ).fetchone()
        if row is None:
            raise NotFoundError("Equipamento não encontrado.")
        return self._row_to_equipment(row)

    def resolve(self, target: str) -> Equipment:
        with self._connect() as connection:
            rows = connection.execute(
                """SELECT id, name, ip, ssh_port, brand, username, created_at, updated_at
                FROM equipment WHERE id = ? OR name = ? COLLATE NOCASE""",
                (target, target),
            ).fetchall()
        if not rows:
            raise NotFoundError("Equipamento não encontrado no inventário.")
        if len(rows) != 1:
            raise RegistryError("Alvo ambíguo no inventário.")
        return self._row_to_equipment(rows[0])

    def get_password(self, equipment_id: str) -> str:
        with self._connect() as connection:
            row = connection.execute(
                "SELECT password_ciphertext FROM equipment WHERE id = ?", (equipment_id,)
            ).fetchone()
        if row is None:
            raise NotFoundError("Equipamento não encontrado.")
        return self._decrypt(bytes(row[0]), equipment_id)

    def update(self, equipment_id: str, item: EquipmentInput) -> Equipment:
        self.get(equipment_id)
        clean = self._validate(item, require_password=False)
        now = self._now()
        try:
            with self._connect() as connection:
                if clean.password is None:
                    cursor = connection.execute(
                        """UPDATE equipment SET name = ?, ip = ?, ssh_port = ?, brand = ?,
                        username = ?, updated_at = ? WHERE id = ?""",
                        (
                            clean.name,
                            clean.ip,
                            clean.ssh_port,
                            clean.brand,
                            clean.username,
                            now,
                            equipment_id,
                        ),
                    )
                else:
                    cursor = connection.execute(
                        """UPDATE equipment SET name = ?, ip = ?, ssh_port = ?, brand = ?,
                        username = ?, password_ciphertext = ?, updated_at = ? WHERE id = ?""",
                        (
                            clean.name,
                            clean.ip,
                            clean.ssh_port,
                            clean.brand,
                            clean.username,
                            self._encrypt(clean.password, equipment_id),
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
        username = item.username.strip()
        ip = item.ip.strip()
        if not name or len(name) > 100:
            raise ValidationError("Nome é obrigatório e deve ter até 100 caracteres.")
        if not brand or len(brand) > 100:
            raise ValidationError("Marca é obrigatória e deve ter até 100 caracteres.")
        if not username or len(username) > 64:
            raise ValidationError("Usuário SSH é obrigatório e deve ter até 64 caracteres.")
        if any(character.isspace() or ord(character) < 33 for character in username):
            raise ValidationError("Usuário SSH não pode conter espaços ou controles.")
        try:
            ip = str(ipaddress.ip_address(ip))
        except ValueError as exc:
            raise ValidationError("Informe um endereço IPv4 ou IPv6 válido.") from exc
        if not isinstance(item.ssh_port, int) or not 1 <= item.ssh_port <= 65535:
            raise ValidationError("A porta SSH deve estar entre 1 e 65535.")
        if require_password and not item.password:
            raise ValidationError("Senha é obrigatória.")
        if item.password is not None and not 1 <= len(item.password) <= 4096:
            raise ValidationError("A senha deve ter entre 1 e 4096 caracteres.")
        return EquipmentInput(name, ip, item.ssh_port, item.password, brand, username)

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
