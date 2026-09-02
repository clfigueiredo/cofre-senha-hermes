from __future__ import annotations

import os
import sqlite3
import stat
from pathlib import Path

import pytest

from equipment_registry.storage import EquipmentInput, Registry, RegistryError, ValidationError


def make_registry(tmp_path: Path) -> Registry:
    return Registry(tmp_path / "equipment.db", tmp_path / "encryption.key")


def test_key_is_created_outside_database_with_owner_only_permissions(tmp_path: Path) -> None:
    registry = make_registry(tmp_path)
    registry.initialize()

    key_path = tmp_path / "encryption.key"
    assert key_path.exists()
    assert stat.S_IMODE(key_path.stat().st_mode) == 0o600
    assert key_path.read_bytes() not in (tmp_path / "equipment.db").read_bytes()


def test_create_encrypts_password_and_list_never_returns_it(tmp_path: Path) -> None:
    registry = make_registry(tmp_path)
    registry.initialize()
    equipment = registry.create(
        EquipmentInput(
            name="Core POP-A",
            ip="192.0.2.10",
            ssh_port=22,
            password="senha-de-teste",
            brand="Cisco",
            username="admin",
        )
    )

    rows = registry.list_equipment()
    assert rows == [equipment]
    assert not hasattr(equipment, "password")
    assert equipment.username == "admin"

    with sqlite3.connect(tmp_path / "equipment.db") as connection:
        stored = connection.execute(
            "SELECT password_ciphertext FROM equipment WHERE id = ?", (equipment.id,)
        ).fetchone()[0]
    assert b"senha-de-teste" not in stored
    assert registry.get_password(equipment.id) == "senha-de-teste"


def test_update_can_preserve_or_replace_password(tmp_path: Path) -> None:
    registry = make_registry(tmp_path)
    registry.initialize()
    equipment = registry.create(EquipmentInput("Edge", "2001:db8::1", 2222, "old", "Cisco"))

    registry.update(equipment.id, EquipmentInput("Edge 2", "2001:db8::1", 22, None, "Cisco"))
    assert registry.get_password(equipment.id) == "old"

    registry.update(equipment.id, EquipmentInput("Edge 2", "2001:db8::1", 22, "new", "Cisco"))
    assert registry.get_password(equipment.id) == "new"


def test_validation_rejects_bad_ip_port_empty_password_and_duplicate_name(tmp_path: Path) -> None:
    registry = make_registry(tmp_path)
    registry.initialize()

    with pytest.raises(ValidationError):
        registry.create(EquipmentInput("R1", "not-an-ip", 22, "secret", "Cisco"))
    with pytest.raises(ValidationError):
        registry.create(EquipmentInput("R1", "192.0.2.1", 70000, "secret", "Cisco"))
    with pytest.raises(ValidationError):
        registry.create(EquipmentInput("R1", "192.0.2.1", 22, "", "Cisco"))

    registry.create(EquipmentInput("R1", "192.0.2.1", 22, "secret", "Cisco"))
    with pytest.raises(ValidationError):
        registry.create(EquipmentInput("r1", "192.0.2.2", 22, "secret", "Huawei"))


def test_delete_removes_ciphertext_and_audit_contains_no_password(tmp_path: Path) -> None:
    registry = make_registry(tmp_path)
    registry.initialize()
    equipment = registry.create(EquipmentInput("OLT", "192.0.2.30", 22, "never-log-me", "Huawei"))
    registry.delete(equipment.id)

    assert registry.list_equipment() == []
    with sqlite3.connect(tmp_path / "equipment.db") as connection:
        audit = "\n".join(row[0] for row in connection.execute("SELECT action FROM audit_log"))
    assert "never-log-me" not in audit


def test_database_and_key_permissions_are_repaired(tmp_path: Path) -> None:
    registry = make_registry(tmp_path)
    registry.initialize()
    os.chmod(tmp_path / "equipment.db", 0o644)
    os.chmod(tmp_path / "encryption.key", 0o644)

    registry.initialize()

    assert stat.S_IMODE((tmp_path / "equipment.db").stat().st_mode) == 0o600
    assert stat.S_IMODE((tmp_path / "encryption.key").stat().st_mode) == 0o600


def test_existing_database_is_migrated_with_default_ssh_username(tmp_path: Path) -> None:
    database = tmp_path / "equipment.db"
    with sqlite3.connect(database) as connection:
        connection.execute(
            """CREATE TABLE equipment (
            id TEXT PRIMARY KEY, name TEXT NOT NULL, ip TEXT NOT NULL,
            ssh_port INTEGER NOT NULL, brand TEXT NOT NULL,
            password_ciphertext BLOB NOT NULL, created_at TEXT NOT NULL,
            updated_at TEXT NOT NULL)"""
        )
    registry = make_registry(tmp_path)
    registry.initialize()
    with sqlite3.connect(database) as connection:
        columns = {row[1] for row in connection.execute("PRAGMA table_info(equipment)")}
    assert "username" in columns
    registry.create(EquipmentInput("R1", "192.0.2.1", 22, "test", "Cisco"))
    with pytest.raises(ValidationError, match="Já existe"):
        registry.create(EquipmentInput("r1", "192.0.2.2", 22, "test", "Cisco"))


def test_migration_refuses_existing_case_insensitive_duplicates(tmp_path: Path) -> None:
    database = tmp_path / "equipment.db"
    with sqlite3.connect(database) as connection:
        connection.execute(
            """CREATE TABLE equipment (
            id TEXT PRIMARY KEY, name TEXT NOT NULL, ip TEXT NOT NULL,
            ssh_port INTEGER NOT NULL, brand TEXT NOT NULL,
            password_ciphertext BLOB NOT NULL, created_at TEXT NOT NULL,
            updated_at TEXT NOT NULL)"""
        )
        rows = [
            ("1", "R1", "192.0.2.1", 22, "Cisco", b"x", "now", "now"),
            ("2", "r1", "192.0.2.2", 22, "Cisco", b"y", "now", "now"),
        ]
        connection.executemany(
            "INSERT INTO equipment VALUES (?, ?, ?, ?, ?, ?, ?, ?)", rows
        )
    registry = make_registry(tmp_path)
    with pytest.raises(RegistryError, match="nomes duplicados"):
        registry.initialize()


def test_existing_insecure_data_directory_is_rejected_without_chmod(tmp_path: Path) -> None:
    insecure = tmp_path / "shared"
    insecure.mkdir(mode=0o755)
    registry = make_registry(insecure)
    with pytest.raises(RegistryError, match="Diretório de dados inseguro"):
        registry.initialize()
    assert stat.S_IMODE(insecure.stat().st_mode) == 0o755


def test_data_directory_symlink_is_rejected(tmp_path: Path) -> None:
    private = tmp_path / "private"
    private.mkdir(mode=0o700)
    linked = tmp_path / "linked"
    linked.symlink_to(private, target_is_directory=True)
    registry = make_registry(linked)
    with pytest.raises(RegistryError, match="link simbólico"):
        registry.initialize()


def test_sqlite_backup_includes_committed_wal_data(tmp_path: Path) -> None:
    registry = make_registry(tmp_path)
    registry.initialize()
    registry.create(EquipmentInput("R1", "192.0.2.1", 22, "test", "Cisco", "admin"))
    backup = tmp_path / "backup.db"
    registry.backup_database(backup)
    with sqlite3.connect(backup) as connection:
        assert connection.execute("SELECT COUNT(*) FROM equipment").fetchone()[0] == 1
    assert stat.S_IMODE(backup.stat().st_mode) == 0o600
