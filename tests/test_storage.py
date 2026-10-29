from __future__ import annotations

import os
import sqlite3
import stat
from pathlib import Path

import pytest

from equipment_registry.storage import (
    EquipmentInput,
    MonitorTargetInput,
    Registry,
    RegistryError,
    ValidationError,
)


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


def test_create_equipment_accepts_ddns_hostname(tmp_path: Path) -> None:
    registry = make_registry(tmp_path)
    registry.initialize()

    equipment = registry.create(
        EquipmentInput(
            name="Pfsense-VLL",
            ip="VLL.DYNDNS.INFO.",
            ssh_port=2222,
            password="test",
            brand="pfSense",
            username="admin",
        )
    )

    assert equipment.ip == "vll.dyndns.info"


@pytest.mark.parametrize(
    "endpoint",
    [
        "192.0.2.1.",
        "2001:db8::1.",
        "host.example.com...",
        "host..example.com",
        f"{'a' * 64}.example.com",
        "fe80::1%eth0",
        "fe80::1%evil\nkey",
        "host.example.com\ninjected",
        "\nexample.com",
        "example.com\r",
        "\texample.com",
    ],
)
def test_create_equipment_rejects_malformed_dns_or_ip_endpoint(
    tmp_path: Path, endpoint: str
) -> None:
    registry = make_registry(tmp_path)
    registry.initialize()

    with pytest.raises(ValidationError, match="IPv4, IPv6 ou nome DNS"):
        registry.create(EquipmentInput("Pfsense-VLL", endpoint, 22, "test", "pfSense"))


def test_create_equipment_accepts_punycode_fqdn(tmp_path: Path) -> None:
    registry = make_registry(tmp_path)
    registry.initialize()

    equipment = registry.create(
        EquipmentInput("Pfsense-IDN", "router.xn--p1ai", 22, "test", "pfSense")
    )

    assert equipment.ip == "router.xn--p1ai"


def test_create_monitor_target_accepts_dns_without_credentials(tmp_path: Path) -> None:
    registry = make_registry(tmp_path)
    registry.initialize()

    target = registry.create_monitor_target(
        MonitorTargetInput(
            name="Pfsense-DRN-WAN1",
            endpoint="dornas1.dyndns.org",
            protocol="snmp",
            port=161,
            brand="pfSense",
        )
    )

    assert target.name == "Pfsense-DRN-WAN1"
    assert target.endpoint == "dornas1.dyndns.org"
    assert target.protocol == "snmp"
    assert target.port == 161
    assert registry.list_monitor_targets() == [target]


def test_update_can_preserve_or_replace_password(tmp_path: Path) -> None:
    registry = make_registry(tmp_path)
    registry.initialize()
    equipment = registry.create(EquipmentInput("Edge", "2001:db8::1", 2222, "old", "Cisco"))

    registry.update(equipment.id, EquipmentInput("Edge 2", "2001:db8::1", 22, None, "Cisco"))
    assert registry.get_password(equipment.id) == "old"

    registry.update(equipment.id, EquipmentInput("Edge 2", "2001:db8::1", 22, "new", "Cisco"))
    assert registry.get_password(equipment.id) == "new"


def test_equipment_can_use_a_loopback_ssh_relay_without_replacing_its_identity(tmp_path: Path) -> None:
    registry = make_registry(tmp_path)
    registry.initialize()

    equipment = registry.create(
        EquipmentInput(
            "Proxmox-Glagio",
            "10.10.1.211",
            22,
            "test",
            "Proxmox",
            relay_host="127.0.0.1",
            relay_port=22211,
        )
    )

    assert equipment.ip == "10.10.1.211"
    assert equipment.ssh_port == 22
    assert equipment.relay_host == "127.0.0.1"
    assert equipment.relay_port == 22211


def test_equipment_rejects_non_loopback_or_incomplete_ssh_relay(tmp_path: Path) -> None:
    registry = make_registry(tmp_path)
    registry.initialize()

    with pytest.raises(ValidationError, match="loopback"):
        registry.create(
            EquipmentInput(
                "R1", "192.0.2.1", 22, "test", "Cisco", relay_host="10.0.0.10", relay_port=22211
            )
        )
    with pytest.raises(ValidationError, match="juntos"):
        registry.create(EquipmentInput("R2", "192.0.2.2", 22, "test", "Cisco", relay_host="127.0.0.1"))


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
    assert "sftp_root" in columns
    registry.create(EquipmentInput("R1", "192.0.2.1", 22, "test", "Cisco"))
    with pytest.raises(ValidationError, match="Já existe"):
        registry.create(EquipmentInput("r1", "192.0.2.2", 22, "test", "Cisco"))


def test_equipment_can_enable_sftp_with_an_absolute_posix_root(tmp_path: Path) -> None:
    registry = make_registry(tmp_path)
    registry.initialize()

    equipment = registry.create(
        EquipmentInput(
            "Supply-FTP",
            "admin.supplyerp.com.br",
            2222,
            "test",
            "SFTP",
            username="fortacao",
            sftp_root="/",
        )
    )

    assert equipment.sftp_root == "/"
    assert registry.list_equipment()[0].sftp_root == "/"


@pytest.mark.parametrize(
    "sftp_root",
    [
        "relative/path",
        "/srv/../secret",
        "/srv/./files",
        "/srv\\files",
        "/srv/files\nother",
        "/srv//files",
    ],
)
def test_equipment_rejects_unsafe_sftp_root(tmp_path: Path, sftp_root: str) -> None:
    registry = make_registry(tmp_path)
    registry.initialize()

    with pytest.raises(ValidationError, match="raiz SFTP"):
        registry.create(
            EquipmentInput(
                "Supply-FTP",
                "admin.supplyerp.com.br",
                2222,
                "test",
                "SFTP",
                username="fortacao",
                sftp_root=sftp_root,
            )
        )


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
