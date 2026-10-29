import sqlite3
from dataclasses import asdict, replace

import pytest

from equipment_registry.storage import EquipmentInput, Registry, RegistryError, ValidationError


@pytest.fixture
def registry(tmp_path):
    result = Registry(tmp_path / "equipment.db", tmp_path / "encryption.key")
    result.initialize()
    return result


def offline(**changes):
    values = {
        "name": "n8n-restore-offline",
        "ip": None,
        "ssh_port": None,
        "password": None,
        "brand": "Hyper-V",
        "username": None,
        "access_type": "offline",
        "client": "GOITS",
        "parent_host": "DESKTOP-5ERNE8J",
        "console_type": "hyper-v",
        "network_state": "disconnected",
    }
    values.update(changes)
    return EquipmentInput(**values)


@pytest.mark.parametrize(
    "changes",
    [
        {"ip": "192.0.2.1"},
        {"ssh_port": 22},
        {"username": "root"},
        {"password": "test-only"},
        {"relay_host": "127.0.0.1"},
        {"relay_port": 2222},
        {"sftp_root": "/"},
        {"network_state": "connected"},
        {"network_state": None},
        {"client": ""},
        {"parent_host": ""},
        {"console_type": ""},
        {"name": ""},
        {"brand": ""},
        {"client": "x" * 101},
        {"parent_host": "bad\u0000host"},
        {"console_type": "x" * 101},
        {"access_type": "unknown"},
    ],
)
def test_offline_rejects_invalid_metadata(registry, changes):
    with pytest.raises(ValidationError):
        registry.create(offline(**changes))
    assert registry.list_equipment() == []


def test_access_type_is_immutable(registry):
    item = registry.create(offline())
    ssh = EquipmentInput("SSH", "192.0.2.1", 22, "test-only", "Linux")
    with pytest.raises(ValidationError, match="tipo"):
        registry.update(item.id, ssh)
    connected = registry.create(ssh)
    with pytest.raises(ValidationError, match="tipo"):
        registry.update(connected.id, offline())
    assert registry.get(item.id) == item
    assert registry.get(connected.id) == connected


def test_names_are_unique_across_ssh_and_offline(registry):
    item = registry.create(offline())
    ssh = EquipmentInput(item.name.upper(), "192.0.2.1", 22, "test-only", "Linux")
    with pytest.raises(ValidationError):
        registry.create(ssh)
    connected = registry.create(replace(ssh, name="Connected"))
    with pytest.raises(ValidationError):
        registry.create(offline(name="CONNECTED"))
    with pytest.raises(ValidationError):
        registry.update(item.id, offline(name="connected"))
    with pytest.raises(ValidationError):
        registry.update(connected.id, replace(ssh, password=None))
    assert registry.get(item.id) == item
    assert registry.get(connected.id) == connected


@pytest.mark.parametrize("operation", ["run", "sftp-list", "sftp-download"])
def test_cli_offline_blocks_before_password_or_connection(
    registry, monkeypatch, operation, tmp_path
):
    from equipment_registry import cli

    item = registry.create(offline())
    monkeypatch.setenv("EQUIPMENT_REGISTRY_DATA_DIR", str(tmp_path))

    def forbidden(*args, **kwargs):
        pytest.fail("Offline must be rejected before secrets or network access")

    monkeypatch.setattr(Registry, "get_password", forbidden)
    for name in ["run_command", "list_sftp", "download_sftp"]:
        monkeypatch.setattr(cli, name, forbidden)
    extra = {
        "run": ["--command", "hostname"],
        "sftp-list": [],
        "sftp-download": ["file", "--output", str(tmp_path / "output")],
    }[operation]
    monkeypatch.setattr("sys.argv", ["equipment-registry", operation, item.name, *extra])
    with pytest.raises(RegistryError, match="offline"):
        cli.main()
    assert not (tmp_path / "output").exists()


@pytest.mark.parametrize(
    "operation",
    ["run_command", "trust_host_on_first_use", "connection_endpoint", "list_sftp", "download_sftp"],
)
def test_connector_offline_blocks_even_forged_network_metadata(
    registry, monkeypatch, tmp_path, operation
):
    import io

    from equipment_registry import connector

    item = replace(
        registry.create(offline()),
        ip="192.0.2.1",
        ssh_port=22,
        username="root",
        sftp_root="/",
        relay_host="127.0.0.1",
        relay_port=22,
    )

    def forbidden(*args, **kwargs):
        pytest.fail("Offline connector touched a host key or network")

    monkeypatch.setattr(connector, "_fetch_host_key", forbidden)
    monkeypatch.setattr(connector.asyncssh, "connect", forbidden)
    monkeypatch.setattr(connector, "_known_hosts_for_target", forbidden)
    args = {
        "run_command": (item, "", tmp_path / "known_hosts", "hostname"),
        "trust_host_on_first_use": (item, tmp_path / "known_hosts"),
        "connection_endpoint": (item,),
        "list_sftp": (item, "", tmp_path / "known_hosts"),
        "download_sftp": (item, "", tmp_path / "known_hosts", "file", io.BytesIO()),
    }[operation]
    kwargs = {"max_bytes": 100} if operation == "download_sftp" else {}
    with pytest.raises(RegistryError, match="offline"):
        getattr(connector, operation)(*args, **kwargs)
    assert not (tmp_path / "known_hosts").exists()


def test_cli_list_offline_metadata(registry, monkeypatch, capsys, tmp_path):
    import json

    from equipment_registry import cli

    item = registry.create(offline())
    monkeypatch.setenv("EQUIPMENT_REGISTRY_DATA_DIR", str(tmp_path))
    monkeypatch.setattr("sys.argv", ["equipment-registry", "list"])
    assert cli.main() == 0
    assert json.loads(capsys.readouterr().out) == [asdict(item)]


def test_additive_migration_preserves_legacy_ssh_and_monitoring(tmp_path):
    path = tmp_path / 'equipment.db'
    with sqlite3.connect(path) as conn:
        conn.executescript('''
            CREATE TABLE equipment (
                id TEXT PRIMARY KEY, name TEXT NOT NULL UNIQUE, ip TEXT NOT NULL,
                ssh_port INTEGER NOT NULL CHECK (ssh_port BETWEEN 1 AND 65535),
                brand TEXT NOT NULL, password_ciphertext BLOB NOT NULL,
                created_at TEXT NOT NULL, updated_at TEXT NOT NULL);
            INSERT INTO equipment VALUES ('legacy', 'Legacy SSH', '192.0.2.1', 22,
                'Linux', X'001122334455', 'created', 'updated');
        ''')
        before = conn.execute('SELECT * FROM equipment').fetchall()
    registry = Registry(path, tmp_path / 'encryption.key')
    registry.initialize()
    from equipment_registry.storage import MonitorTargetInput
    monitor = registry.create_monitor_target(
        MonitorTargetInput('Monitor', '192.0.2.2', 'tcp', 443, 'Linux'))
    registry.create(offline())
    registry.initialize()
    registry.initialize()
    assert registry.resolve('Legacy SSH').access_type == 'ssh'
    assert registry.resolve('Legacy SSH').username == 'root'
    assert registry.list_monitor_targets() == [monitor]
    with sqlite3.connect(path) as conn:
        after = conn.execute('''SELECT id, name, ip, ssh_port, brand,
                              password_ciphertext, created_at, updated_at FROM equipment''').fetchall()
        assert after == before
        columns = {row[1] for row in conn.execute('PRAGMA table_info(offline_equipment)')}
        assert not columns.intersection({'ip', 'ssh_port', 'username', 'password_ciphertext'})
        assert conn.execute('PRAGMA integrity_check').fetchone()[0] == 'ok'
        with pytest.raises(sqlite3.IntegrityError):
            conn.execute("UPDATE equipment SET name = 'N8N-RESTORE-OFFLINE' WHERE id = 'legacy'")


def test_offline_lifecycle_without_credentials(registry, monkeypatch):
    def forbidden(*args):
        pytest.fail("Offline must not use cryptography")

    monkeypatch.setattr(registry, "_encrypt", forbidden)
    monkeypatch.setattr(registry, "_decrypt", forbidden)
    item = registry.create(offline())
    assert item.access_type == "offline"
    assert item.ip is item.ssh_port is item.username is None
    assert item.client == "GOITS"
    assert item.parent_host == "DESKTOP-5ERNE8J"
    assert item.console_type == "hyper-v"
    assert item.network_state == "disconnected"
    assert registry.resolve(item.name.upper()) == item
    assert registry.list_equipment() == [item]
    assert registry.list_monitor_targets() == []
    assert not any("password" in key for key in asdict(item))
    with pytest.raises(RegistryError, match="offline"):
        registry.get_password(item.id)
    edited = registry.update(item.id, offline(client="Another client"))
    assert edited.client == "Another client"
    assert edited.created_at == item.created_at
    registry.initialize()
    assert registry.get(item.id) == edited
    registry.delete(item.id)
    assert registry.list_equipment() == []
    with sqlite3.connect(registry.database_path) as conn:
        assert conn.execute("SELECT count(*) FROM equipment").fetchone()[0] == 0
        assert conn.execute("SELECT action FROM audit_log").fetchall() == [
            ("equipment.created",),
            ("equipment.updated",),
            ("equipment.deleted",),
        ]
