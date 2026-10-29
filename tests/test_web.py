from __future__ import annotations

from pathlib import Path

import pytest

from equipment_registry.app import create_app
from equipment_registry.auth import create_admin


@pytest.fixture
def app(tmp_path: Path):
    create_admin(tmp_path / "auth.json", "admin-test-password")
    application = create_app(
        {
            "TESTING": True,
            "DATA_DIR": tmp_path,
            "SECRET_KEY": "test-session-key-not-for-production",
        }
    )
    return application


@pytest.fixture
def client(app):
    return app.test_client()


def login(client):
    page = client.get("/login")
    token = page.data.decode().split('name="csrf_token" value="', 1)[1].split('"', 1)[0]
    return client.post(
        "/login",
        data={"username": "admin", "password": "admin-test-password", "csrf_token": token},
        follow_redirects=True,
    )


def csrf_from(response) -> str:
    return response.data.decode().split('name="csrf_token" value="', 1)[1].split('"', 1)[0]


def test_offline_form_and_authenticated_lifecycle(client):
    login(client)
    index = client.get("/").get_data(as_text=True)
    assert "Console local / offline" in index
    page = client.get("/equipment/new?access_type=offline")
    html = page.get_data(as_text=True)
    for field in [
        "ip",
        "ssh_port",
        "username",
        "password",
        "relay_host",
        "relay_port",
        "sftp_root",
    ]:
        assert f'name="{field}"' not in html
    for field in ["client", "parent_host", "console_type", "network_state", "access_type"]:
        assert f'name="{field}"' in html
    assert "script-src 'none'" in page.headers["Content-Security-Policy"]
    data = {
        "name": "n8n-restore-offline",
        "brand": "Hyper-V",
        "access_type": "offline",
        "client": "GOITS",
        "parent_host": "DESKTOP-5ERNE8J",
        "console_type": "hyper-v",
        "network_state": "disconnected",
        "csrf_token": csrf_from(page),
    }
    response = client.post("/equipment/new", data=data, follow_redirects=True)
    assert response.status_code == 200
    html = response.get_data(as_text=True)
    assert "n8n-restore-offline" in html
    assert "GOITS" in html
    assert "DESKTOP-5ERNE8J" in html
    assert "hyper-v" in html
    assert "Rede desconectada" in html
    registry = client.application.extensions["equipment_registry"]
    item = registry.resolve("n8n-restore-offline")
    assert item.access_type == "offline"
    edit_url = f"/equipment/{item.id}/edit"
    edit = client.get(edit_url)
    assert 'name="password"' not in edit.get_data(as_text=True)
    data.update(client="GOITS updated", csrf_token=csrf_from(edit))
    assert client.post(edit_url, data=data).status_code == 302
    assert registry.get(item.id).client == "GOITS updated"
    delete_url = f"/equipment/{item.id}/delete"
    deleted = client.post(
        delete_url,
        data={"confirmation": item.name, "csrf_token": csrf_from(client.get(delete_url))},
    )
    assert deleted.status_code == 302
    assert registry.list_equipment() == []


@pytest.mark.parametrize(
    "extra",
    [
        {"ip": "192.0.2.1"},
        {"ssh_port": "22"},
        {"username": "root"},
        {"password": "test-only"},
        {"network_state": "connected"},
        {"client": ""},
        {"access_type": "unknown"},
    ],
)
def test_offline_form_rejects_invalid_payload_without_echoing_secrets(client, extra):
    login(client)
    page = client.get("/equipment/new?access_type=offline")
    data = {
        "name": "offline-test",
        "brand": "Hyper-V",
        "access_type": "offline",
        "client": "GOITS",
        "parent_host": "HOST",
        "console_type": "hyper-v",
        "network_state": "disconnected",
        "csrf_token": csrf_from(page),
    }
    data.update(extra)
    response = client.post("/equipment/new", data=data)
    assert response.status_code in (200, 400)
    assert b"test-only" not in response.data
    assert client.application.extensions["equipment_registry"].list_equipment() == []


def test_offline_routes_require_auth_and_csrf(client):
    assert client.get("/equipment/new?access_type=offline").status_code == 302
    login(client)
    assert client.post("/equipment/new", data={"access_type": "offline"}).status_code == 400


def test_first_run_setup_creates_admin_without_storing_plaintext(tmp_path: Path) -> None:
    application = create_app(
        {
            "TESTING": True,
            "DATA_DIR": tmp_path,
            "SECRET_KEY": "test-session-key-not-for-production",
        }
    )
    first_client = application.test_client()
    redirected = first_client.get("/", follow_redirects=False)
    assert redirected.status_code == 302
    assert "/setup" in redirected.headers["Location"]

    setup_page = first_client.get("/setup")
    token = csrf_from(setup_page)
    completed = first_client.post(
        "/setup",
        data={
            "password": "a-secure-admin-password",
            "password_confirmation": "a-secure-admin-password",
            "csrf_token": token,
        },
        follow_redirects=True,
    )
    assert completed.status_code == 200
    assert b"Equipamentos" in completed.data
    assert b"a-secure-admin-password" not in (tmp_path / "auth.json").read_bytes()

    second_client = application.test_client()
    assert second_client.get("/setup").status_code == 404


def test_first_run_setup_is_rejected_from_remote_address(tmp_path: Path) -> None:
    application = create_app(
        {
            "TESTING": True,
            "DATA_DIR": tmp_path,
            "SECRET_KEY": "test-session-key-not-for-production",
        }
    )
    remote_client = application.test_client()
    response = remote_client.get("/setup", environ_base={"REMOTE_ADDR": "192.168.1.20"})
    assert response.status_code == 403


def test_private_pages_require_login(client) -> None:
    response = client.get("/", follow_redirects=False)
    assert response.status_code == 302
    assert "/login" in response.headers["Location"]


def test_login_rejects_bad_credentials(client) -> None:
    page = client.get("/login")
    token = csrf_from(page)
    response = client.post(
        "/login",
        data={"username": "admin", "password": "wrong", "csrf_token": token},
        follow_redirects=True,
    )
    assert b"Credenciais inv" in response.data


def test_authenticated_user_can_create_and_list_without_password_disclosure(client) -> None:
    assert login(client).status_code == 200
    page = client.get("/equipment/new")
    token = csrf_from(page)
    response = client.post(
        "/equipment/new",
        data={
            "name": "SW-CORE-01",
            "ip": "192.0.2.10",
            "ssh_port": "22",
            "username": "admin",
            "brand": "Cisco",
            "password": "web-secret-value",
            "csrf_token": token,
        },
        follow_redirects=True,
    )
    assert response.status_code == 200
    assert b"SW-CORE-01" in response.data
    assert b"192.0.2.10" in response.data
    assert b"admin" in response.data
    assert b"web-secret-value" not in response.data


def test_authenticated_user_can_create_equipment_with_ddns(client) -> None:
    assert login(client).status_code == 200
    page = client.get("/equipment/new")
    assert b"Endere\xc3\xa7o IP ou DDNS/FQDN" in page.data
    token = csrf_from(page)

    response = client.post(
        "/equipment/new",
        data={
            "name": "Pfsense-VLL",
            "ip": "VLL.DYNDNS.INFO.",
            "ssh_port": "2222",
            "username": "admin",
            "brand": "pfSense",
            "password": "web-secret-value",
            "csrf_token": token,
        },
        follow_redirects=True,
    )

    assert response.status_code == 200
    assert b"vll.dyndns.info" in response.data


def test_authenticated_user_can_register_a_loopback_ssh_relay(client) -> None:
    assert login(client).status_code == 200
    page = client.get("/equipment/new")
    token = csrf_from(page)

    response = client.post(
        "/equipment/new",
        data={
            "name": "Proxmox-Glagio",
            "ip": "10.10.1.211",
            "ssh_port": "22",
            "username": "root",
            "brand": "Proxmox",
            "relay_host": "127.0.0.1",
            "relay_port": "22211",
            "password": "web-secret-value",
            "csrf_token": token,
        },
        follow_redirects=True,
    )

    equipment = client.application.extensions["equipment_registry"].list_equipment()[0]
    assert response.status_code == 200
    assert equipment.relay_host == "127.0.0.1"
    assert equipment.relay_port == 22211


def test_authenticated_user_can_enable_sftp_with_explicit_root(client) -> None:
    assert login(client).status_code == 200
    page = client.get("/equipment/new")
    assert b"Raiz SFTP" in page.data
    token = csrf_from(page)

    response = client.post(
        "/equipment/new",
        data={
            "name": "Supply-FTP",
            "ip": "sftp.example.test",
            "ssh_port": "2222",
            "username": "admin",
            "brand": "SFTP",
            "sftp_root": "/",
            "password": "web-secret-value",
            "csrf_token": token,
        },
        follow_redirects=True,
    )

    equipment = client.application.extensions["equipment_registry"].list_equipment()[0]
    assert response.status_code == 200
    assert equipment.sftp_root == "/"
    assert b"SFTP habilitado" in response.data


def test_authenticated_user_can_create_monitor_target_without_secret(client) -> None:
    assert login(client).status_code == 200
    page = client.get("/monitor-target/new")
    token = csrf_from(page)
    response = client.post(
        "/monitor-target/new",
        data={
            "name": "Pfsense-DRN-WAN1",
            "endpoint": "dornas1.dyndns.org",
            "protocol": "snmp",
            "port": "161",
            "brand": "pfSense",
            "csrf_token": token,
        },
        follow_redirects=True,
    )

    assert response.status_code == 200
    assert b"Pfsense-DRN-WAN1" in response.data
    assert b"dornas1.dyndns.org" in response.data
    assert b"Senha" not in page.data


def test_delete_requires_a_confirmation_page_and_exact_name(client) -> None:
    login(client)
    new_page = client.get("/equipment/new")
    token = csrf_from(new_page)
    client.post(
        "/equipment/new",
        data={
            "name": "SW-DELETE-ME",
            "ip": "192.0.2.88",
            "ssh_port": "22",
            "username": "admin",
            "brand": "Cisco",
            "password": "secret-value",
            "csrf_token": token,
        },
    )
    equipment = client.application.extensions["equipment_registry"].list_equipment()[0]

    confirmation = client.get(f"/equipment/{equipment.id}/delete")
    assert confirmation.status_code == 200
    token = csrf_from(confirmation)
    rejected = client.post(
        f"/equipment/{equipment.id}/delete",
        data={"csrf_token": token, "confirmation": "wrong-name"},
        follow_redirects=True,
    )
    assert b"Digite o nome exato" in rejected.data
    assert len(client.application.extensions["equipment_registry"].list_equipment()) == 1

    confirmation = client.get(f"/equipment/{equipment.id}/delete")
    token = csrf_from(confirmation)
    accepted = client.post(
        f"/equipment/{equipment.id}/delete",
        data={"csrf_token": token, "confirmation": "SW-DELETE-ME"},
        follow_redirects=True,
    )
    assert b"Equipamento exclu" in accepted.data
    assert client.application.extensions["equipment_registry"].list_equipment() == []


def test_post_without_csrf_is_rejected(client) -> None:
    login(client)
    response = client.post(
        "/equipment/new",
        data={
            "name": "R1",
            "ip": "192.0.2.1",
            "ssh_port": "22",
            "username": "admin",
            "brand": "Cisco",
            "password": "secret",
        },
    )
    assert response.status_code == 400


def test_security_headers_are_present(client) -> None:
    response = client.get("/login")
    assert response.headers["X-Content-Type-Options"] == "nosniff"
    assert response.headers["X-Frame-Options"] == "DENY"
    assert "default-src 'self'" in response.headers["Content-Security-Policy"]
    assert response.headers["Cache-Control"] == "no-store"


def test_health_does_not_disclose_secrets(client) -> None:
    response = client.get("/health")
    assert response.status_code == 200
    assert response.json == {"database": "ok", "status": "ok"}
