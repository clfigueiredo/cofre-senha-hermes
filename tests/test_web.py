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
