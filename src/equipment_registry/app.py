from __future__ import annotations

import ipaddress
import os
import secrets
import time
from collections import defaultdict
from collections.abc import Callable
from functools import wraps
from pathlib import Path
from typing import Any, TypeVar

from flask import (
    Flask,
    abort,
    flash,
    jsonify,
    redirect,
    render_template,
    request,
    session,
    url_for,
)

from .auth import create_admin, verify_admin
from .storage import EquipmentInput, NotFoundError, Registry, ValidationError

F = TypeVar("F", bound=Callable[..., Any])
_LOGIN_ATTEMPTS: dict[str, list[float]] = defaultdict(list)


def _secret_file(path: Path) -> str:
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    try:
        descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    except FileExistsError:
        pass
    else:
        with os.fdopen(descriptor, "w", encoding="ascii") as stream:
            stream.write(secrets.token_hex(32))
    os.chmod(path, 0o600)
    value = path.read_text(encoding="ascii").strip()
    if len(value) < 32:
        raise RuntimeError("Chave de sessão inválida.")
    return value


def create_app(test_config: dict[str, Any] | None = None) -> Flask:
    app = Flask(__name__)
    data_dir = Path(os.environ.get("EQUIPMENT_REGISTRY_DATA_DIR", "~/.local/share/equipment-registry")).expanduser()
    app.config.update(
        DATA_DIR=data_dir,
        SESSION_COOKIE_HTTPONLY=True,
        SESSION_COOKIE_SAMESITE="Strict",
        SESSION_COOKIE_SECURE=os.environ.get("EQUIPMENT_REGISTRY_HTTPS") == "1",
        MAX_CONTENT_LENGTH=32 * 1024,
        PERMANENT_SESSION_LIFETIME=1800,
    )
    if test_config:
        app.config.update(test_config)
    data_dir = Path(app.config["DATA_DIR"])
    app.secret_key = app.config.get("SECRET_KEY") or _secret_file(data_dir / "session.key")
    auth_path = data_dir / "auth.json"
    registry = Registry(data_dir / "equipment.db", data_dir / "encryption.key")
    registry.initialize()
    app.extensions["equipment_registry"] = registry

    def login_required(view: F) -> F:
        @wraps(view)
        def wrapped(*args: Any, **kwargs: Any):
            if not auth_path.exists():
                return redirect(url_for("setup"))
            if not session.get("authenticated"):
                return redirect(url_for("login"))
            return view(*args, **kwargs)

        return wrapped  # type: ignore[return-value]

    def csrf_token() -> str:
        token = session.get("csrf_token")
        if not token:
            token = secrets.token_urlsafe(32)
            session["csrf_token"] = token
        return token

    app.jinja_env.globals["csrf_token"] = csrf_token

    @app.before_request
    def enforce_csrf() -> None:
        if request.method == "POST":
            expected = session.get("csrf_token", "")
            received = request.form.get("csrf_token", "")
            if not expected or not secrets.compare_digest(expected, received):
                abort(400, "Token CSRF inválido.")

    @app.after_request
    def security_headers(response):
        response.headers["Content-Security-Policy"] = (
            "default-src 'self'; style-src 'self'; img-src 'self' data:; "
            "script-src 'none'; frame-ancestors 'none'; base-uri 'none'; form-action 'self'"
        )
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["Referrer-Policy"] = "no-referrer"
        response.headers["Cache-Control"] = "no-store"
        return response

    @app.get("/health")
    def health():
        return jsonify(status="ok", database="ok" if registry.health() else "error")

    @app.route("/setup", methods=["GET", "POST"])
    def setup():
        if auth_path.exists():
            abort(404)
        remote_address: ipaddress.IPv4Address | ipaddress.IPv6Address | None = None
        try:
            remote_address = ipaddress.ip_address(request.remote_addr or "")
        except ValueError:
            abort(403)
        if remote_address is None or not remote_address.is_loopback:
            abort(403, "A configuração inicial só pode ser feita localmente.")
        if request.method == "POST":
            password = request.form.get("password", "")
            confirmation = request.form.get("password_confirmation", "")
            if password != confirmation:
                flash("As senhas não conferem.", "error")
            else:
                try:
                    create_admin(auth_path, password)
                except ValueError as exc:
                    flash(str(exc), "error")
                else:
                    session.clear()
                    session["authenticated"] = True
                    session["csrf_token"] = secrets.token_urlsafe(32)
                    session.permanent = True
                    return redirect(url_for("index"))
        return render_template("setup.html")

    @app.route("/login", methods=["GET", "POST"])
    def login():
        if not auth_path.exists():
            return redirect(url_for("setup"))
        if request.method == "POST":
            remote = request.remote_addr or "unknown"
            now = time.monotonic()
            for address, stamps in list(_LOGIN_ATTEMPTS.items()):
                fresh = [stamp for stamp in stamps if now - stamp < 300]
                if fresh:
                    _LOGIN_ATTEMPTS[address] = fresh
                else:
                    _LOGIN_ATTEMPTS.pop(address, None)
            attempts = [stamp for stamp in _LOGIN_ATTEMPTS[remote] if now - stamp < 300]
            _LOGIN_ATTEMPTS[remote] = attempts
            if len(attempts) >= 5:
                abort(429, "Muitas tentativas. Aguarde cinco minutos.")
            if verify_admin(
                data_dir / "auth.json",
                request.form.get("username", ""),
                request.form.get("password", ""),
            ):
                _LOGIN_ATTEMPTS.pop(remote, None)
                session.clear()
                session["authenticated"] = True
                session["csrf_token"] = secrets.token_urlsafe(32)
                session.permanent = True
                return redirect(url_for("index"))
            _LOGIN_ATTEMPTS[remote].append(now)
            flash("Credenciais inválidas.", "error")
        return render_template("login.html")

    @app.post("/logout")
    @login_required
    def logout():
        session.clear()
        return redirect(url_for("login"))

    @app.get("/")
    @login_required
    def index():
        return render_template("index.html", equipment=registry.list_equipment())

    @app.route("/equipment/new", methods=["GET", "POST"])
    @login_required
    def equipment_new():
        if request.method == "POST":
            try:
                registry.create(_form_input(require_password=True))
            except (ValidationError, ValueError) as exc:
                flash(str(exc), "error")
            else:
                flash("Equipamento cadastrado.", "success")
                return redirect(url_for("index"))
        return render_template("equipment_form.html", item=None)

    @app.route("/equipment/<equipment_id>/edit", methods=["GET", "POST"])
    @login_required
    def equipment_edit(equipment_id: str):
        try:
            item = registry.get(equipment_id)
            if request.method == "POST":
                registry.update(equipment_id, _form_input(require_password=False))
                flash("Equipamento atualizado.", "success")
                return redirect(url_for("index"))
        except (ValidationError, ValueError) as exc:
            flash(str(exc), "error")
        except NotFoundError:
            abort(404)
        return render_template("equipment_form.html", item=item)

    @app.route("/equipment/<equipment_id>/delete", methods=["GET", "POST"])
    @login_required
    def equipment_delete(equipment_id: str):
        try:
            item = registry.get(equipment_id)
            if request.method == "POST":
                if request.form.get("confirmation", "") != item.name:
                    flash("Digite o nome exato do equipamento para confirmar.", "error")
                else:
                    registry.delete(equipment_id)
                    flash("Equipamento excluído.", "success")
                    return redirect(url_for("index"))
        except NotFoundError:
            abort(404)
        return render_template("equipment_delete.html", item=item)

    def _form_input(*, require_password: bool) -> EquipmentInput:
        password = request.form.get("password", "")
        if not require_password and not password:
            password = None
        return EquipmentInput(
            name=request.form.get("name", ""),
            ip=request.form.get("ip", ""),
            ssh_port=int(request.form.get("ssh_port", "0")),
            password=password,
            brand=request.form.get("brand", ""),
            username=request.form.get("username", ""),
        )

    return app
