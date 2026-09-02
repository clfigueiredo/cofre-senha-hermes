from __future__ import annotations

import json
import os
from pathlib import Path

from werkzeug.security import check_password_hash, generate_password_hash


def create_admin(path: Path, password: str) -> None:
    if len(password) < 12:
        raise ValueError("A senha administrativa precisa ter pelo menos 12 caracteres.")
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    temporary = path.with_suffix(".tmp")
    temporary.write_text(
        json.dumps({"username": "admin", "password_hash": generate_password_hash(password)}),
        encoding="utf-8",
    )
    os.chmod(temporary, 0o600)
    temporary.replace(path)
    os.chmod(path, 0o600)


def verify_admin(path: Path, username: str, password: str) -> bool:
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return False
    return username == data.get("username") == "admin" and check_password_hash(
        data.get("password_hash", ""), password
    )
