# Hermes installation contract

This repository contains a security-sensitive local equipment vault. When the user asks to install it:

1. Read `skill/equipment-registry-ops/SKILL.md` and `SECURITY.md` before executing anything.
2. Inspect `scripts/install.py`; do not run unreviewed code blindly.
3. Run `python3 scripts/install.py` from the repository root. Use `--service` only when the user asks for persistent startup.
4. The web interface listens on `0.0.0.0:8787` by default so the user can register equipment from the local network. Use `--host` only if the user asks for a different address. Never expose the service directly to the Internet.
5. Do not request an administrator or equipment password in chat. The user creates the administrator at `http://<server-ip>:8787/setup` (or with `equipment-registry init`) and registers equipment through the web interface.
6. The installer does not modify `SOUL.md` or any other Hermes persona file. Do not add inventory policies to `SOUL.md` on your own.
7. Verify `equipment-registry list`, the `/health` endpoint when the service is running, and the installed skill path.
8. Tell the user the interface URL and to start a new Hermes session so the installed skill loads.

Never commit or transmit `equipment.db`, `encryption.key`, `session.key`, `auth.json`, `known_hosts`, `.env`, backups, or credential-bearing logs.
