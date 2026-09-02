# Hermes installation contract

This repository contains a security-sensitive local equipment vault. When the user asks to install it:

1. Read `skill/equipment-registry-ops/SKILL.md` and `SECURITY.md` before executing anything.
2. Inspect `scripts/install.py`; do not run unreviewed code blindly.
3. Run `python3 scripts/install.py` from the repository root. Use `--service` only when the user asks for persistent startup.
4. Keep the default bind `127.0.0.1`. Use a private-LAN address only after explicit authorization and firewall/subnet review. Never expose the service directly to the Internet.
5. Do not request an administrator or equipment password in chat. The administrator sets it interactively with `equipment-registry init` or through `/setup` on a trusted connection.
6. Verify `equipment-registry list`, the `/health` endpoint when the service is running, installed skill path, and the managed policy block in `$HERMES_HOME/SOUL.md`.
7. Tell the user to start a new Hermes session so the installed skill and policy load.

Never commit or transmit `equipment.db`, `encryption.key`, `session.key`, `auth.json`, `known_hosts`, `.env`, backups, or credential-bearing logs.
