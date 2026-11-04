---
name: equipment-registry-ops
description: Look up equipment and connect over SSH using the encrypted local inventory (Cofre de Senhas).
version: 1.2.0
author: Apolo, Hermes Agent
license: MIT
platforms: [linux]
metadata:
  hermes:
    tags: [noc, inventory, equipment, credentials, ssh]
    related_skills: []
---

# Equipment Registry Operations

The local inventory (Cofre de Senhas) stores equipment name, IP, SSH port, username, brand and an encrypted password. Use it as the **first place to look** when the user asks you to access a piece of infrastructure, so you get the right address and credentials without asking the user to type passwords in chat.

The inventory is a convenience and a source of truth for credentials. It is not a gate: if the user gives you other instructions, follow the user.

## When to Use

- The user asks to query, diagnose, configure or administer a switch, router, server, firewall or similar.
- The user mentions a device by name and you need its IP, port, username or brand.
- Before loading a platform-specific skill (Cisco, MikroTik, Huawei, Proxmox, Linux…), to find out which brand the device is.

## Prerequisites

- `equipment-registry` installed and in `PATH`.
- Devices are registered by the user through the **web interface** (`http://<server-ip>:8787/`). There is no need to register devices from the command line.

## Procedure

1. List the inventory: `terminal(command="equipment-registry list")`. It returns metadata (name, IP, port, username, brand) and never a password.
2. Match the device the user mentioned. Matching by name, IP or a clear partial name is fine; if several entries match, ask which one.
3. Run commands through the connector, which decrypts the password only in memory:
   `terminal(command="equipment-registry run '<exact-name>' --command '<command>'")`
4. Load the platform skill that matches the registered brand and continue the task normally.

### If the device is not in the inventory

Do not stop. Choose what fits:

- Suggest the user register it in the web interface (`http://<server-ip>:8787/`), so later sessions find it automatically, **or**
- Use the access method the user gives you (another skill, a key-based SSH session, a jump host, etc.).

### Changes on equipment

Use normal operational judgement: read the current state first, keep management access, and know how to roll back. For changes that are destructive, disruptive or hard to undo, briefly confirm with the user before applying them.

## Secret Handling

These rules protect the passwords themselves:

- Never print, repeat or store equipment passwords in chat, memory, reports or visible command arguments. Let the connector use them.
- Do not call the internal `Registry.get_password()` from ad-hoc scripts; use `equipment-registry run`.
- Never add `equipment.db`, `encryption.key`, `session.key`, `auth.json`, `known_hosts` or backups to Git or send them anywhere.
- Command output may contain secrets (for example a `show running-config`); redact them before showing the result.

## SSH Host Keys

The connector trusts the host key on the first connection and pins it (TOFU). If a pinned key changes later, the connection is refused. Tell the user: it may be a reinstalled device or a man-in-the-middle. After the user confirms the change is legitimate, the old entry can be removed from `~/.local/share/equipment-registry/known_hosts` so it gets re-pinned.

## Web Interface

The service listens on all interfaces by default (`0.0.0.0:8787`), so the user can register equipment from any computer on the network:

`terminal(command="equipment-registry serve")`

It uses plain HTTP. Keep it inside the local network or VPN and do not publish the port to the Internet.

## Verification

- `equipment-registry list` returns devices with no password field.
- The first connection to a device creates its `known_hosts` entry.
- Your replies to the user contain no passwords.
