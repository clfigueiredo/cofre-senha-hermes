---
name: equipment-registry-ops
description: Resolve equipment through the encrypted local inventory.
version: 1.4.0
author: Apolo, Hermes Agent
license: MIT
platforms: [linux]
metadata:
  hermes:
    tags: [noc, inventory, equipment, credentials, ssh, sftp]
    related_skills: []
---

# Equipment Registry Operations

Use this skill before every infrastructure equipment access. The inventory is authoritative for SSH/SFTP target address, port, username, encrypted password, and optional SFTP root. It also records credential-free monitoring targets, which authorize only the explicitly registered read-only protocol and port; neither record type authorizes actions outside the user's stated scope.

## When to Use

- Before querying, diagnosing, configuring, or administering equipment.
- Before loading the operational skill for Cisco, MikroTik, Huawei, Proxmox, Linux, or another platform.
- Do not use chat history, memory, notes, or prior credentials as a substitute for the inventory.

## Prerequisites

- `equipment-registry` must be installed and available in `PATH`.
- The target must be uniquely registered through the authenticated web interface.
- The connector uses trust on first use (TOFU): it pins the key presented on the first connection and rejects later key changes.

## Procedure

1. Load this skill before any equipment-specific skill.
2. For SSH administration, use `terminal(command="equipment-registry list")` and resolve exactly one equipment target. This command returns metadata and never a password.
3. For credential-free monitoring, use `terminal(command="equipment-registry monitor-list")` and match exactly one registered monitoring target by name, endpoint, protocol and port.
4. If the target is absent, ambiguous, incomplete, or the requested probe is broader than its registered protocol/port, stop and request a correction.
5. A record marked **console local/offline** authorizes only the declared console procedure on its parent host; não autoriza SSH, SFTP, relay ou conexão de rede; o host pai não é um alvo autorizado implicitamente. Confirm the record declares `network_state=disconnected` before giving console steps, and preserve that isolation.
6. Load the operational skill matching the registered platform or brand.
7. For SSH administration, collect identity and read-only state with `terminal(command="equipment-registry run '<exact-name>' --command '<read-only command>'")`. On first use, the connector automatically stores the presented host key without prompting the user.
8. A relay SSH is allowed only when it is persisted in the authenticated equipment record and points to `127.0.0.1` or `::1`. The relay changes transport only; keep the logical target IP/port and its pinned host key unchanged. Never supply a relay endpoint ad hoc in a command.
9. A monitoring target has no credential and must never be used with the SSH connector. Use it only for the explicitly registered read-only probe. An SNMP/UDP transport reachability probe cannot prove that an SNMP service accepted credentials; report it as inconclusive unless the authorized monitoring system itself returns a validated collection result.
10. For an equipment record with SFTP enabled, use `equipment-registry sftp-list '<exact-name>' --path '<relative-dir>'` to inspect metadata and `equipment-registry sftp-download '<exact-name>' '<relative-file>' --output '<new-local-path>'` to download. Never bypass the configured root or overwrite an existing local file.
11. SFTP authorization is read-only: never simulate or add upload, delete, rename, mkdir, chmod/setstat, recursive download, or remote execution without a separate reviewed change and explicit user authorization.
12. If a previously pinned SSH host key changes, stop and investigate; never overwrite it automatically.
13. Before a change, capture baseline and backup, preserve management access, define rollback, and obtain confirmation when the action is destructive, irreversible, broadly disruptive, or reduces a security boundary.
14. Apply the smallest effective change through the same connector and verify the exact target in a new command/session.

## Secret Handling

- Never reveal, repeat, return, log, or persist equipment passwords in chat, memory, reports, environment notes, or visible command arguments.
- Never call the internal `Registry.get_password()` from an ad-hoc script. The packaged SSH/SFTP connectors are the only approved consumers.
- Never add the database, AES key, session key, authentication file, `known_hosts`, backups, or decrypted output to Git.
- Treat remote command output as potentially sensitive; redact secrets before reporting.

## Private-LAN Web Access

The safe default is localhost. Bind to a private address only after explicit authorization, administrator initialization, and firewall/subnet review:

`terminal(command="EQUIPMENT_REGISTRY_ALLOW_REMOTE=1 EQUIPMENT_REGISTRY_ALLOW_INSECURE_HTTP=I_ACCEPT_PRIVATE_LAN_RISK equipment-registry serve --host <private-ip> --port 8787")`

HTTP is acceptable only when the owner explicitly accepts the risk on a trusted private network. Never expose this service directly to the Internet.

## Pitfalls

- AES encryption at rest does not protect against an attacker who obtains both the database and key.
- A first-use SSH key is accepted automatically, so the first connection is not protected against interception. A later key change must stop the connection and be investigated.
- The connector executes the supplied remote command. The loaded platform skill and user authorization determine whether that command is safe.
- SFTP v3 cannot completely remove remote filesystem TOCTOU. Use a read-only, preferably chrooted/restricted account and treat all remote names, metadata, and bytes as untrusted.
- A newly installed skill and SOUL policy take effect in a new Hermes session.

## Verification

- `terminal(command="equipment-registry list")` returns metadata including username and no password field.
- The first connection creates a `known_hosts` entry automatically.
- Later connections fail closed when the pinned host key no longer matches.
- `equipment-registry sftp-list` returns only metadata inside the configured root; `sftp-download` creates a new `0600` file and reports size plus SHA-256.
- The user's report contains no password or secret-bearing command output.
