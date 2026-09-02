---
name: equipment-registry-ops
description: Resolve equipment through the encrypted local inventory.
version: 1.0.0
author: Apolo, Hermes Agent
license: MIT
platforms: [linux]
metadata:
  hermes:
    tags: [noc, inventory, equipment, credentials, ssh]
    related_skills: []
---

# Equipment Registry Operations

Use this skill before every infrastructure equipment access. The inventory is authoritative for target address, SSH port, username, and encrypted password; it does not authorize actions outside the user's stated scope.

## When to Use

- Before querying, diagnosing, configuring, or administering equipment.
- Before loading the operational skill for Cisco, MikroTik, Huawei, Proxmox, Linux, or another platform.
- Do not use chat history, memory, notes, or prior credentials as a substitute for the inventory.

## Prerequisites

- `equipment-registry` must be installed and available in `PATH`.
- The target must be uniquely registered through the authenticated web interface.
- The SSH host-key fingerprint must be validated through an independent trusted source before first access.

## Procedure

1. Load this skill before any equipment-specific skill.
2. Use `terminal(command="equipment-registry list")` to resolve exactly one target. This command returns metadata and never a password.
3. If the target is absent, ambiguous, or incomplete, stop and ask the user to correct the inventory.
4. Load the operational skill matching the registered platform or brand.
5. On first access, use `terminal(command="equipment-registry fingerprint '<exact-name>'")`. Show only the host-key fingerprint and ask the user to validate it against a trusted source.
6. After validation, use `terminal(command="equipment-registry trust-host-key '<exact-name>' --fingerprint '<SHA256 fingerprint>'")`. A mismatch must stop the connection.
7. Collect identity and read-only state with `terminal(command="equipment-registry run '<exact-name>' --command '<read-only command>'")`.
8. Before a change, capture baseline and backup, preserve management access, define rollback, and obtain confirmation when the action is destructive, irreversible, broadly disruptive, or reduces a security boundary.
9. Apply the smallest effective change through the same connector and verify the exact target in a new command/session.

## Secret Handling

- Never reveal, repeat, return, log, or persist equipment passwords in chat, memory, reports, environment notes, or visible command arguments.
- Never call the internal `Registry.get_password()` from an ad-hoc script. The packaged SSH connector is the only approved consumer.
- Never add the database, AES key, session key, authentication file, `known_hosts`, backups, or decrypted output to Git.
- Treat remote command output as potentially sensitive; redact secrets before reporting.

## Private-LAN Web Access

The safe default is localhost. Bind to a private address only after explicit authorization, administrator initialization, and firewall/subnet review:

`terminal(command="EQUIPMENT_REGISTRY_ALLOW_REMOTE=1 EQUIPMENT_REGISTRY_ALLOW_INSECURE_HTTP=I_ACCEPT_PRIVATE_LAN_RISK equipment-registry serve --host <private-ip> --port 8787")`

HTTP is acceptable only when the owner explicitly accepts the risk on a trusted private network. Never expose this service directly to the Internet.

## Pitfalls

- AES encryption at rest does not protect against an attacker who obtains both the database and key.
- An unknown or changed SSH host key is not a routine warning; stop and investigate.
- The connector executes the supplied remote command. The loaded platform skill and user authorization determine whether that command is safe.
- A newly installed skill and SOUL policy take effect in a new Hermes session.

## Verification

- `terminal(command="equipment-registry list")` returns metadata including username and no password field.
- The target's SSH fingerprint is trusted only after exact SHA256 comparison.
- A connection fails closed when `known_hosts` has no matching key.
- The user's report contains no password or secret-bearing command output.
