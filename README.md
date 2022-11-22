# EvernightRealm

> Host your own private world for your group — immersive activities, characters and virtual assets on a machine you own.

[English](./README.md) · [简体中文](./README.zh-CN.md) · [繁體中文（台灣）](./README.zh-TW.md) · [日本語](./README.ja-JP.md)

## What is EvernightRealm?

EvernightRealm is a self-hosted, offline-first platform for a small group of players: run immersive activities together, play characters, and trade virtual assets — all on a local network, with no internet, cloud accounts or telemetry.

## Features (under development)

- **Immersive activities** — organize scenes, phases and events for your group
- **Characters & identities** — player, NPC and admin roles in one private world
- **Virtual assets** — items with real ownership and auditable trades
- **Private chat** — messages stay on your own server
- **Offline-first** — everything runs on a machine you own; no cloud required

## Current status

EvernightRealm is under active development and no stable release is available yet. The server can already be built as a **single executable**: one port serves both the web interface (so far the app shell — switchable UI language and a server connectivity probe, with business features still in development) and the API endpoints, so a browser pointed at that address is all you need — no separate static hosting.

The server also ships a maintenance command that produces a **consistent backup package**: a single-file database snapshot — taken while the server keeps running, and not a copy of the live write-ahead-log file — together with the config file and the media, document and upload directories, each file recorded with its size and SHA-256 in a manifest. A matching `restore` command turns such a package back into a **fresh, empty data directory**: it re-verifies every file against the manifest, reads the snapshot's database facts and compares them with the manifest both before and after the files land, refuses to overwrite any existing directory (back up that directory yourself first), refuses a database schema newer than the running executable, and records the restore itself as a server-side audit entry. A backup package still cannot be encrypted, and old packages are not pruned automatically.

A one-time Root initialization is available as a **local command only**:

    evernight-server init-root --password-stdin --data-dir <data directory>

It reads the password from stdin (two lines: the password and its confirmation), stores an Argon2id hash in the data directory's `config.yaml`, and prints nothing secret — no plaintext, no default password is ever generated or shown. Because handing out the server's highest privilege is authorized by being able to run a command on the server host, this step opens no HTTP endpoint and no listening socket at all; CORS, client-reported addresses or hiding a button are not authorization. Initialization is refused while the service holds the single-writer instance lock, while `ER_SECURITY_ROOT_PASSWORD_HASH` overrides the file, or while the audit table does not exist yet, and it can never run a second time — the Root password is rotated through the authenticated in-service change flow (`POST /auth/password/change` after signing in as Root); only a genuinely lost password justifies the local recovery command below. A read-only `evernight-server root-status` reports whether Root exists without creating or changing anything, and reports only that much: never a config path, hash or bootstrap secret. Success and refusal both land in the Root audit table without any password.

Recovering a lost Root password is likewise a **local command only**:

    evernight-server recover-root --password-stdin --confirm --data-dir <data directory>

It also reads the new password from stdin (two lines, password and confirmation) and never accepts a password value on the command line, and it requires the service to be stopped: a running server holds the credential in memory, so editing the config file would not make it re-read — the result would be "the terminal said it succeeded while the old password still works", a state far harder to diagnose than a refusal. Recovery neither asks for nor verifies the old password: being able to run this command on the host and to read that config file is the entire authorization for the action, which is why there is also no backdoor password, no downloadable recovery file and no HTTP endpoint. On success the credential in the config file is overwritten with the Argon2id encoding of the new password, every Root session is revoked inside the same database transaction (the next request from those devices is rejected), and a `server.root_recover` audit entry is written; ordinary account sessions are not touched at all. If that transaction cannot be committed, the config file is switched back to the credential it held and the command reports failure, leaving the usable state exactly as it was (a double fault where even the rollback fails is recorded as an Error in the persistent log file and explicitly asks for a manual follow-up entry). `--confirm` must be given explicitly, because the price of an overwrite is that the old password dies permanently and every Root device is signed out. When the config file has no credential yet the command refuses and points at `init-root`; an existing value that is too corrupt to verify can still be recovered — that is precisely the shape `init-root` refuses, and the two write paths each have exactly one success shape.

A first-run screen has to state honestly whether the server is not initialized yet, so the server also answers a read-only `GET /root/init-status`: three booleans only — whether the config file exists, whether a Root credential is present, and whether the environment override is set. It returns no path, no length, no fragment of any credential, and it writes neither to the database nor to the audit log. It says whether, never how to change: initializing Root is still reachable only through `init-root` run on the server host itself (overwriting a lost credential is the `recover-root` command above, and neither one is reachable over the network).

## How it will work (once released)

- One person hosts the server on their machine (Windows or Linux)
- Everyone else joins from a browser on the same local network
- No third-party registration; data stays on the host's machine

## Languages

The interface will be available in Simplified Chinese, Traditional Chinese (Taiwan), English and Japanese.

## Building from source

The Windows executable carries an icon that is generated, not committed: `cmd/evernight-server/resource_windows_*.syso` is derived from `assets/icons/EvernightRealmBackendRounded.ico`. On a fresh clone, run

    python tools/icons/generate_icons.py

before building, otherwise the executable is produced without an icon and `go build` reports nothing. `python tools/icons/generate_icons.py --check` reports the current state without writing anything; see `tools/icons/README.md`.

## License

Mulan Permissive Software License, Version 2 (MulanPSL-2.0).
