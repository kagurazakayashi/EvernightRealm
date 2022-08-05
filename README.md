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

## How it will work (once released)

- One person hosts the server on their machine (Windows or Linux)
- Everyone else joins from a browser on the same local network
- No third-party registration; data stays on the host's machine

## Languages

The interface will be available in Simplified Chinese, Traditional Chinese (Taiwan), English and Japanese.

## License

Mulan Permissive Software License, Version 2 (MulanPSL-2.0).
