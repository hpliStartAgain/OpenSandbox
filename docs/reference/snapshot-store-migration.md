---
title: Snapshot Store Migration
description: Migration guide for switching the server snapshot store from SQLite to PostgreSQL.
---

# Snapshot Store Migration Guide

Features: [PostgreSQL store #1653](https://github.com/opensandbox-group/OpenSandbox/pull/1653), [migration #1669](https://github.com/opensandbox-group/OpenSandbox/issues/1669)

## Background

The server persists the public snapshot catalog in a configurable store. SQLite is the
default backend; the PostgreSQL backend is opt-in for operators that need external
persistence. The PostgreSQL backend does **not** read an existing SQLite database, so a
server switched from `store.type = "sqlite"` to `store.type = "postgresql"` starts with an
empty snapshot catalog.

Use the `migrate-snapshots` command to copy existing snapshot records from SQLite to
PostgreSQL before switching the store type.

## Before you start

- Stop the server (or at least stop issuing snapshot requests) so the source SQLite
  database is not modified while it is read.
- The target PostgreSQL database must be reachable and the configured role must be able to
  create the `snapshots` table.
- Run the command against the same target database the server will use after the switch.

## Migrate

Dry-run first to see what would be copied:

```bash
opensandbox-server migrate-snapshots \
  --from ~/.opensandbox/opensandbox.db \
  --to postgresql://user:password@localhost:5432/opensandbox \
  --dry-run
```

Then run the migration:

```bash
opensandbox-server migrate-snapshots \
  --from ~/.opensandbox/opensandbox.db \
  --to postgresql://user:password@localhost:5432/opensandbox
```

The command prints a summary:

```text
Snapshots migrated: total=42, migrated=42, skipped=0
```

## Behavior

- Records whose id already exists in PostgreSQL are skipped, so the command can be re-run
  safely. A repeated run reports `migrated=0` and `skipped=42`.
- `--dry-run` reports the counts without writing anything, including without creating the
  PostgreSQL `snapshots` table, so it works with read-only target credentials.
- The source SQLite database is opened read-only and is never modified, so a backup on a
  read-only mount can be migrated.
- The PostgreSQL schema is created only on a real migration run, when the table does not
  already exist.
- Timestamps stored as naive UTC in SQLite are written as `TIMESTAMPTZ` in UTC.
- Operation generation and attempt counters are preserved, while any source
  lease owner and expiry are cleared. Stop the SQLite Server before migration;
  a lease from that stopped process must not block PostgreSQL recovery.
- Legacy unfinished `Creating` rows that predate the attempt counter are
  conservatively marked as already started, so recovery observes existing
  runtime state instead of repeating external creation side effects.

## Switch the server

After migration, update the server configuration:

```toml
[store]
type = "postgresql"

[store.postgresql]
# In production, inject the DSN with OPENSANDBOX_STORE_POSTGRESQL_DSN instead.
dsn = "postgresql://user:password@localhost:5432/opensandbox"
```

Restart the server. Snapshot lookups and restore requests now read the shared PostgreSQL
catalog, including the migrated records.

For Kubernetes public snapshots, you may then increase the active Server replica
count. Every replica must use this same PostgreSQL database. Docker public
snapshots remain limited to one active Server.

## Verify

- `GET /v1/sandboxes/{id}/snapshots` returns the migrated snapshot records.
- Restoring a sandbox with an existing `snapshotId` succeeds.

## Roll back the Server version

The PostgreSQL schema upgrade adds columns with backward-compatible defaults, so
an older Server can still read the snapshot table. Before starting an older
version, scale back to one active Server because versions without operation
leases cannot coordinate in-flight snapshot work. The migration command is
one-way and does not copy later PostgreSQL changes back to SQLite.
