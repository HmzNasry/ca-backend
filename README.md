# ca-backend

This service now persists all mutable state (accounts, bans, admins, and the
user registry used by the socket server) in a relational database managed by
SQLAlchemy. SQLite is still the default for local development, but production
deployments (Render, etc.) should provide a PostgreSQL connection string via
`DATABASE_URL`.

## Environment variables

| Name | Description |
| --- | --- |
| `DATABASE_URL` | SQLAlchemy connection string. Defaults to `sqlite:///./chatapp.db` when unset. Use `postgresql+psycopg2://<user>:<pass>@<host>:<port>/<db>` on Render. |

## Local development

1. `cd ca-backend`
2. `python -m venv .venv && source .venv/bin/activate`
3. `pip install -r requirements.txt`
4. Optionally set `DATABASE_URL` (leave unset for the bundled SQLite file).
5. `uvicorn app.main:app --reload`

`app/db.py` automatically calls `init_db()` so any missing tables are created on
boot.

## Render deployment

1. Create a **Render PostgreSQL (Free)** instance.
2. Copy the provided internal connection string (it uses the `postgresql://`
   scheme).
3. In the backend service's settings add `DATABASE_URL` with that value.
4. Trigger a deploy. SQLAlchemy + psycopg2 will create the tables on startup.

## Migrating legacy JSON data

Legacy installs stored accounts, bans, admins, and registry data in JSON. Run
the helper script once to import that data into the database.

```bash
cd ca-backend
python -m scripts.migrate_legacy
```

The script:

- imports `app/auth_users.json` into the `accounts` table
- imports `app/users.json` into the `user_registry` table
- imports `app/banned.json`, `app/admins.json`, and `app/admin_blacklist.json`
  into their respective allow/deny tables

It is idempotent (existing rows are skipped) and respects `DATABASE_URL`, so you
can point it at your Render database over a port-forward/tunnel before
switching the production service.
