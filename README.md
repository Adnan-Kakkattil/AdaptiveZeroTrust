# Adaptive Zero Trust Access Control System

Phase 1 real application on Flask + SQLite with:

- Secure session authentication with hashed passwords
- Role-based access control (`admin`, `analyst`)
- Continuous telemetry ingestion and policy decisioning
- Deterministic policy engine with persisted reason codes
- Audit event history, filtering, pagination, and CSV export
- Policy editor with server-side validation and policy versioning

## Quick start

1. Create and activate a virtual environment.
2. Install dependencies:

```bash
pip install -r requirements.txt
```

3. Optional environment variables:

```bash
set SECRET_KEY=replace-this
set DB_PATH=data/zero_trust.db
set APP_DEBUG=false
set SESSION_COOKIE_SECURE=false
set MAX_FAILED_LOGINS=5
set LOCKOUT_WINDOW_MINUTES=15
```

4. Start server:

```bash
python app.py
```

5. Open:

```text
http://127.0.0.1:5000
```

## Default users

- Admin: `admin` / `admin123`
- Analyst: `analyst` / `analyst123`

Use these only for local development.

## Create additional users

```bash
flask --app app.py create-user
```

## API (v1)

- `GET /api/v1/health`
- `POST /api/v1/auth/login`
- `POST /api/v1/auth/logout`
- `GET /api/v1/auth/me`
- `GET /api/v1/dashboard/tick`
- `GET /api/v1/policy`
- `PUT /api/v1/policy` (admin only)
- `POST /api/v1/anomalies/inject` (admin only)
- `GET /api/v1/audit/events`
- `GET /api/v1/policy-decisions`
- `GET /api/v1/audit/export.csv`

All JSON endpoints return envelope format:

```json
{
  "data": {},
  "error": null,
  "meta": { "requestId": "..." }
}
```

## Test and smoke check

Run tests:

```bash
python -m unittest discover -s tests
```

Run smoke script:

```bash
python scripts/smoke_test.py
```
