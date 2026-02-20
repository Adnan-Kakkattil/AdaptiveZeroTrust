import csv
import hashlib
import io
import json
import logging
import os
import random
import re
import shutil
import sqlite3
import time
import uuid
from contextlib import contextmanager
from datetime import datetime, timedelta, timezone
from functools import wraps
from logging.handlers import RotatingFileHandler
from pathlib import Path
from typing import Any, Dict, List, Tuple

from flask import Flask, current_app, g, has_request_context, make_response, request, send_from_directory, session
from dotenv import load_dotenv
from werkzeug.security import check_password_hash, generate_password_hash


BASE_DIR = Path(__file__).resolve().parent
DEFAULT_DB_PATH = BASE_DIR / "data" / "zero_trust.db"
load_dotenv(BASE_DIR / ".env")

DEFAULT_POLICY = {
    "locationWeight": 0.30,
    "deviceWeight": 0.40,
    "behaviorWeight": 0.30,
    "revokeThreshold": 45,
    "stepUpThreshold": 68,
    "version": 1,
}


def now_utc() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def clamp(value: int, min_value: int = 0, max_value: int = 100) -> int:
    return max(min_value, min(max_value, value))


def parse_iso(value: str) -> datetime:
    return datetime.fromisoformat(value)


def validate_password_policy(password: str) -> Tuple[bool, str]:
    if len(password) < 12:
        return False, "Password must be at least 12 characters"
    if not re.search(r"[A-Z]", password):
        return False, "Password must include an uppercase letter"
    if not re.search(r"[a-z]", password):
        return False, "Password must include a lowercase letter"
    if not re.search(r"\d", password):
        return False, "Password must include a digit"
    if not re.search(r"[^\w\s]", password):
        return False, "Password must include a special character"
    return True, ""


def generate_csrf_token() -> str:
    return uuid.uuid4().hex


def is_mutating_request() -> bool:
    return request.method.upper() in {"POST", "PUT", "PATCH", "DELETE"}


def is_csrf_exempt(path: str) -> bool:
    return path in {"/api/v1/auth/login", "/api/v1/auth/csrf", "/api/v1/health"}


def setup_logging(app: Flask) -> None:
    log_dir = Path(app.config["LOG_DIR"])
    log_dir.mkdir(parents=True, exist_ok=True)
    app_file = log_dir / "app.log"
    security_file = log_dir / "security.log"

    class JsonFormatter(logging.Formatter):
        def format(self, record: logging.LogRecord) -> str:
            payload = {
                "timestamp": datetime.now(timezone.utc).isoformat(timespec="seconds"),
                "level": record.levelname,
                "logger": record.name,
                "message": record.getMessage(),
                "requestId": getattr(record, "request_id", "-"),
            }
            return json.dumps(payload)

    class RequestFilter(logging.Filter):
        def filter(self, record: logging.LogRecord) -> bool:
            record.request_id = getattr(g, "request_id", "-") if has_request_context() else "-"
            return True

    formatter = JsonFormatter()

    app_file_handler = RotatingFileHandler(app_file, maxBytes=2_000_000, backupCount=5, encoding="utf-8")
    app_file_handler.setFormatter(formatter)
    app_file_handler.addFilter(RequestFilter())

    security_file_handler = RotatingFileHandler(security_file, maxBytes=2_000_000, backupCount=10, encoding="utf-8")
    security_file_handler.setFormatter(formatter)
    security_file_handler.addFilter(RequestFilter())

    stream_handler = logging.StreamHandler()
    stream_handler.setFormatter(formatter)
    stream_handler.addFilter(RequestFilter())

    for handler in app.logger.handlers:
        handler.close()
    app.logger.handlers.clear()
    app.logger.setLevel(logging.INFO)
    app.logger.addHandler(app_file_handler)
    app.logger.addHandler(stream_handler)

    security_logger = logging.getLogger("security")
    security_logger.handlers.clear()
    security_logger.setLevel(logging.INFO)
    security_logger.addHandler(security_file_handler)
    security_logger.propagate = False


def get_db_connection() -> sqlite3.Connection:
    conn = sqlite3.connect(current_app.config["DB_PATH"])
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA foreign_keys=ON")
    return conn


@contextmanager
def db_conn():
    conn = get_db_connection()
    try:
        yield conn
    finally:
        conn.close()


def success_response(data: Any, meta: Dict[str, Any] | None = None, status: int = 200):
    payload = {
        "data": data,
        "error": None,
        "meta": {"requestId": getattr(g, "request_id", "-")},
    }
    if meta:
        payload["meta"].update(meta)
    return payload, status


def error_response(code: str, message: str, status: int):
    return {
        "data": None,
        "error": {"code": code, "message": message},
        "meta": {"requestId": getattr(g, "request_id", "-")},
    }, status


def init_db() -> None:
    db_path = Path(current_app.config["DB_PATH"])
    db_path.parent.mkdir(parents=True, exist_ok=True)
    with db_conn() as conn:
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS app_users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT UNIQUE NOT NULL,
                password_hash TEXT NOT NULL,
                role TEXT NOT NULL CHECK(role IN ('admin', 'analyst')),
                full_name TEXT NOT NULL,
                is_active INTEGER NOT NULL DEFAULT 1,
                created_at TEXT NOT NULL,
                last_login TEXT,
                password_changed_at TEXT
            )
            """
        )
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS monitored_identities (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                identity_code TEXT UNIQUE NOT NULL,
                name TEXT NOT NULL,
                role TEXT NOT NULL,
                location TEXT NOT NULL,
                ip_address TEXT NOT NULL,
                device_posture TEXT NOT NULL,
                behavior_score INTEGER NOT NULL,
                trust_score INTEGER NOT NULL,
                access_state TEXT NOT NULL,
                protected_asset TEXT NOT NULL,
                last_seen TEXT NOT NULL
            )
            """
        )
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS telemetry_signals (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                identity_code TEXT NOT NULL,
                signal_time TEXT NOT NULL,
                location_score INTEGER NOT NULL,
                device_score INTEGER NOT NULL,
                behavior_score INTEGER NOT NULL,
                context_json TEXT NOT NULL
            )
            """
        )
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS policy_decisions (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                decision_time TEXT NOT NULL,
                identity_code TEXT NOT NULL,
                trust_score INTEGER NOT NULL,
                decision TEXT NOT NULL,
                reason_codes TEXT NOT NULL,
                policy_version INTEGER NOT NULL
            )
            """
        )
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS audit_events (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                event_time TEXT NOT NULL,
                severity TEXT NOT NULL,
                event_type TEXT NOT NULL,
                message TEXT NOT NULL,
                actor_username TEXT,
                identity_code TEXT,
                request_id TEXT
            )
            """
        )
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS policy_config (
                config_key TEXT PRIMARY KEY,
                config_value TEXT NOT NULL,
                updated_by TEXT NOT NULL,
                updated_at TEXT NOT NULL
            )
            """
        )
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS login_attempts (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT NOT NULL,
                ip_address TEXT NOT NULL,
                attempted_at TEXT NOT NULL,
                success INTEGER NOT NULL
            )
            """
        )
        conn.execute("CREATE INDEX IF NOT EXISTS idx_identity_code ON monitored_identities(identity_code)")
        conn.execute("CREATE INDEX IF NOT EXISTS idx_signal_time ON telemetry_signals(signal_time)")
        conn.execute("CREATE INDEX IF NOT EXISTS idx_signal_identity ON telemetry_signals(identity_code)")
        conn.execute("CREATE INDEX IF NOT EXISTS idx_decision_time ON policy_decisions(decision_time)")
        conn.execute("CREATE INDEX IF NOT EXISTS idx_decision_identity ON policy_decisions(identity_code)")
        conn.execute("CREATE INDEX IF NOT EXISTS idx_audit_time ON audit_events(event_time)")
        conn.execute("CREATE INDEX IF NOT EXISTS idx_audit_severity ON audit_events(severity)")
        conn.execute("CREATE INDEX IF NOT EXISTS idx_login_attempts_time ON login_attempts(attempted_at)")
        columns = conn.execute("PRAGMA table_info(app_users)").fetchall()
        existing_columns = {row["name"] for row in columns}
        if "password_changed_at" not in existing_columns:
            conn.execute("ALTER TABLE app_users ADD COLUMN password_changed_at TEXT")
        conn.commit()

        identity_count = conn.execute("SELECT COUNT(*) AS total FROM monitored_identities").fetchone()["total"]
        if identity_count == 0:
            seeds = [
                ("ZT-901", "Sarah Jenkins", "Lead DevOps", "Berlin, DE", "192.168.1.42", "Compliant", 92, 94, "ALLOW", "Prod Kubernetes"),
                ("ZT-902", "Michael Chen", "Product Manager", "San Francisco, US", "10.0.4.11", "Compliant", 83, 88, "ALLOW", "Product Analytics"),
                ("ZT-903", "Alex Rivera", "Senior Security", "Austin, US", "172.16.0.5", "Compliant", 96, 97, "ALLOW", "SIEM Console"),
                ("ZT-904", "Elena Petrova", "Contractor", "Warsaw, PL", "84.12.33.1", "Outdated Patch", 64, 67, "STEP_UP", "Vendor Portal"),
                ("ZT-905", "David Smith", "HR Director", "London, UK", "192.168.1.101", "Compliant", 89, 90, "ALLOW", "HR Records"),
                ("ZT-906", "Nadia Khan", "Finance Analyst", "Dubai, AE", "10.2.9.44", "Compliant", 86, 84, "ALLOW", "Treasury Dashboard"),
            ]
            now = now_utc()
            conn.executemany(
                """
                INSERT INTO monitored_identities (
                    identity_code, name, role, location, ip_address, device_posture,
                    behavior_score, trust_score, access_state, protected_asset, last_seen
                )
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                [(*item, now) for item in seeds],
            )

        user_count = conn.execute("SELECT COUNT(*) AS total FROM app_users").fetchone()["total"]
        if user_count == 0:
            now = now_utc()
            conn.executemany(
                """
                INSERT INTO app_users (username, password_hash, role, full_name, created_at)
                VALUES (?, ?, ?, ?, ?)
                """,
                [
                    ("admin", generate_password_hash("admin123"), "admin", "SOC Administrator", now),
                    ("analyst", generate_password_hash("analyst123"), "analyst", "Security Analyst", now),
                ],
            )

        config_count = conn.execute("SELECT COUNT(*) AS total FROM policy_config").fetchone()["total"]
        if config_count == 0:
            now = now_utc()
            defaults = {
                "location_weight": DEFAULT_POLICY["locationWeight"],
                "device_weight": DEFAULT_POLICY["deviceWeight"],
                "behavior_weight": DEFAULT_POLICY["behaviorWeight"],
                "revoke_threshold": DEFAULT_POLICY["revokeThreshold"],
                "step_up_threshold": DEFAULT_POLICY["stepUpThreshold"],
                "version": DEFAULT_POLICY["version"],
            }
            for key, value in defaults.items():
                conn.execute(
                    """
                    INSERT INTO policy_config (config_key, config_value, updated_by, updated_at)
                    VALUES (?, ?, ?, ?)
                    """,
                    (key, str(value), "system", now),
                )

        conn.commit()


def audit_event(
    severity: str,
    event_type: str,
    message: str,
    actor_username: str | None = None,
    identity_code: str | None = None,
) -> None:
    logging.getLogger("security").info(
        json.dumps(
            {
                "severity": severity,
                "eventType": event_type,
                "message": message,
                "actorUsername": actor_username,
                "identityCode": identity_code,
            }
        )
    )
    with db_conn() as conn:
        conn.execute(
            """
            INSERT INTO audit_events (
                event_time, severity, event_type, message, actor_username, identity_code, request_id
            )
            VALUES (?, ?, ?, ?, ?, ?, ?)
            """,
            (
                now_utc(),
                severity,
                event_type,
                message,
                actor_username,
                identity_code,
                getattr(g, "request_id", None),
            ),
        )
        conn.commit()


def current_identity() -> Dict[str, str] | None:
    if "username" not in session:
        return None
    return {
        "username": session["username"],
        "role": session["role"],
        "fullName": session["full_name"],
    }


def require_auth(roles: List[str] | None = None):
    def decorator(func):
        @wraps(func)
        def wrapper(*args, **kwargs):
            identity = current_identity()
            if not identity:
                return error_response("AUTH_REQUIRED", "Authentication required", 401)
            if roles and identity["role"] not in roles:
                return error_response("FORBIDDEN", "Insufficient privileges", 403)
            return func(*args, **kwargs)

        return wrapper

    return decorator


def get_policy_config() -> Dict[str, Any]:
    with db_conn() as conn:
        rows = conn.execute("SELECT config_key, config_value FROM policy_config").fetchall()
    config = {row["config_key"]: row["config_value"] for row in rows}

    location = float(config.get("location_weight", DEFAULT_POLICY["locationWeight"]))
    device = float(config.get("device_weight", DEFAULT_POLICY["deviceWeight"]))
    behavior = float(config.get("behavior_weight", DEFAULT_POLICY["behaviorWeight"]))
    total = location + device + behavior
    if total <= 0:
        location, device, behavior, total = 0.3, 0.4, 0.3, 1.0

    return {
        "locationWeight": round(location / total, 3),
        "deviceWeight": round(device / total, 3),
        "behaviorWeight": round(behavior / total, 3),
        "revokeThreshold": int(float(config.get("revoke_threshold", DEFAULT_POLICY["revokeThreshold"]))),
        "stepUpThreshold": int(float(config.get("step_up_threshold", DEFAULT_POLICY["stepUpThreshold"]))),
        "version": int(float(config.get("version", DEFAULT_POLICY["version"]))),
    }


def save_policy_config(updated: Dict[str, Any], updated_by: str) -> Dict[str, Any]:
    existing = get_policy_config()
    new_version = existing["version"] + 1
    now = now_utc()
    payload = {
        "location_weight": updated["locationWeight"],
        "device_weight": updated["deviceWeight"],
        "behavior_weight": updated["behaviorWeight"],
        "revoke_threshold": updated["revokeThreshold"],
        "step_up_threshold": updated["stepUpThreshold"],
        "version": new_version,
    }
    with db_conn() as conn:
        for key, value in payload.items():
            conn.execute(
                """
                INSERT INTO policy_config (config_key, config_value, updated_by, updated_at)
                VALUES (?, ?, ?, ?)
                ON CONFLICT(config_key) DO UPDATE SET
                    config_value = excluded.config_value,
                    updated_by = excluded.updated_by,
                    updated_at = excluded.updated_at
                """,
                (key, str(value), updated_by, now),
            )
        conn.commit()
    return get_policy_config()


def score_location(location: str) -> int:
    lowered = location.lower()
    if "anonymous" in lowered or "vpn" in lowered:
        return 20
    if "unknown" in lowered:
        return 30
    return 80


def score_device(posture: str) -> int:
    mapping = {
        "Compliant": 92,
        "Outdated Patch": 58,
        "Endpoint Drift": 38,
        "Jailbroken": 25,
    }
    return mapping.get(posture, 65)


def deterministic_jitter(seed: str, low: int, high: int) -> int:
    digest = hashlib.md5(seed.encode("utf-8")).hexdigest()
    as_int = int(digest[:8], 16)
    return low + (as_int % (high - low + 1))


def evaluate_policy(
    location_score: int,
    device_score: int,
    behavior_score: int,
    policy: Dict[str, Any],
) -> Tuple[int, str, List[str]]:
    trust_score = int(
        (location_score * policy["locationWeight"])
        + (device_score * policy["deviceWeight"])
        + (behavior_score * policy["behaviorWeight"])
    )
    trust_score = clamp(trust_score)

    reasons: List[str] = []
    if location_score < 45:
        reasons.append("LOCATION_ANOMALY")
    if device_score < 50:
        reasons.append("DEVICE_POSTURE_RISK")
    if behavior_score < 55:
        reasons.append("BEHAVIOR_DEVIATION")
    if not reasons:
        reasons.append("BASELINE_OK")

    if trust_score < policy["revokeThreshold"]:
        return trust_score, "REVOKE", reasons
    if trust_score < policy["stepUpThreshold"]:
        return trust_score, "STEP_UP", reasons
    return trust_score, "ALLOW", reasons


def ingest_and_decide() -> None:
    policy = get_policy_config()
    now = now_utc()
    with db_conn() as conn:
        identities = conn.execute("SELECT * FROM monitored_identities ORDER BY id").fetchall()
        for identity in identities:
            jitter_seed = f"{identity['identity_code']}-{now[:16]}"
            behavior = clamp(identity["behavior_score"] + deterministic_jitter(jitter_seed, -4, 4))
            location_score = clamp(score_location(identity["location"]) + deterministic_jitter(jitter_seed + "l", -8, 8))
            device_score = clamp(score_device(identity["device_posture"]) + deterministic_jitter(jitter_seed + "d", -6, 6))
            trust, decision, reasons = evaluate_policy(location_score, device_score, behavior, policy)

            conn.execute(
                """
                INSERT INTO telemetry_signals (
                    identity_code, signal_time, location_score, device_score, behavior_score, context_json
                ) VALUES (?, ?, ?, ?, ?, ?)
                """,
                (
                    identity["identity_code"],
                    now,
                    location_score,
                    device_score,
                    behavior,
                    json.dumps(
                        {
                            "location": identity["location"],
                            "ipAddress": identity["ip_address"],
                            "devicePosture": identity["device_posture"],
                        }
                    ),
                ),
            )
            conn.execute(
                """
                INSERT INTO policy_decisions (
                    decision_time, identity_code, trust_score, decision, reason_codes, policy_version
                ) VALUES (?, ?, ?, ?, ?, ?)
                """,
                (
                    now,
                    identity["identity_code"],
                    trust,
                    decision,
                    json.dumps(reasons),
                    policy["version"],
                ),
            )

            previous = identity["access_state"]
            conn.execute(
                """
                UPDATE monitored_identities
                SET behavior_score = ?, trust_score = ?, access_state = ?, last_seen = ?
                WHERE id = ?
                """,
                (behavior, trust, decision, now, identity["id"]),
            )

            if previous != decision:
                severity = "INFO" if decision == "ALLOW" else "WARN" if decision == "STEP_UP" else "CRITICAL"
                conn.execute(
                    """
                    INSERT INTO audit_events (
                        event_time, severity, event_type, message, actor_username, identity_code, request_id
                    ) VALUES (?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        now,
                        severity,
                        "POLICY_TRANSITION",
                        f"{identity['name']} transitioned from {previous} to {decision}",
                        "policy_engine",
                        identity["identity_code"],
                        getattr(g, "request_id", None),
                    ),
                )
        conn.commit()


def get_dashboard_payload() -> Dict[str, Any]:
    with db_conn() as conn:
        identities = conn.execute(
            "SELECT * FROM monitored_identities ORDER BY trust_score ASC, id ASC"
        ).fetchall()
        events = conn.execute(
            """
            SELECT id, event_time, severity, event_type, message, actor_username, identity_code
            FROM audit_events
            ORDER BY id DESC LIMIT 20
            """
        ).fetchall()

    users = [
        {
            "identityCode": row["identity_code"],
            "name": row["name"],
            "role": row["role"],
            "location": row["location"],
            "ipAddress": row["ip_address"],
            "devicePosture": row["device_posture"],
            "behaviorScore": row["behavior_score"],
            "trustScore": row["trust_score"],
            "accessState": row["access_state"],
            "protectedAsset": row["protected_asset"],
            "lastSeen": row["last_seen"],
        }
        for row in identities
    ]
    if users:
        trust_index = round(sum(user["trustScore"] for user in users) / len(users), 1)
    else:
        trust_index = 0.0

    metrics = {
        "activeIdentities": len(users),
        "trustIndex": trust_index,
        "revokedSessions": sum(1 for u in users if u["accessState"] == "REVOKE"),
        "stepUpChallenges": sum(1 for u in users if u["accessState"] == "STEP_UP"),
        "allowedSessions": sum(1 for u in users if u["accessState"] == "ALLOW"),
    }
    return {
        "metrics": metrics,
        "identities": users,
        "policy": get_policy_config(),
        "events": [
            {
                "id": row["id"],
                "eventTime": row["event_time"],
                "severity": row["severity"],
                "eventType": row["event_type"],
                "message": row["message"],
                "actorUsername": row["actor_username"],
                "identityCode": row["identity_code"],
            }
            for row in events
        ],
    }


def parse_pagination() -> Tuple[int, int]:
    page = max(int(request.args.get("page", 1)), 1)
    page_size = min(max(int(request.args.get("pageSize", 20)), 1), 100)
    return page, page_size


def list_audit_events() -> Dict[str, Any]:
    severity = request.args.get("severity")
    event_type = request.args.get("eventType")
    page, page_size = parse_pagination()
    offset = (page - 1) * page_size
    clauses = []
    params: List[Any] = []
    if severity:
        clauses.append("severity = ?")
        params.append(severity.upper())
    if event_type:
        clauses.append("event_type = ?")
        params.append(event_type)
    where = " WHERE " + " AND ".join(clauses) if clauses else ""
    with db_conn() as conn:
        rows = conn.execute(
            f"""
            SELECT id, event_time, severity, event_type, message, actor_username, identity_code
            FROM audit_events
            {where}
            ORDER BY id DESC
            LIMIT ? OFFSET ?
            """,
            [*params, page_size, offset],
        ).fetchall()
        total = conn.execute(
            f"SELECT COUNT(*) AS total FROM audit_events {where}",
            params,
        ).fetchone()["total"]
    return {
        "items": [
            {
                "id": row["id"],
                "eventTime": row["event_time"],
                "severity": row["severity"],
                "eventType": row["event_type"],
                "message": row["message"],
                "actorUsername": row["actor_username"],
                "identityCode": row["identity_code"],
            }
            for row in rows
        ],
        "page": page,
        "pageSize": page_size,
        "total": total,
    }


def list_policy_decisions() -> Dict[str, Any]:
    decision_filter = request.args.get("decision")
    identity_code = request.args.get("identityCode")
    page, page_size = parse_pagination()
    offset = (page - 1) * page_size

    clauses = []
    params: List[Any] = []
    if decision_filter:
        clauses.append("decision = ?")
        params.append(decision_filter.upper())
    if identity_code:
        clauses.append("identity_code = ?")
        params.append(identity_code)

    where = " WHERE " + " AND ".join(clauses) if clauses else ""
    with db_conn() as conn:
        rows = conn.execute(
            f"""
            SELECT id, decision_time, identity_code, trust_score, decision, reason_codes, policy_version
            FROM policy_decisions
            {where}
            ORDER BY id DESC
            LIMIT ? OFFSET ?
            """,
            [*params, page_size, offset],
        ).fetchall()
        total = conn.execute(
            f"SELECT COUNT(*) AS total FROM policy_decisions {where}",
            params,
        ).fetchone()["total"]

    return {
        "items": [
            {
                "id": row["id"],
                "decisionTime": row["decision_time"],
                "identityCode": row["identity_code"],
                "trustScore": row["trust_score"],
                "decision": row["decision"],
                "reasons": json.loads(row["reason_codes"]),
                "policyVersion": row["policy_version"],
            }
            for row in rows
        ],
        "page": page,
        "pageSize": page_size,
        "total": total,
    }


def should_lockout(username: str, ip_address: str) -> bool:
    window_minutes = int(current_app.config["LOCKOUT_WINDOW_MINUTES"])
    max_fails = int(current_app.config["MAX_FAILED_LOGINS"])
    cutoff = (datetime.now(timezone.utc) - timedelta(minutes=window_minutes)).isoformat(timespec="seconds")
    with db_conn() as conn:
        count = conn.execute(
            """
            SELECT COUNT(*) AS total
            FROM login_attempts
            WHERE attempted_at >= ?
              AND success = 0
              AND (username = ? OR ip_address = ?)
            """,
            (cutoff, username, ip_address),
        ).fetchone()["total"]
    return count >= max_fails


def record_login_attempt(username: str, ip_address: str, success: bool) -> None:
    with db_conn() as conn:
        conn.execute(
            """
            INSERT INTO login_attempts (username, ip_address, attempted_at, success)
            VALUES (?, ?, ?, ?)
            """,
            (username, ip_address, now_utc(), 1 if success else 0),
        )
        conn.commit()


def create_user(username: str, password: str, role: str, full_name: str) -> None:
    valid, message = validate_password_policy(password)
    if not valid:
        raise ValueError(message)
    now = now_utc()
    with db_conn() as conn:
        conn.execute(
            """
            INSERT INTO app_users (username, password_hash, role, full_name, created_at, password_changed_at)
            VALUES (?, ?, ?, ?, ?, ?)
            """,
            (username, generate_password_hash(password), role, full_name, now, now),
        )
        conn.commit()


def create_app(test_config: Dict[str, Any] | None = None) -> Flask:
    app = Flask(__name__)
    app.config.update(
        APP_ENV=os.getenv("APP_ENV", "development"),
        SECRET_KEY=os.getenv("SECRET_KEY", "change-this-in-production"),
        DB_PATH=os.getenv("DB_PATH", str(DEFAULT_DB_PATH)),
        LOG_DIR=os.getenv("LOG_DIR", str(BASE_DIR / "logs")),
        SESSION_COOKIE_HTTPONLY=True,
        SESSION_COOKIE_SAMESITE=os.getenv("SESSION_COOKIE_SAMESITE", "Lax"),
        SESSION_COOKIE_SECURE=os.getenv("SESSION_COOKIE_SECURE", "true").lower() == "true",
        PERMANENT_SESSION_LIFETIME=timedelta(minutes=int(os.getenv("SESSION_TTL_MINUTES", "45"))),
        MAX_FAILED_LOGINS=int(os.getenv("MAX_FAILED_LOGINS", "5")),
        LOCKOUT_WINDOW_MINUTES=int(os.getenv("LOCKOUT_WINDOW_MINUTES", "15")),
        MAX_CONTENT_LENGTH=int(os.getenv("MAX_CONTENT_LENGTH_BYTES", "1048576")),
        MIN_FREE_DISK_BYTES=int(os.getenv("MIN_FREE_DISK_BYTES", "104857600")),
        DEBUG=os.getenv("APP_DEBUG", "false").lower() == "true",
    )
    if test_config:
        app.config.update(test_config)

    app.config["STARTED_AT"] = now_utc()
    if app.config["APP_ENV"] == "production":
        if app.config["SECRET_KEY"] in {"", "change-this-in-production"}:
            raise RuntimeError("SECRET_KEY must be configured in production")
        if app.config["DEBUG"]:
            raise RuntimeError("APP_DEBUG must be false in production")
        if not app.config["SESSION_COOKIE_SECURE"]:
            raise RuntimeError("SESSION_COOKIE_SECURE must be true in production")

    setup_logging(app)

    @app.before_request
    def before_request():
        g.request_id = str(uuid.uuid4())
        g.request_started = time.time()
        if "csrf_token" not in session:
            session["csrf_token"] = generate_csrf_token()
        if is_mutating_request() and not is_csrf_exempt(request.path):
            token = request.headers.get("X-CSRF-Token", "")
            if token != session.get("csrf_token"):
                return error_response("CSRF_FAILED", "Invalid CSRF token", 403)

    @app.after_request
    def after_request(response):
        response.headers["X-Request-Id"] = getattr(g, "request_id", "-")
        response.headers["Cache-Control"] = "no-store"
        if session.get("csrf_token"):
            response.headers["X-CSRF-Token"] = session["csrf_token"]
        duration_ms = int((time.time() - getattr(g, "request_started", time.time())) * 1000)
        app.logger.info(
            json.dumps(
                {
                    "path": request.path,
                    "method": request.method,
                    "status": response.status_code,
                    "durationMs": duration_ms,
                    "actor": session.get("username"),
                }
            )
        )
        return response

    @app.route("/")
    def home():
        return send_from_directory(BASE_DIR, "index.html")

    @app.route("/api/v1/health")
    def health():
        db_ok = True
        write_ok = True
        db_path = Path(app.config["DB_PATH"])
        db_size_bytes = db_path.stat().st_size if db_path.exists() else 0
        free_disk_bytes = shutil.disk_usage(db_path.parent).free if db_path.parent.exists() else 0
        try:
            with db_conn() as conn:
                conn.execute("SELECT 1")
                conn.execute("CREATE TABLE IF NOT EXISTS _healthcheck (id INTEGER PRIMARY KEY, checked_at TEXT NOT NULL)")
                conn.execute("INSERT INTO _healthcheck (checked_at) VALUES (?)", (now_utc(),))
                conn.execute("DELETE FROM _healthcheck WHERE id NOT IN (SELECT id FROM _healthcheck ORDER BY id DESC LIMIT 1)")
                conn.commit()
        except sqlite3.Error:
            db_ok = False
            write_ok = False
        migration_status = "ok" if db_ok else "error"
        status = "ok" if db_ok and write_ok else "degraded"
        return success_response(
            {
                "status": status,
                "db": db_ok,
                "writeCheck": write_ok,
                "migrationStatus": migration_status,
                "dbSizeBytes": db_size_bytes,
                "freeDiskBytes": free_disk_bytes,
                "freeDiskHealthy": free_disk_bytes >= app.config["MIN_FREE_DISK_BYTES"],
            }
        )

    @app.route("/api/v1/auth/csrf")
    def csrf_token():
        if "csrf_token" not in session:
            session["csrf_token"] = generate_csrf_token()
        return success_response({"csrfToken": session["csrf_token"]})

    @app.route("/api/v1/auth/me")
    def auth_me():
        identity = current_identity()
        return success_response(
            {"authenticated": bool(identity), "user": identity},
        )

    @app.route("/api/v1/auth/login", methods=["POST"])
    def auth_login():
        payload = request.get_json(silent=True) or {}
        username = str(payload.get("username", "")).strip()
        password = str(payload.get("password", ""))
        ip_address = request.headers.get("X-Forwarded-For", request.remote_addr or "0.0.0.0")
        if not username or not password:
            return error_response("BAD_REQUEST", "Username and password are required", 400)
        if should_lockout(username, ip_address):
            return error_response("LOCKED_OUT", "Too many failed attempts. Try later.", 429)

        with db_conn() as conn:
            user = conn.execute(
                """
                SELECT username, password_hash, role, full_name, is_active, password_changed_at
                FROM app_users
                WHERE username = ?
                """,
                (username,),
            ).fetchone()
        if user is None or not check_password_hash(user["password_hash"], password):
            record_login_attempt(username, ip_address, False)
            audit_event("WARN", "LOGIN_FAILED", f"Failed login for {username}", actor_username=username)
            return error_response("AUTH_FAILED", "Authentication failed", 401)
        if user["is_active"] != 1:
            audit_event("WARN", "LOGIN_DISABLED_ACCOUNT", f"Disabled account login attempt for {username}", actor_username=username)
            return error_response("AUTH_FAILED", "Authentication failed", 401)

        record_login_attempt(username, ip_address, True)
        session["username"] = user["username"]
        session["role"] = user["role"]
        session["full_name"] = user["full_name"]
        with db_conn() as conn:
            conn.execute(
                "UPDATE app_users SET last_login = ?, password_changed_at = COALESCE(password_changed_at, ?) WHERE username = ?",
                (now_utc(), now_utc(), user["username"]),
            )
            conn.commit()
        audit_event("INFO", "LOGIN_SUCCESS", f"Operator login: {user['username']}", actor_username=user["username"])
        return success_response({"user": current_identity()})

    @app.route("/api/v1/auth/logout", methods=["POST"])
    @require_auth()
    def auth_logout():
        actor = session.get("username")
        session.clear()
        audit_event("INFO", "LOGOUT", f"Operator logout: {actor}", actor_username=actor)
        return success_response({"ok": True})

    @app.route("/api/v1/dashboard/tick")
    @require_auth(["admin", "analyst"])
    def dashboard_tick():
        ingest_and_decide()
        return success_response(get_dashboard_payload())

    @app.route("/api/v1/policy", methods=["GET"])
    @require_auth(["admin", "analyst"])
    def get_policy():
        return success_response({"policy": get_policy_config()})

    @app.route("/api/v1/policy", methods=["PUT"])
    @require_auth(["admin"])
    def update_policy():
        payload = request.get_json(silent=True) or {}
        required = ["locationWeight", "deviceWeight", "behaviorWeight", "revokeThreshold", "stepUpThreshold"]
        missing = [field for field in required if field not in payload]
        if missing:
            return error_response("BAD_REQUEST", f"Missing field(s): {', '.join(missing)}", 400)
        try:
            candidate = {
                "locationWeight": float(payload["locationWeight"]),
                "deviceWeight": float(payload["deviceWeight"]),
                "behaviorWeight": float(payload["behaviorWeight"]),
                "revokeThreshold": int(payload["revokeThreshold"]),
                "stepUpThreshold": int(payload["stepUpThreshold"]),
            }
        except (TypeError, ValueError):
            return error_response("BAD_REQUEST", "Policy values are invalid", 400)

        if min(candidate["locationWeight"], candidate["deviceWeight"], candidate["behaviorWeight"]) < 0:
            return error_response("BAD_REQUEST", "Weights must be non-negative", 400)
        if candidate["revokeThreshold"] >= candidate["stepUpThreshold"]:
            return error_response("BAD_REQUEST", "revokeThreshold must be less than stepUpThreshold", 400)
        if not (0 <= candidate["revokeThreshold"] <= 100 and 0 <= candidate["stepUpThreshold"] <= 100):
            return error_response("BAD_REQUEST", "Thresholds must be in range 0-100", 400)

        updated = save_policy_config(candidate, session["username"])
        audit_event(
            "INFO",
            "POLICY_UPDATED",
            f"Policy updated to version {updated['version']}",
            actor_username=session["username"],
        )
        return success_response({"policy": updated})

    @app.route("/api/v1/anomalies/inject", methods=["POST"])
    @require_auth(["admin"])
    def inject_anomaly():
        with db_conn() as conn:
            target = conn.execute(
                """
                SELECT * FROM monitored_identities
                WHERE access_state != 'REVOKE'
                ORDER BY RANDOM()
                LIMIT 1
                """
            ).fetchone()
            if target is None:
                return success_response({"message": "No eligible identity found"})
            now = now_utc()
            conn.execute(
                """
                UPDATE monitored_identities
                SET location = ?, ip_address = ?, device_posture = ?, behavior_score = ?,
                    trust_score = ?, access_state = ?, last_seen = ?
                WHERE id = ?
                """,
                (
                    "Anonymous VPN Exit Node",
                    "Unattributed Source",
                    "Endpoint Drift",
                    random.randint(8, 20),
                    random.randint(8, 24),
                    "REVOKE",
                    now,
                    target["id"],
                ),
            )
            conn.execute(
                """
                INSERT INTO policy_decisions (
                    decision_time, identity_code, trust_score, decision, reason_codes, policy_version
                ) VALUES (?, ?, ?, ?, ?, ?)
                """,
                (
                    now,
                    target["identity_code"],
                    10,
                    "REVOKE",
                    json.dumps(["INJECTED_ANOMALY"]),
                    get_policy_config()["version"],
                ),
            )
            conn.commit()
        audit_event(
            "CRITICAL",
            "ANOMALY_INJECTED",
            f"Anomaly injected for {target['name']}",
            actor_username=session["username"],
            identity_code=target["identity_code"],
        )
        return success_response({"targetUser": target["name"], "targetCode": target["identity_code"]})

    @app.route("/api/v1/audit/events")
    @require_auth(["admin", "analyst"])
    def get_audit_events():
        return success_response(list_audit_events())

    @app.route("/api/v1/policy-decisions")
    @require_auth(["admin", "analyst"])
    def get_policy_decisions_route():
        return success_response(list_policy_decisions())

    @app.route("/api/v1/audit/export.csv")
    @require_auth(["admin", "analyst"])
    def export_audit_csv():
        history = list_audit_events()
        out = io.StringIO()
        writer = csv.writer(out)
        writer.writerow(["id", "event_time", "severity", "event_type", "message", "actor_username", "identity_code"])
        for row in history["items"]:
            writer.writerow(
                [
                    row["id"],
                    row["eventTime"],
                    row["severity"],
                    row["eventType"],
                    row["message"],
                    row["actorUsername"] or "",
                    row["identityCode"] or "",
                ]
            )
        response = make_response(out.getvalue())
        response.headers["Content-Type"] = "text/csv; charset=utf-8"
        response.headers["Content-Disposition"] = "attachment; filename=audit-events.csv"
        return response

    @app.route("/api/v1/admin/diagnostics")
    @require_auth(["admin"])
    def admin_diagnostics():
        with db_conn() as conn:
            total_identities = conn.execute("SELECT COUNT(*) AS total FROM monitored_identities").fetchone()["total"]
            total_audits = conn.execute("SELECT COUNT(*) AS total FROM audit_events").fetchone()["total"]
            policy = get_policy_config()
        return success_response(
            {
                "appEnv": app.config["APP_ENV"],
                "startedAt": app.config["STARTED_AT"],
                "uptimeSeconds": int((datetime.now(timezone.utc) - parse_iso(app.config["STARTED_AT"])).total_seconds()),
                "dbPath": app.config["DB_PATH"],
                "totalIdentities": total_identities,
                "totalAuditEvents": total_audits,
                "policyVersion": policy["version"],
            }
        )

    @app.cli.command("create-user")
    def create_user_cli():
        username = input("Username: ").strip()
        password = input("Password: ").strip()
        role = input("Role (admin/analyst): ").strip().lower()
        full_name = input("Full name: ").strip() or username
        if role not in {"admin", "analyst"}:
            print("Invalid role.")
            return
        try:
            create_user(username, password, role, full_name)
            print(f"User {username} created.")
        except ValueError as exc:
            print(str(exc))
        except sqlite3.IntegrityError:
            print("Username already exists.")

    with app.app_context():
        init_db()
    return app


app = create_app()


if __name__ == "__main__":
    app.run(debug=app.config["DEBUG"])
