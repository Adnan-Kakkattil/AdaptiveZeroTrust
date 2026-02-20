import csv
import io
import random
import sqlite3
from datetime import datetime
from functools import wraps
from pathlib import Path
from typing import Any, Dict, List

from flask import Flask, jsonify, make_response, request, send_from_directory, session


BASE_DIR = Path(__file__).resolve().parent
DB_DIR = BASE_DIR / "data"
DB_PATH = DB_DIR / "zero_trust.db"

app = Flask(__name__)
app.secret_key = "adaptive-zero-trust-demo-secret"

DEFAULT_POLICY = {
    "location_weight": 0.30,
    "device_weight": 0.40,
    "behavior_weight": 0.30,
    "revoke_threshold": 45,
    "step_up_threshold": 68,
}


def get_db_connection() -> sqlite3.Connection:
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def clamp(value: int, min_value: int = 0, max_value: int = 100) -> int:
    return max(min_value, min(max_value, value))


def init_db() -> None:
    DB_DIR.mkdir(parents=True, exist_ok=True)
    with get_db_connection() as conn:
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_code TEXT UNIQUE NOT NULL,
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
            CREATE TABLE IF NOT EXISTS policy_events (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                event_time TEXT NOT NULL,
                severity TEXT NOT NULL,
                event_type TEXT NOT NULL,
                message TEXT NOT NULL,
                user_code TEXT
            )
            """
        )
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS auth_users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT UNIQUE NOT NULL,
                password TEXT NOT NULL,
                role TEXT NOT NULL,
                full_name TEXT NOT NULL
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
        conn.commit()

        existing = conn.execute("SELECT COUNT(*) AS total FROM users").fetchone()["total"]
        if existing == 0:
            seed_users = [
                ("ZT-901", "Sarah Jenkins", "Lead DevOps", "Berlin, DE", "192.168.1.42", "Compliant", 92, 94, "ALLOW", "Prod Kubernetes"),
                ("ZT-902", "Michael Chen", "Product Manager", "San Francisco, US", "10.0.4.11", "Compliant", 83, 88, "ALLOW", "Product Analytics"),
                ("ZT-903", "Alex Rivera", "Senior Security", "Austin, US", "172.16.0.5", "Compliant", 96, 97, "ALLOW", "SIEM Console"),
                ("ZT-904", "Elena Petrova", "Contractor", "Warsaw, PL", "84.12.33.1", "Outdated Patch", 64, 67, "STEP_UP", "Vendor Portal"),
                ("ZT-905", "David Smith", "HR Director", "London, UK", "192.168.1.101", "Compliant", 89, 90, "ALLOW", "HR Records"),
                ("ZT-906", "Nadia Khan", "Finance Analyst", "Dubai, AE", "10.2.9.44", "Compliant", 86, 84, "ALLOW", "Treasury Dashboard"),
            ]
            now = datetime.utcnow().isoformat(timespec="seconds")
            conn.executemany(
                """
                INSERT INTO users (
                    user_code, name, role, location, ip_address, device_posture,
                    behavior_score, trust_score, access_state, protected_asset, last_seen
                )
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                [(*entry, now) for entry in seed_users],
            )

            initial_logs = [
                (now, "INFO", "ENGINE_START", "Adaptive policy engine initialized", None),
                (now, "INFO", "BASELINE", "Continuous verification loop started", None),
            ]
            conn.executemany(
                """
                INSERT INTO policy_events (event_time, severity, event_type, message, user_code)
                VALUES (?, ?, ?, ?, ?)
                """,
                initial_logs,
            )
            conn.commit()

        auth_existing = conn.execute("SELECT COUNT(*) AS total FROM auth_users").fetchone()["total"]
        if auth_existing == 0:
            conn.executemany(
                """
                INSERT INTO auth_users (username, password, role, full_name)
                VALUES (?, ?, ?, ?)
                """,
                [
                    ("admin", "admin123", "admin", "SOC Administrator"),
                    ("analyst", "analyst123", "analyst", "Security Analyst"),
                ],
            )

        config_existing = conn.execute("SELECT COUNT(*) AS total FROM policy_config").fetchone()["total"]
        if config_existing == 0:
            now = datetime.utcnow().isoformat(timespec="seconds")
            conn.executemany(
                """
                INSERT INTO policy_config (config_key, config_value, updated_by, updated_at)
                VALUES (?, ?, ?, ?)
                """,
                [
                    ("location_weight", str(DEFAULT_POLICY["location_weight"]), "system", now),
                    ("device_weight", str(DEFAULT_POLICY["device_weight"]), "system", now),
                    ("behavior_weight", str(DEFAULT_POLICY["behavior_weight"]), "system", now),
                    ("revoke_threshold", str(DEFAULT_POLICY["revoke_threshold"]), "system", now),
                    ("step_up_threshold", str(DEFAULT_POLICY["step_up_threshold"]), "system", now),
                ],
            )
        conn.commit()


def log_event(severity: str, event_type: str, message: str, user_code: str | None = None) -> None:
    now = datetime.utcnow().isoformat(timespec="seconds")
    with get_db_connection() as conn:
        conn.execute(
            """
            INSERT INTO policy_events (event_time, severity, event_type, message, user_code)
            VALUES (?, ?, ?, ?, ?)
            """,
            (now, severity, event_type, message, user_code),
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
                return jsonify({"error": "Authentication required"}), 401
            if roles and identity["role"] not in roles:
                return jsonify({"error": "Insufficient privileges"}), 403
            return func(*args, **kwargs)

        return wrapper

    return decorator


def get_policy_config() -> Dict[str, Any]:
    with get_db_connection() as conn:
        rows = conn.execute(
            """
            SELECT config_key, config_value, updated_by, updated_at
            FROM policy_config
            """
        ).fetchall()

    config_map = {row["config_key"]: row["config_value"] for row in rows}
    location_weight = float(config_map.get("location_weight", DEFAULT_POLICY["location_weight"]))
    device_weight = float(config_map.get("device_weight", DEFAULT_POLICY["device_weight"]))
    behavior_weight = float(config_map.get("behavior_weight", DEFAULT_POLICY["behavior_weight"]))
    total = location_weight + device_weight + behavior_weight
    if total == 0:
        location_weight, device_weight, behavior_weight = (
            DEFAULT_POLICY["location_weight"],
            DEFAULT_POLICY["device_weight"],
            DEFAULT_POLICY["behavior_weight"],
        )
        total = 1.0

    return {
        "locationWeight": round(location_weight / total, 3),
        "deviceWeight": round(device_weight / total, 3),
        "behaviorWeight": round(behavior_weight / total, 3),
        "revokeThreshold": int(float(config_map.get("revoke_threshold", DEFAULT_POLICY["revoke_threshold"]))),
        "stepUpThreshold": int(float(config_map.get("step_up_threshold", DEFAULT_POLICY["step_up_threshold"]))),
    }


def save_policy_config(new_policy: Dict[str, Any], updated_by: str) -> Dict[str, Any]:
    now = datetime.utcnow().isoformat(timespec="seconds")
    with get_db_connection() as conn:
        for key, value in {
            "location_weight": new_policy["locationWeight"],
            "device_weight": new_policy["deviceWeight"],
            "behavior_weight": new_policy["behaviorWeight"],
            "revoke_threshold": new_policy["revokeThreshold"],
            "step_up_threshold": new_policy["stepUpThreshold"],
        }.items():
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
    if "VPN" in location or "Anonymous" in location:
        return 20
    if "Unknown" in location:
        return 25
    return random.randint(70, 95)


def score_device(device_posture: str) -> int:
    mapping = {
        "Compliant": random.randint(85, 98),
        "Outdated Patch": random.randint(45, 68),
        "Jailbroken": random.randint(20, 40),
        "Endpoint Drift": random.randint(35, 60),
    }
    return mapping.get(device_posture, random.randint(50, 75))


def decide_access(trust_score: int, revoke_threshold: int, step_up_threshold: int) -> str:
    if trust_score < revoke_threshold:
        return "REVOKE"
    if trust_score < step_up_threshold:
        return "STEP_UP"
    return "ALLOW"


def recalculate_users() -> Dict[str, int]:
    policy = get_policy_config()
    with get_db_connection() as conn:
        users = conn.execute("SELECT * FROM users ORDER BY id").fetchall()
        now = datetime.utcnow().isoformat(timespec="seconds")
        policy_denials = 0

        for user in users:
            location_component = score_location(user["location"])
            device_component = score_device(user["device_posture"])
            behavioral_component = clamp(user["behavior_score"] + random.randint(-4, 3))
            trust = int(
                (location_component * policy["locationWeight"])
                + (device_component * policy["deviceWeight"])
                + (behavioral_component * policy["behaviorWeight"])
            )
            trust = clamp(trust + random.randint(-2, 2))
            access = decide_access(
                trust,
                policy["revokeThreshold"],
                policy["stepUpThreshold"],
            )
            if access == "REVOKE":
                policy_denials += 1

            conn.execute(
                """
                UPDATE users
                SET behavior_score = ?, trust_score = ?, access_state = ?, last_seen = ?
                WHERE id = ?
                """,
                (behavioral_component, trust, access, now, user["id"]),
            )

            if access in {"STEP_UP", "REVOKE"}:
                severity = "WARN" if access == "STEP_UP" else "CRITICAL"
                msg = (
                    f"{user['name']} flagged by policy engine. "
                    f"Decision={access}, trust_score={trust}"
                )
                conn.execute(
                    """
                    INSERT INTO policy_events (event_time, severity, event_type, message, user_code)
                    VALUES (?, ?, ?, ?, ?)
                    """,
                    (now, severity, "POLICY_DECISION", msg, user["user_code"]),
                )

        conn.commit()
        return {"policy_denials": policy_denials}


def get_dashboard_payload() -> Dict[str, List[Dict[str, str]]]:
    with get_db_connection() as conn:
        users = conn.execute("SELECT * FROM users ORDER BY trust_score ASC").fetchall()
        events = conn.execute(
            """
            SELECT event_time, severity, event_type, message, user_code
            FROM policy_events
            ORDER BY id DESC
            LIMIT 15
            """
        ).fetchall()

    users_json = []
    for row in users:
        users_json.append(
            {
                "userCode": row["user_code"],
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
        )

    events_json = []
    for row in events:
        events_json.append(
            {
                "eventTime": row["event_time"],
                "severity": row["severity"],
                "eventType": row["event_type"],
                "message": row["message"],
                "userCode": row["user_code"],
            }
        )

    if users_json:
        trust_index = round(sum(item["trustScore"] for item in users_json) / len(users_json), 1)
    else:
        trust_index = 0.0

    revoked = sum(1 for item in users_json if item["accessState"] == "REVOKE")
    step_up = sum(1 for item in users_json if item["accessState"] == "STEP_UP")
    allowed = sum(1 for item in users_json if item["accessState"] == "ALLOW")

    return {
        "metrics": {
            "activeIdentities": len(users_json),
            "trustIndex": trust_index,
            "revokedSessions": revoked,
            "stepUpChallenges": step_up,
            "allowedSessions": allowed,
        },
        "users": users_json,
        "events": events_json,
        "policy": get_policy_config(),
    }


@app.route("/")
def home():
    return send_from_directory(BASE_DIR, "index.html")


@app.route("/api/auth/me")
def auth_me():
    identity = current_identity()
    if not identity:
        return jsonify({"authenticated": False}), 200
    return jsonify({"authenticated": True, "user": identity})


@app.route("/api/auth/login", methods=["POST"])
def auth_login():
    body = request.get_json(silent=True) or {}
    username = str(body.get("username", "")).strip()
    password = str(body.get("password", "")).strip()
    if not username or not password:
        return jsonify({"error": "Username and password are required"}), 400

    with get_db_connection() as conn:
        user = conn.execute(
            """
            SELECT username, password, role, full_name
            FROM auth_users
            WHERE username = ?
            """,
            (username,),
        ).fetchone()

    if user is None or user["password"] != password:
        return jsonify({"error": "Invalid credentials"}), 401

    session["username"] = user["username"]
    session["role"] = user["role"]
    session["full_name"] = user["full_name"]
    log_event("INFO", "LOGIN_SUCCESS", f"Operator login: {user['username']}")
    return jsonify({"ok": True, "user": current_identity()})


@app.route("/api/auth/logout", methods=["POST"])
@require_auth()
def auth_logout():
    username = session.get("username", "unknown")
    session.clear()
    log_event("INFO", "LOGOUT", f"Operator logout: {username}")
    return jsonify({"ok": True})


@app.route("/api/tick")
@require_auth(["admin", "analyst"])
def tick():
    recalculate_users()
    return jsonify(get_dashboard_payload())


@app.route("/api/inject-anomaly", methods=["POST"])
@require_auth(["admin"])
def inject_anomaly():
    with get_db_connection() as conn:
        target = conn.execute(
            "SELECT * FROM users WHERE access_state != 'REVOKE' ORDER BY RANDOM() LIMIT 1"
        ).fetchone()
        now = datetime.utcnow().isoformat(timespec="seconds")

        if target is None:
            conn.execute(
                """
                INSERT INTO policy_events (event_time, severity, event_type, message, user_code)
                VALUES (?, ?, ?, ?, ?)
                """,
                (now, "WARN", "NO_TARGET", "No eligible identity available for anomaly injection", None),
            )
            conn.commit()
            return jsonify({"ok": True, "message": "No eligible user to downgrade"}), 200

        compromised_score = random.randint(8, 24)
        compromised_behavior = random.randint(10, 25)
        conn.execute(
            """
            UPDATE users
            SET location = ?, ip_address = ?, device_posture = ?, behavior_score = ?,
                trust_score = ?, access_state = ?, last_seen = ?
            WHERE id = ?
            """,
            (
                "Anonymous VPN Exit Node",
                "Unattributed Source",
                "Endpoint Drift",
                compromised_behavior,
                compromised_score,
                "REVOKE",
                now,
                target["id"],
            ),
        )

        conn.execute(
            """
            INSERT INTO policy_events (event_time, severity, event_type, message, user_code)
            VALUES (?, ?, ?, ?, ?)
            """,
            (
                now,
                "CRITICAL",
                "ANOMALY_INJECTION",
                f"Anomalous pattern injected for {target['name']}. Access automatically revoked.",
                target["user_code"],
            ),
        )
        conn.commit()

    return jsonify({"ok": True, "targetUser": target["name"], "targetCode": target["user_code"]})


@app.route("/api/policy", methods=["GET"])
@require_auth(["admin", "analyst"])
def get_policy():
    return jsonify({"policy": get_policy_config()})


@app.route("/api/policy", methods=["POST"])
@require_auth(["admin"])
def update_policy():
    payload = request.get_json(silent=True) or {}
    required_fields = [
        "locationWeight",
        "deviceWeight",
        "behaviorWeight",
        "revokeThreshold",
        "stepUpThreshold",
    ]
    for field in required_fields:
        if field not in payload:
            return jsonify({"error": f"Missing field: {field}"}), 400

    try:
        updated = {
            "locationWeight": float(payload["locationWeight"]),
            "deviceWeight": float(payload["deviceWeight"]),
            "behaviorWeight": float(payload["behaviorWeight"]),
            "revokeThreshold": int(payload["revokeThreshold"]),
            "stepUpThreshold": int(payload["stepUpThreshold"]),
        }
    except ValueError:
        return jsonify({"error": "Invalid policy values"}), 400

    if min(updated["locationWeight"], updated["deviceWeight"], updated["behaviorWeight"]) < 0:
        return jsonify({"error": "Weights must be non-negative"}), 400
    if not (0 <= updated["revokeThreshold"] <= 100 and 0 <= updated["stepUpThreshold"] <= 100):
        return jsonify({"error": "Thresholds must be between 0 and 100"}), 400
    if updated["revokeThreshold"] >= updated["stepUpThreshold"]:
        return jsonify({"error": "revokeThreshold must be less than stepUpThreshold"}), 400

    new_policy = save_policy_config(updated, session["username"])
    log_event(
        "INFO",
        "POLICY_UPDATED",
        (
            f"Policy updated by {session['username']}: "
            f"weights=({new_policy['locationWeight']},{new_policy['deviceWeight']},{new_policy['behaviorWeight']}), "
            f"thresholds=({new_policy['revokeThreshold']},{new_policy['stepUpThreshold']})"
        ),
    )
    return jsonify({"ok": True, "policy": new_policy})


@app.route("/api/audit/export.csv")
@require_auth(["admin", "analyst"])
def export_audit_csv():
    with get_db_connection() as conn:
        rows = conn.execute(
            """
            SELECT id, event_time, severity, event_type, message, user_code
            FROM policy_events
            ORDER BY id DESC
            LIMIT 200
            """
        ).fetchall()

    out = io.StringIO()
    writer = csv.writer(out)
    writer.writerow(["id", "event_time", "severity", "event_type", "message", "user_code"])
    for row in rows:
        writer.writerow(
            [
                row["id"],
                row["event_time"],
                row["severity"],
                row["event_type"],
                row["message"],
                row["user_code"] or "",
            ]
        )

    response = make_response(out.getvalue())
    response.headers["Content-Type"] = "text/csv; charset=utf-8"
    response.headers["Content-Disposition"] = "attachment; filename=audit-events.csv"
    return response


if __name__ == "__main__":
    init_db()
    app.run(debug=True)
