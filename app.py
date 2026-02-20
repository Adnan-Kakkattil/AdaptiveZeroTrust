import random
import sqlite3
from datetime import datetime
from pathlib import Path
from typing import Dict, List

from flask import Flask, jsonify, send_from_directory


BASE_DIR = Path(__file__).resolve().parent
DB_DIR = BASE_DIR / "data"
DB_PATH = DB_DIR / "zero_trust.db"

app = Flask(__name__)


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


def decide_access(trust_score: int) -> str:
    if trust_score < 45:
        return "REVOKE"
    if trust_score < 68:
        return "STEP_UP"
    return "ALLOW"


def recalculate_users() -> Dict[str, int]:
    with get_db_connection() as conn:
        users = conn.execute("SELECT * FROM users ORDER BY id").fetchall()
        now = datetime.utcnow().isoformat(timespec="seconds")
        policy_denials = 0

        for user in users:
            location_component = score_location(user["location"])
            device_component = score_device(user["device_posture"])
            behavioral_component = clamp(user["behavior_score"] + random.randint(-4, 3))
            trust = int(
                (location_component * 0.30)
                + (device_component * 0.40)
                + (behavioral_component * 0.30)
            )
            trust = clamp(trust + random.randint(-2, 2))
            access = decide_access(trust)
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
    }


@app.route("/")
def home():
    return send_from_directory(BASE_DIR, "index.html")


@app.route("/api/tick")
def tick():
    recalculate_users()
    return jsonify(get_dashboard_payload())


@app.route("/api/inject-anomaly", methods=["POST"])
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


if __name__ == "__main__":
    init_db()
    app.run(debug=True)
