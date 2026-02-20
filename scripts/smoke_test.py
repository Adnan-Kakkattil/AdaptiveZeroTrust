import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from app import create_app


def run_smoke():
    app = create_app(
        {
            "TESTING": True,
            "SECRET_KEY": "smoke-secret",
        }
    )
    client = app.test_client()

    health = client.get("/api/v1/health")
    assert health.status_code == 200, "health failed"

    login = client.post("/api/v1/auth/login", json={"username": "admin", "password": "admin123"})
    assert login.status_code == 200, "login failed"

    tick = client.get("/api/v1/dashboard/tick")
    assert tick.status_code == 200, "dashboard tick failed"

    print("Smoke test passed.")


if __name__ == "__main__":
    run_smoke()
