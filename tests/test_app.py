import tempfile
import unittest
from pathlib import Path

from app import create_app


class ZeroTrustAppTests(unittest.TestCase):
    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        db_path = Path(self.temp_dir.name) / "test.db"
        self.app = create_app(
            {
                "TESTING": True,
                "DB_PATH": str(db_path),
                "SECRET_KEY": "test-secret",
                "SESSION_COOKIE_SECURE": False,
            }
        )
        self.client = self.app.test_client()

    def tearDown(self):
        self.temp_dir.cleanup()

    def login(self, username, password):
        response = self.client.post(
            "/api/v1/auth/login",
            json={"username": username, "password": password},
        )
        return response

    def csrf_headers(self):
        csrf = self.client.get("/api/v1/auth/csrf")
        payload = csrf.get_json()
        return {"X-CSRF-Token": payload["data"]["csrfToken"]}

    def test_health_endpoint(self):
        response = self.client.get("/api/v1/health")
        self.assertEqual(response.status_code, 200)
        payload = response.get_json()
        self.assertEqual(payload["data"]["status"], "ok")
        self.assertTrue(payload["data"]["db"])

    def test_auth_me_unauthenticated(self):
        response = self.client.get("/api/v1/auth/me")
        self.assertEqual(response.status_code, 200)
        payload = response.get_json()
        self.assertFalse(payload["data"]["authenticated"])

    def test_login_and_tick(self):
        login = self.login("admin", "admin123")
        self.assertEqual(login.status_code, 200)

        tick = self.client.get("/api/v1/dashboard/tick")
        self.assertEqual(tick.status_code, 200)
        payload = tick.get_json()
        self.assertIn("metrics", payload["data"])
        self.assertIn("identities", payload["data"])

    def test_analyst_forbidden_for_anomaly_injection(self):
        self.assertEqual(self.login("analyst", "analyst123").status_code, 200)
        response = self.client.post("/api/v1/anomalies/inject", headers=self.csrf_headers())
        self.assertEqual(response.status_code, 403)

    def test_admin_can_update_policy(self):
        self.assertEqual(self.login("admin", "admin123").status_code, 200)
        response = self.client.put(
            "/api/v1/policy",
            headers=self.csrf_headers(),
            json={
                "locationWeight": 0.25,
                "deviceWeight": 0.5,
                "behaviorWeight": 0.25,
                "revokeThreshold": 40,
                "stepUpThreshold": 70,
            },
        )
        self.assertEqual(response.status_code, 200)
        payload = response.get_json()
        self.assertEqual(payload["data"]["policy"]["revokeThreshold"], 40)
        self.assertEqual(payload["data"]["policy"]["stepUpThreshold"], 70)


if __name__ == "__main__":
    unittest.main()
