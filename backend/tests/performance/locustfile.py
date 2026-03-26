"""Locust load test for CipherRadar API baseline (Plan 1.10).

Simulates authenticated users hitting the main dashboard and admin endpoints.
Run:
    cd backend && .venv/bin/locust -f tests/performance/locustfile.py \
        --headless -u 20 -r 5 -t 30s --host http://localhost:8001
"""

from locust import HttpUser, between, task


class CipherRadarUser(HttpUser):
    """Simulated authenticated CipherRadar dashboard user."""

    wait_time = between(1, 3)
    host = "http://localhost:8001"

    def on_start(self) -> None:
        """Login and store JWT token for subsequent requests."""
        response = self.client.post(
            "/api/v1/auth/login",
            json={"email": "admin@cipherradar.local", "password": "password"},
        )
        if response.status_code == 200:
            data = response.json()
            # TokenResponse uses CamelCaseModel -> accessToken in JSON
            token = data.get("accessToken", data.get("access_token", ""))
            self.client.headers.update({"Authorization": f"Bearer {token}"})

    # ------------------------------------------------------------------
    # Portfolio endpoints (dashboard home)
    # ------------------------------------------------------------------

    @task(3)
    def portfolio_summary(self) -> None:
        """GET /api/v1/portfolio/summary — main dashboard card."""
        self.client.get("/api/v1/portfolio/summary")

    @task(2)
    def portfolio_quantum(self) -> None:
        """GET /api/v1/portfolio/quantum — quantum readiness widget."""
        self.client.get("/api/v1/portfolio/quantum")

    @task(1)
    def portfolio_compliance(self) -> None:
        """GET /api/v1/portfolio/compliance — compliance scores widget."""
        self.client.get("/api/v1/portfolio/compliance")

    # ------------------------------------------------------------------
    # Asset inventory
    # ------------------------------------------------------------------

    @task(2)
    def list_assets(self) -> None:
        """GET /api/v1/assets — paginated asset list (page 1, 15 items)."""
        self.client.get("/api/v1/assets?page=1&page_size=15")

    # ------------------------------------------------------------------
    # Admin endpoints (requires org_admin / security_manager role)
    # ------------------------------------------------------------------

    @task(1)
    def admin_users(self) -> None:
        """GET /api/v1/admin/users — org user list."""
        self.client.get("/api/v1/admin/users")

    @task(1)
    def admin_settings(self) -> None:
        """GET /api/v1/admin/settings — org settings."""
        self.client.get("/api/v1/admin/settings")

    # ------------------------------------------------------------------
    # Infrastructure
    # ------------------------------------------------------------------

    @task(1)
    def health_check(self) -> None:
        """GET /api/v1/health — unauthenticated health probe."""
        self.client.get("/api/v1/health")
