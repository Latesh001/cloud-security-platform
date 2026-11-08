"""Test Flask API endpoints for /api/auth/register and /api/auth/login."""
import sys
import os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from app import app
from database.extensions import init_mongo
from database.models import User


def test_auth_api_flow():
    with app.app_context():
        if not init_mongo(app):
            print("[SKIP] MongoDB not connected")
            return True

        client = app.test_client()

        test_email = "api_test_user@example.com"
        User.query.filter_by(email=test_email).delete()

        res = client.post("/api/auth/register", json={
            "name": "API Test User",
            "email": test_email,
            "location": "Hyderabad, India",
            "role": "Security Analyst",
        })
        assert res.status_code == 201, f"Registration failed with status {res.status_code}: {res.get_json()}"
        assert res.get_json().get("auto_verified") is True
        print("[PASS] Registration via email returned 201 Created")

        user_db = User.query.filter_by(email=test_email).first()
        assert user_db is not None
        assert user_db.verification_status == "verified"
        assert user_db.role == "Security Analyst"
        assert user_db.country == "Hyderabad, India"
        assert not user_db.phone

        res = client.post("/api/auth/login", json={"email": test_email})
        assert res.status_code == 200, f"Login failed with status {res.status_code}: {res.get_json()}"
        data = res.get_json()
        assert "access_token" in data, "Access token missing from login response"
        print("[PASS] Email-only login returned 200 OK with access token")

        res = client.post("/api/auth/register", json={
            "name": "Phone Attempt",
            "email": test_email,
            "phone": "+19998887777",
            "location": "India",
            "role": "Developer",
        })
        assert res.status_code == 409, f"Duplicate email should be rejected: {res.get_json()}"
        print("[PASS] Duplicate email rejected; phone is not used for registration")

        User.query.filter_by(email=test_email).delete()
        print("[PASS] All Auth API integration tests passed!")
        return True


if __name__ == "__main__":
    test_auth_api_flow()
