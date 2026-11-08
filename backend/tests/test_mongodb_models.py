"""Test MongoDB models and collection persistence."""
import sys
import os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from database.extensions import init_mongo, mongo_available
from database.models import User, Project, SecurityReport, Incident, Notification, ChatHistory
from flask import Flask
from config.settings import Config

app = Flask(__name__)
app.config.from_object(Config)

def test_models():
    with app.app_context():
        if not init_mongo(app):
            print("[SKIP] MongoDB service is not running locally.")
            return True

        # Test User creation & query
        test_email = "test_mongo_user@example.com"
        existing = User.query.filter_by(email=test_email).first()
        if existing:
            existing.delete()

        user = User(
            name="Mongo Test User",
            email=test_email,
            password_hash="hashed_pw_123",
            role="Developer",
        )
        user.save()
        assert user.user_id is not None, "user_id should be auto-incremented"

        found_user = User.query.filter_by(email=test_email).first()
        assert found_user is not None, "User should be found by email"
        assert found_user.name == "Mongo Test User"

        # Test Project creation & relationship
        proj_id = "PRJ-9999"
        existing_proj = Project.query.get(proj_id)
        if existing_proj:
            existing_proj.delete()

        proj = Project(
            project_id=proj_id,
            user_id=found_user.user_id,
            project_name="MongoDB Security App",
            category="Fintech",
            security_score=88.5,
            status="Approved",
        )
        proj.save()

        user_projects = found_user.projects
        assert len(user_projects) >= 1, "User projects relationship should return saved project"
        assert user_projects[0].project_id == proj_id

        # Cleanup test data
        proj.delete()
        user.delete()
        print("[PASS] MongoDB models test passed successfully.")
        return True

if __name__ == "__main__":
    test_models()
