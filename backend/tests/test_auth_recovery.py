"""Test Auth recovery fixes for MongoQuery delete, desc sorting, $or filters, and sparse index persistence."""
import sys
import os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from database.extensions import init_mongo
from database.models import User, OTPRecord, ChatHistory
from flask import Flask
from config.settings import Config

app = Flask(__name__)
app.config.from_object(Config)


def test_auth_and_query_recovery():
    with app.app_context():
        if not init_mongo(app):
            print("[SKIP] MongoDB service is not running locally.")
            return True

        # 1. Test MongoQuery.delete() on OTPRecord
        identifier = "test_auth_fix@example.com"
        purpose = "registration"

        # Cleanup existing test OTPs
        deleted_count = OTPRecord.query.filter_by(identifier=identifier, purpose=purpose).delete()
        print(f"[PASS] Cleaned up {deleted_count} old test OTP records using MongoQuery.delete()")

        # Create OTP records
        otp1 = OTPRecord(identifier=identifier, otp_code="111111", purpose=purpose, verified=False)
        otp1.save()

        otp2 = OTPRecord(identifier=identifier, otp_code="222222", purpose=purpose, verified=False)
        otp2.save()

        found_otps = OTPRecord.query.filter_by(identifier=identifier, purpose=purpose).all()
        assert len(found_otps) == 2, "Should find 2 saved OTP records"

        # Test .desc() ordering
        latest_otp = OTPRecord.query.filter_by(identifier=identifier, purpose=purpose).order_by(
            OTPRecord.created_date.desc()
        ).first()
        assert latest_otp is not None, "Latest OTP should be found"

        # Test bulk delete method on MongoQuery
        del_count = OTPRecord.query.filter_by(identifier=identifier, purpose=purpose, verified=False).delete()
        assert del_count == 2, f"Expected 2 deleted OTP records, got {del_count}"
        assert OTPRecord.query.filter_by(identifier=identifier, purpose=purpose).count() == 0

        # 2. Test User creation without phone (sparse unique index test)
        u1_email = "sparse_user1@example.com"
        u2_email = "sparse_user2@example.com"
        User.query.filter_by(email=u1_email).delete()
        User.query.filter_by(email=u2_email).delete()

        user1 = User(name="Sparse User 1", email=u1_email, password_hash="hash1")
        user1.save()
        user2 = User(name="Sparse User 2", email=u2_email, password_hash="hash2")
        user2.save()
        print("[PASS] Saved multiple users without phone numbers without DuplicateKeyError on null sparse index")

        # 3. Test $or filter logic: (User.email == x) | (User.phone == x)
        found_u1 = User.query.filter((User.email == u1_email) | (User.phone == u1_email)).first()
        assert found_u1 is not None and found_u1.email == u1_email, "User 1 should be matched by $or query"

        # Clean up test users
        user1.delete()
        user2.delete()
        print("[PASS] All Auth recovery checks passed successfully.")
        return True


if __name__ == "__main__":
    test_auth_and_query_recovery()
