"""Shared Flask extensions and MongoDB access helpers.

MongoDB is the sole, primary database for storing all application data,
relational entities, logs, findings, recommendations, and forensic evidence.
"""
from typing import Any, Dict, List, Optional
from flask_mail import Mail
from flask_jwt_extended import JWTManager
from pymongo import MongoClient, ReturnDocument
from pymongo.errors import PyMongoError

mail = Mail()
jwt = JWTManager()

mongo_client = None
mongo_db = None


def init_mongo(app) -> bool:
    """Connect to MongoDB, returning whether the connection succeeded."""
    global mongo_client, mongo_db
    try:
        mongo_client = MongoClient(
            app.config["MONGO_URI"],
            serverSelectionTimeoutMS=5000,
            connectTimeoutMS=5000,
        )
        mongo_client.admin.command("ping")
        mongo_db = mongo_client.get_default_database()
        app.logger.info("MongoDB connected successfully: %s", mongo_db.name)
        _init_indexes()
        return True
    except PyMongoError as exc:
        mongo_client = None
        mongo_db = None
        app.logger.error("MongoDB connection failed (%s). Unable to start platform.", exc)
        return False


def _init_indexes() -> None:
    """Initialize unique and performance indexes on MongoDB collections."""
    if mongo_db is None:
        return
    try:
        mongo_db["users"].create_index("email", unique=True, sparse=True)
        mongo_db["users"].create_index("phone", unique=True, sparse=True)
        mongo_db["users"].create_index("user_id", unique=True)
        mongo_db["projects"].create_index("project_id", unique=True)
        mongo_db["incidents"].create_index("incident_id", unique=True)
        mongo_db["security_reports"].create_index("report_id", unique=True)
        mongo_db["notifications"].create_index("notification_id", unique=True)
        mongo_db["email_verifications"].create_index("token", unique=True, sparse=True)
    except PyMongoError:
        pass


def mongo_available() -> bool:
    return mongo_db is not None


def get_next_sequence(name: str) -> int:
    """Generate auto-increment integer IDs using MongoDB counters collection."""
    if mongo_db is None:
        return 1
    try:
        doc = mongo_db["counters"].find_one_and_update(
            {"_id": name},
            {"$inc": {"seq": 1}},
            upsert=True,
            return_document=ReturnDocument.AFTER,
        )
        return doc["seq"]
    except PyMongoError:
        return 1


def mongo_insert(collection: str, document: Dict[str, Any]) -> bool:
    if mongo_db is None:
        return False
    try:
        mongo_db[collection].insert_one(document)
        return True
    except PyMongoError:
        return False


def mongo_find_one(collection: str, query: Dict[str, Any],
                   sort: Optional[List] = None) -> Optional[Dict[str, Any]]:
    if mongo_db is None:
        return None
    try:
        document = mongo_db[collection].find_one(query, sort=sort)
    except PyMongoError:
        return None
    if document and "_id" in document:
        document["_id"] = str(document["_id"])
    return document


def mongo_find(collection: str, query: Dict[str, Any],
               sort: Optional[List] = None, limit: int = 50) -> List[Dict[str, Any]]:
    if mongo_db is None:
        return []
    try:
        cursor = mongo_db[collection].find(query)
        if sort:
            cursor = cursor.sort(sort)
        documents = list(cursor.limit(limit))
    except PyMongoError:
        return []
    for document in documents:
        if "_id" in document:
            document["_id"] = str(document["_id"])
    return documents


def mongo_count(collection: str, query: Dict[str, Any]) -> int:
    if mongo_db is None:
        return 0
    try:
        return mongo_db[collection].count_documents(query)
    except PyMongoError:
        return 0


class DummySession:
    """Session compatibility shim for seamless MongoDB operations."""

    def __init__(self):
        self._dirty = set()

    def track(self, instance):
        if hasattr(instance, "save"):
            self._dirty.add(instance)

    def add(self, instance):
        if hasattr(instance, "save"):
            instance.save()
            self._dirty.add(instance)

    def add_all(self, instances):
        for inst in instances:
            self.add(inst)

    def delete(self, instance):
        if hasattr(instance, "delete"):
            instance.delete()
        self._dirty.discard(instance)

    def commit(self):
        for instance in list(self._dirty):
            if hasattr(instance, "save"):
                instance.save()
        self._dirty.clear()

    def rollback(self):
        self._dirty.clear()


class DummyDB:
    """Database compatibility shim wrapping MongoDB operations."""

    def __init__(self):
        self.session = DummySession()

    def init_app(self, app):
        pass

    def create_all(self):
        pass


db = DummyDB()
