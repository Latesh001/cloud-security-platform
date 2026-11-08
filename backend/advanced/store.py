"""Mongo helpers and automatic collection/index setup for Advanced Features."""
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from database.extensions import get_next_sequence, mongo_db
from pymongo.errors import PyMongoError

COLLECTIONS = (
    "phase1_analysis", "cloud_assets", "security_logs", "threat_alerts",
    "playbooks", "ioc_database", "compliance_reports", "forensic_reports",
    "vulnerabilities", "asset_inventory", "automation_history",
    "phase_integration", "raw_logs", "normalized_logs", "correlated_events",
    "advanced_chat", "chat_history", "chain_of_custody",
)


def utcnow() -> str:
    return datetime.now(timezone.utc).isoformat()


def available() -> bool:
    return mongo_db is not None


def collection(name: str):
    if mongo_db is None:
        return None
    return mongo_db[name]


def clean(doc: Optional[Dict]) -> Optional[Dict]:
    if not doc:
        return None
    out = dict(doc)
    if "_id" in out:
        out["_id"] = str(out["_id"])
    return out


def ensure_collections() -> None:
    if mongo_db is None:
        return
    try:
        existing = set(mongo_db.list_collection_names())
        for name in COLLECTIONS:
            if name not in existing:
                mongo_db.create_collection(name)
        mongo_db["phase1_analysis"].create_index("project_id")
        mongo_db["phase_integration"].create_index("project_id", unique=True)
        mongo_db["vulnerabilities"].create_index("vuln_id", unique=True)
        mongo_db["asset_inventory"].create_index("asset_id", unique=True)
        mongo_db["ioc_database"].create_index("ioc_id", unique=True)
        mongo_db["playbooks"].create_index("playbook_id", unique=True)
        mongo_db["normalized_logs"].create_index("project_id")
        mongo_db["correlated_events"].create_index("project_id")
        mongo_db["automation_history"].create_index("project_id")
        mongo_db["forensic_reports"].create_index("incident_id")
    except PyMongoError:
        pass


def next_id(name: str, prefix: str) -> str:
    return f"{prefix}-{get_next_sequence(name):04d}"


def insert(name: str, document: Dict[str, Any]) -> Optional[Dict]:
    coll = collection(name)
    payload = dict(document)
    payload.setdefault("created_at", utcnow())
    payload.setdefault("updated_at", payload["created_at"])
    if coll is None:
        return clean(payload)
    try:
        coll.insert_one(payload)
        return clean(payload)
    except PyMongoError:
        return clean(payload)


def find(name: str, query: Dict = None, sort: Optional[List] = None,
         limit: int = 200) -> List[Dict]:
    coll = collection(name)
    if coll is None:
        return []
    try:
        cursor = coll.find(query or {})
        if sort:
            cursor = cursor.sort(sort)
        return [clean(d) for d in cursor.limit(limit)]
    except PyMongoError:
        return []


def find_one(name: str, query: Dict) -> Optional[Dict]:
    coll = collection(name)
    if coll is None:
        return None
    try:
        return clean(coll.find_one(query))
    except PyMongoError:
        return None


def update(name: str, query: Dict, values: Dict) -> Optional[Dict]:
    coll = collection(name)
    if coll is None:
        return None
    payload = dict(values)
    payload["updated_at"] = utcnow()
    try:
        coll.update_one(query, {"$set": payload}, upsert=False)
        return find_one(name, query)
    except PyMongoError:
        return None


def upsert(name: str, query: Dict, values: Dict) -> Optional[Dict]:
    coll = collection(name)
    if coll is None:
        return None
    payload = dict(values)
    payload["updated_at"] = utcnow()
    payload.setdefault("created_at", utcnow())
    try:
        coll.update_one(query, {"$set": payload}, upsert=True)
        return find_one(name, query)
    except PyMongoError:
        return None


def delete(name: str, query: Dict) -> int:
    coll = collection(name)
    if coll is None:
        return 0
    try:
        return coll.delete_one(query).deleted_count
    except PyMongoError:
        return 0


def count(name: str, query: Dict = None) -> int:
    coll = collection(name)
    if coll is None:
        return 0
    try:
        return coll.count_documents(query or {})
    except PyMongoError:
        return 0
