from datetime import datetime, timezone
from database import extensions


def utcnow():
    return datetime.now(timezone.utc)


class MongoInFilter:
    def __init__(self, field: str, values: list):
        self.field = field
        self.values = values


class MongoSortSpec:
    def __init__(self, field: str, direction: int = 1):
        self.field = field
        self.direction = direction


class MongoQueryFilter(dict):
    def __or__(self, other):
        left_or = self.get("$or")
        if isinstance(other, MongoQueryFilter):
            right_or = other.get("$or")
            right_dict = dict(other)
        elif isinstance(other, dict):
            right_or = other.get("$or")
            right_dict = other
        else:
            return NotImplemented

        conditions = []
        if left_or:
            conditions.extend(left_or)
        else:
            conditions.append(dict(self))

        if right_or:
            conditions.extend(right_or)
        else:
            conditions.append(right_dict)

        return MongoQueryFilter({"$or": conditions})

    def __ror__(self, other):
        return self.__or__(other)


class FieldProperty:
    def __init__(self, name: str):
        self.name = name

    def __get__(self, instance, owner):
        if instance is not None:
            return instance._data.get(self.name)
        return self

    def __set__(self, instance, value):
        if instance is not None:
            instance._data[self.name] = value

    def in_(self, values):
        return MongoInFilter(self.name, list(values))

    def desc(self):
        return MongoSortSpec(self.name, -1)

    def asc(self):
        return MongoSortSpec(self.name, 1)

    def __eq__(self, other):
        return MongoQueryFilter({self.name: other})

    def __ne__(self, other):
        return MongoQueryFilter({self.name: {"$ne": other}})


class classproperty:
    def __init__(self, fget):
        self.fget = fget

    def __get__(self, instance, owner):
        return self.fget(owner)


class MongoQuery:
    def __init__(self, model_cls):
        self.model_cls = model_cls
        self.raw_query = {}
        self.sort_spec = None
        self.limit_val = None

    def filter_by(self, **kwargs):
        new_q = MongoQuery(self.model_cls)
        new_q.raw_query = dict(self.raw_query)
        for key, value in kwargs.items():
            if key == "user_id" and isinstance(value, int):
                new_q.raw_query[key] = {"$in": [value, str(value)]}
            elif key == "user_id" and isinstance(value, str) and value.isdigit():
                new_q.raw_query[key] = {"$in": [value, int(value)]}
            else:
                new_q.raw_query[key] = value
        new_q.sort_spec = self.sort_spec
        new_q.limit_val = self.limit_val
        return new_q

    def filter(self, *args, **kwargs):
        new_q = MongoQuery(self.model_cls)
        new_q.raw_query = dict(self.raw_query)
        for arg in args:
            if isinstance(arg, MongoInFilter):
                new_q.raw_query[arg.field] = {"$in": arg.values}
            elif isinstance(arg, dict):
                new_q.raw_query.update(arg)
        new_q.raw_query.update(kwargs)
        new_q.sort_spec = self.sort_spec
        new_q.limit_val = self.limit_val
        return new_q

    def get(self, id_val):
        if id_val is None or extensions.mongo_db is None:
            return None
        pk_field = self.model_cls._pk_field
        coll = extensions.mongo_db[self.model_cls._collection]

        doc = coll.find_one({pk_field: id_val})
        if not doc and isinstance(id_val, str) and id_val.isdigit():
            doc = coll.find_one({pk_field: int(id_val)})
        elif not doc and isinstance(id_val, int):
            doc = coll.find_one({pk_field: str(id_val)})

        return self.model_cls.from_dict(doc) if doc else None

    def first(self):
        if extensions.mongo_db is None:
            return None
        cursor = extensions.mongo_db[self.model_cls._collection].find(self.raw_query)
        if self.sort_spec:
            cursor = cursor.sort(self.sort_spec)
        docs = list(cursor.limit(1))
        return self.model_cls.from_dict(docs[0]) if docs else None

    def all(self):
        if extensions.mongo_db is None:
            return []
        cursor = extensions.mongo_db[self.model_cls._collection].find(self.raw_query)
        if self.sort_spec:
            cursor = cursor.sort(self.sort_spec)
        if self.limit_val:
            cursor = cursor.limit(self.limit_val)
        return [self.model_cls.from_dict(d) for d in cursor]

    def order_by(self, *fields):
        new_q = MongoQuery(self.model_cls)
        new_q.raw_query = dict(self.raw_query)
        sort_specs = []
        for field in fields:
            if isinstance(field, MongoSortSpec):
                sort_specs.append((field.field, field.direction))
            elif isinstance(field, FieldProperty):
                sort_specs.append((field.name, 1))
            elif isinstance(field, str):
                sort_dir = 1
                if field.startswith("-"):
                    field = field[1:]
                    sort_dir = -1
                sort_specs.append((field, sort_dir))
            elif hasattr(field, "name"):
                sort_specs.append((field.name, -1 if getattr(field, "is_desc", False) else 1))
        new_q.sort_spec = sort_specs if sort_specs else self.sort_spec
        new_q.limit_val = self.limit_val
        return new_q

    def limit(self, val: int):
        new_q = MongoQuery(self.model_cls)
        new_q.raw_query = dict(self.raw_query)
        new_q.sort_spec = self.sort_spec
        new_q.limit_val = val
        return new_q

    def count(self) -> int:
        if extensions.mongo_db is None:
            return 0
        return extensions.mongo_db[self.model_cls._collection].count_documents(self.raw_query)

    def delete(self) -> int:
        if extensions.mongo_db is None:
            return 0
        res = extensions.mongo_db[self.model_cls._collection].delete_many(self.raw_query)
        return res.deleted_count


class BaseMongoModel:
    _collection = ""
    _pk_field = "id"
    _auto_increment_pk = True
    _field_defaults = {}

    def __init_subclass__(cls, **kwargs):
        super().__init_subclass__(**kwargs)
        for key in getattr(cls, "_field_defaults", {}):
            if not hasattr(cls, key):
                setattr(cls, key, FieldProperty(key))

    def __init__(self, **kwargs):
        self._data = {}
        for k, default_val in self._field_defaults.items():
            if callable(default_val):
                self._data[k] = default_val()
            else:
                self._data[k] = default_val

        for k, v in kwargs.items():
            self._data[k] = v

    def __getattr__(self, name):
        if name in ("_data", "_collection", "_pk_field", "_auto_increment_pk", "_field_defaults"):
            return super().__getattribute__(name)
        if name in self._data:
            return self._data[name]
        if name in self._field_defaults:
            default_val = self._field_defaults[name]
            return default_val() if callable(default_val) else default_val
        raise AttributeError(f"'{self.__class__.__name__}' object has no attribute '{name}'")

    def __setattr__(self, name, value):
        if name in ("_data", "_collection", "_pk_field", "_auto_increment_pk", "_field_defaults"):
            super().__setattr__(name, value)
        else:
            if not hasattr(self, "_data"):
                super().__setattr__("_data", {})
            self._data[name] = value
            if hasattr(extensions, "db") and hasattr(extensions.db, "session"):
                extensions.db.session.track(self)

    @classmethod
    def from_dict(cls, doc: dict):
        if not doc:
            return None
        data = dict(doc)
        data.pop("_id", None)
        obj = cls(**data)
        return obj

    @classproperty
    def query(cls):
        return MongoQuery(cls)

    def save(self):
        if extensions.mongo_db is None:
            return self

        pk_val = self._data.get(self._pk_field)
        if self._auto_increment_pk and pk_val is None:
            pk_val = extensions.get_next_sequence(self._collection)
            self._data[self._pk_field] = pk_val

        if pk_val is None:
            raise ValueError(f"Primary key '{self._pk_field}' missing for model {self.__class__.__name__}")

        doc = {k: v for k, v in self._data.items() if v is not None}
        extensions.mongo_db[self._collection].replace_one({self._pk_field: pk_val}, doc, upsert=True)
        return self

    def delete(self):
        if extensions.mongo_db is None:
            return
        pk_val = self._data.get(self._pk_field)
        if pk_val is not None:
            extensions.mongo_db[self._collection].delete_one({self._pk_field: pk_val})


class User(BaseMongoModel):
    _collection = "users"
    _pk_field = "user_id"
    _auto_increment_pk = True

    _field_defaults = {
        "user_id": None,
        "name": "",
        "email": None,
        "phone": None,
        "password_hash": "",
        "country": "",
        "state": "",
        "organization": "",
        "profession": "",
        "role": "Developer",
        "mfa_enabled": False,
        "verification_status": "pending",
        "is_active": True,
        "created_date": utcnow,
    }

    user_id = FieldProperty("user_id")
    email = FieldProperty("email")
    phone = FieldProperty("phone")

    @property
    def projects(self):
        return Project.query.filter_by(user_id=self._data.get("user_id")).all()

    @property
    def notifications(self):
        return Notification.query.filter_by(user_id=self._data.get("user_id")).all()

    @property
    def chat_history(self):
        return ChatHistory.query.filter_by(user_id=self._data.get("user_id")).all()


class Project(BaseMongoModel):
    _collection = "projects"
    _pk_field = "project_id"
    _auto_increment_pk = False

    _field_defaults = {
        "project_id": None,
        "user_id": None,
        "project_name": "",
        "description": "",
        "category": "General Software",
        "programming_language": "",
        "framework": "",
        "version": "1.0.0",
        "cloud_provider": "AWS",
        "security_score": 0.0,
        "status": "Created",
        "monitoring_enabled": False,
        "upload_path": "",
        "created_date": utcnow,
    }

    project_id = FieldProperty("project_id")
    user_id = FieldProperty("user_id")

    @property
    def owner(self):
        return User.query.get(self._data.get("user_id"))

    @property
    def reports(self):
        return SecurityReport.query.filter_by(project_id=self._data.get("project_id")).all()

    @property
    def incidents(self):
        return Incident.query.filter_by(project_id=self._data.get("project_id")).all()

    @property
    def monitoring(self):
        return ProjectMonitoring.query.filter_by(project_id=self._data.get("project_id")).first()


class SecurityReport(BaseMongoModel):
    _collection = "security_reports"
    _pk_field = "report_id"
    _auto_increment_pk = True

    _field_defaults = {
        "report_id": None,
        "project_id": None,
        "critical": 0,
        "high": 0,
        "medium": 0,
        "low": 0,
        "score": 0.0,
        "risk_level": "Low",
        "recommendation": "",
        "approval_status": "Pending",
        "report_path": "",
        "created_date": utcnow,
    }

    report_id = FieldProperty("report_id")
    project_id = FieldProperty("project_id")

    @property
    def project(self):
        return Project.query.get(self._data.get("project_id"))


class Notification(BaseMongoModel):
    _collection = "notifications"
    _pk_field = "notification_id"
    _auto_increment_pk = True

    _field_defaults = {
        "notification_id": None,
        "user_id": None,
        "title": "",
        "message": "",
        "read_status": False,
        "created_date": utcnow,
    }

    notification_id = FieldProperty("notification_id")
    user_id = FieldProperty("user_id")

    @property
    def user(self):
        return User.query.get(self._data.get("user_id"))


class Incident(BaseMongoModel):
    _collection = "incidents"
    _pk_field = "incident_id"
    _auto_increment_pk = False

    _field_defaults = {
        "incident_id": None,
        "project_id": None,
        "threat": "",
        "severity": "Medium",
        "confidence": 0.0,
        "affected_user": "",
        "source_ip": "",
        "status": "Open",
        "created_time": utcnow,
        "resolved_time": None,
    }

    incident_id = FieldProperty("incident_id")
    project_id = FieldProperty("project_id")

    @property
    def project(self):
        return Project.query.get(self._data.get("project_id"))

    @property
    def responses(self):
        return Response.query.filter_by(incident_id=self._data.get("incident_id")).all()


class Response(BaseMongoModel):
    _collection = "responses"
    _pk_field = "response_id"
    _auto_increment_pk = True

    _field_defaults = {
        "response_id": None,
        "incident_id": None,
        "action": "",
        "result": "",
        "executed_time": utcnow,
    }

    response_id = FieldProperty("response_id")
    incident_id = FieldProperty("incident_id")

    @property
    def incident(self):
        return Incident.query.get(self._data.get("incident_id"))


class ProjectMonitoring(BaseMongoModel):
    _collection = "project_monitoring"
    _pk_field = "id"
    _auto_increment_pk = True

    _field_defaults = {
        "id": None,
        "project_id": None,
        "monitoring_enabled": False,
        "current_state": "Stopped",
        "total_logs": 0,
        "total_threats": 0,
        "last_updated": utcnow,
    }

    id = FieldProperty("id")
    project_id = FieldProperty("project_id")

    @property
    def project(self):
        return Project.query.get(self._data.get("project_id"))


class ThreatSummary(BaseMongoModel):
    _collection = "threat_summary"
    _pk_field = "id"
    _auto_increment_pk = True

    _field_defaults = {
        "id": None,
        "project_id": None,
        "threat_type": "",
        "severity": "Medium",
        "confidence": 0.0,
        "status": "Observation",
        "created_date": utcnow,
    }

    id = FieldProperty("id")
    project_id = FieldProperty("project_id")


class ChatHistory(BaseMongoModel):
    _collection = "chat_history"
    _pk_field = "chat_id"
    _auto_increment_pk = True

    _field_defaults = {
        "chat_id": None,
        "user_id": None,
        "project_id": None,
        "question": "",
        "answer": "",
        "category": "General",
        "created_date": utcnow,
    }

    chat_id = FieldProperty("chat_id")
    user_id = FieldProperty("user_id")

    @property
    def user(self):
        return User.query.get(self._data.get("user_id"))


class OTPRecord(BaseMongoModel):
    _collection = "otp_records"
    _pk_field = "id"
    _auto_increment_pk = True

    _field_defaults = {
        "id": None,
        "identifier": "",
        "otp_code": "",
        "purpose": "",
        "attempts": 0,
        "expires_at": utcnow,
        "verified": False,
        "created_date": utcnow,
    }

    id = FieldProperty("id")
    identifier = FieldProperty("identifier")


class EmailVerification(BaseMongoModel):
    _collection = "email_verifications"
    _pk_field = "id"
    _auto_increment_pk = True

    _field_defaults = {
        "id": None,
        "user_id": None,
        "token": "",
        "expires_at": utcnow,
        "used": False,
    }

    id = FieldProperty("id")
    user_id = FieldProperty("user_id")
    token = FieldProperty("token")
