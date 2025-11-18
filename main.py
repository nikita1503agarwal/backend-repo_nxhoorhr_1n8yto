import os
from datetime import datetime, timezone
from typing import List, Optional

from fastapi import FastAPI, HTTPException, Depends
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, EmailStr
from bson import ObjectId

from database import db, create_document, get_documents

app = FastAPI()

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Utilities
class ObjectIdStr(str):
    @classmethod
    def __get_validators__(cls):
        yield cls.validate

    @classmethod
    def validate(cls, v):
        try:
            return str(ObjectId(str(v)))
        except Exception:
            raise ValueError("Invalid ObjectId")

# Request models
class RegisterRequest(BaseModel):
    name: str
    email: EmailStr
    password: str
    role: str  # student | teacher

class LoginRequest(BaseModel):
    email: EmailStr
    password: str

class CreateTaskRequest(BaseModel):
    title: str
    description: Optional[str] = None
    due_date: datetime
    audience: str = "all_students" # or "specific"
    audience_ids: Optional[List[str]] = None

class CreateEventRequest(BaseModel):
    title: str
    description: Optional[str] = None
    start_time: datetime
    end_time: datetime
    audience: str = "all_students"
    audience_ids: Optional[List[str]] = None

# Very light auth (token per user) for demo
from hashlib import sha256

def hash_password(raw: str) -> str:
    return sha256(raw.encode()).hexdigest()

def make_token(email: str) -> str:
    base = f"{email}:{datetime.now(timezone.utc).timestamp()}"
    return sha256(base.encode()).hexdigest()

# Auth dependencies (simple)
class AuthedUser(BaseModel):
    id: str
    name: str
    email: EmailStr
    role: str
    is_verified: bool

async def get_user_from_token(token: str = None) -> Optional[AuthedUser]:
    from fastapi import Request
    # token provided via header X-Auth-Token
    from fastapi import Header
    return None

async def get_current_user(x_auth_token: Optional[str] = None, x_user_id: Optional[str] = None):
    from fastapi import Header
    token = x_auth_token
    user_id = x_user_id
    if not token or not user_id:
        raise HTTPException(status_code=401, detail="Missing auth headers")
    user = db.user.find_one({"_id": ObjectId(user_id)})
    if not user:
        raise HTTPException(status_code=401, detail="Invalid user")
    session = db.session.find_one({"user_id": user_id, "token": token})
    if not session:
        raise HTTPException(status_code=401, detail="Invalid session")
    return AuthedUser(
        id=str(user["_id"]),
        name=user.get("name"),
        email=user.get("email"),
        role=user.get("role", "student"),
        is_verified=user.get("is_verified", True)
    )

@app.get("/")
def root():
    return {"message": "Classroom Scheduler API"}

@app.get("/schema")
def get_schema():
    # Minimal schema export so the platform can inspect collections
    from schemas import User, Session, Event, Task, Notification
    return {
        "user": User.model_json_schema(),
        "session": Session.model_json_schema(),
        "event": Event.model_json_schema(),
        "task": Task.model_json_schema(),
        "notification": Notification.model_json_schema(),
    }

@app.post("/auth/register")
def register(req: RegisterRequest):
    role = req.role if req.role in ["student", "teacher"] else "student"
    existing = db.user.find_one({"email": req.email})
    if existing:
        raise HTTPException(400, "Email already registered")
    is_verified = True if role == "student" else False
    user_id = create_document("user", {
        "name": req.name,
        "email": req.email,
        "password_hash": hash_password(req.password),
        "role": role,
        "is_verified": is_verified,
        "is_active": True
    })
    return {"user_id": user_id, "requires_admin_verification": role == "teacher"}

@app.post("/auth/login")
def login(req: LoginRequest):
    user = db.user.find_one({"email": req.email})
    if not user or user.get("password_hash") != hash_password(req.password):
        raise HTTPException(401, "Invalid email or password")
    if user.get("role") == "teacher" and not user.get("is_verified", False):
        raise HTTPException(403, "Teacher account pending admin verification")
    token = make_token(req.email)
    create_document("session", {"user_id": str(user["_id"]), "token": token})
    return {"token": token, "user": {"id": str(user["_id"]), "name": user.get("name"), "email": user.get("email"), "role": user.get("role")}}

# Admin verifies teacher
class VerifyTeacherRequest(BaseModel):
    user_id: str

@app.post("/admin/verify-teacher")
def verify_teacher(req: VerifyTeacherRequest, current=Depends(get_current_user)):
    if current.role != "admin":
        raise HTTPException(403, "Admin only")
    res = db.user.update_one({"_id": ObjectId(req.user_id), "role": "teacher"}, {"$set": {"is_verified": True, "updated_at": datetime.now(timezone.utc)}})
    if res.matched_count == 0:
        raise HTTPException(404, "Teacher not found")
    return {"status": "ok"}

# Teacher creates tasks and events
@app.post("/tasks")
def create_task(req: CreateTaskRequest, current=Depends(get_current_user)):
    if current.role != "teacher":
        raise HTTPException(403, "Only teachers can create tasks")
    if not current.is_verified:
        raise HTTPException(403, "Teacher account not verified")
    data = {
        "title": req.title,
        "description": req.description,
        "due_date": req.due_date,
        "created_by": current.id,
        "audience": req.audience,
        "audience_ids": req.audience_ids or [],
        "notified": False,
    }
    task_id = create_document("task", data)
    return {"task_id": task_id}

@app.post("/events")
def create_event(req: CreateEventRequest, current=Depends(get_current_user)):
    if current.role != "teacher":
        raise HTTPException(403, "Only teachers can create events")
    if not current.is_verified:
        raise HTTPException(403, "Teacher account not verified")
    data = {
        "title": req.title,
        "description": req.description,
        "start_time": req.start_time,
        "end_time": req.end_time,
        "created_by": current.id,
        "audience": req.audience,
        "audience_ids": req.audience_ids or [],
    }
    event_id = create_document("event", data)
    return {"event_id": event_id}

# Listing for students
@app.get("/my/tasks")
def my_tasks(current=Depends(get_current_user)):
    if current.role == "teacher":
        # teacher sees tasks they created
        tasks = get_documents("task", {"created_by": current.id})
    else:
        # student sees tasks for all or specific including them
        tasks = db.task.find({
            "$or": [
                {"audience": "all_students"},
                {"audience": "specific", "audience_ids": {"$in": [current.id]}}
            ]
        }).sort("due_date", 1)
    # convert ObjectId
    out = []
    for t in tasks:
        t["id"] = str(t.pop("_id"))
        out.append(t)
    return out

@app.get("/my/events")
def my_events(current=Depends(get_current_user)):
    if current.role == "teacher":
        events = get_documents("event", {"created_by": current.id})
    else:
        events = db.event.find({
            "$or": [
                {"audience": "all_students"},
                {"audience": "specific", "audience_ids": {"$in": [current.id]}}
            ]
        }).sort("start_time", 1)
    out = []
    for e in events:
        e["id"] = str(e.pop("_id"))
        out.append(e)
    return out

# Notifications: a simple sweep endpoint to generate overdue notifications
@app.post("/cron/generate-deadline-notifs")
def cron_generate_deadline_notifications():
    now = datetime.now(timezone.utc)
    overdue = db.task.find({"due_date": {"$lte": now}, "notified": False})
    created = 0
    for task in overdue:
        # audience all students -> notify every student
        if task.get("audience") == "all_students":
            # notify all students in DB
            for user in db.user.find({"role": "student", "is_active": True}):
                create_document("notification", {
                    "user_id": str(user["_id"]),
                    "title": f"Deadline reached: {task.get('title')}",
                    "message": f"The task '{task.get('title')}' is now due.",
                    "kind": "deadline",
                    "related_type": "task",
                    "related_id": str(task["_id"])
                })
                created += 1
        else:
            for uid in task.get("audience_ids", []):
                create_document("notification", {
                    "user_id": uid,
                    "title": f"Deadline reached: {task.get('title')}",
                    "message": f"The task '{task.get('title')}' is now due.",
                    "kind": "deadline",
                    "related_type": "task",
                    "related_id": str(task["_id"])
                })
                created += 1
        # mark task as notified
        db.task.update_one({"_id": task["_id"]}, {"$set": {"notified": True, "updated_at": now}})
    return {"notifications_created": created}

@app.get("/my/notifications")
def my_notifications(current=Depends(get_current_user)):
    notifs = db.notification.find({"user_id": current.id}).sort("created_at", -1)
    out = []
    for n in notifs:
        n["id"] = str(n.pop("_id"))
        out.append(n)
    return out

# Simple headers doc
@app.get("/auth/headers")
def auth_headers_note():
    return {"note": "Send X-Auth-Token and X-User-Id headers with requests after login."}

@app.get("/test")
def test_database():
    response = {
        "backend": "✅ Running",
        "database": "❌ Not Available",
        "database_url": None,
        "database_name": None,
        "connection_status": "Not Connected",
        "collections": []
    }
    try:
        if db is not None:
            response["database"] = "✅ Available"
            response["database_url"] = "✅ Configured"
            response["database_name"] = db.name if hasattr(db, 'name') else "✅ Connected"
            response["connection_status"] = "Connected"
            try:
                collections = db.list_collection_names()
                response["collections"] = collections[:10]
                response["database"] = "✅ Connected & Working"
            except Exception as e:
                response["database"] = f"⚠️  Connected but Error: {str(e)[:50]}"
        else:
            response["database"] = "⚠️  Available but not initialized"
    except Exception as e:
        response["database"] = f"❌ Error: {str(e)[:50]}"
    import os as _os
    response["database_url"] = "✅ Set" if _os.getenv("DATABASE_URL") else "❌ Not Set"
    response["database_name"] = "✅ Set" if _os.getenv("DATABASE_NAME") else "❌ Not Set"
    return response

if __name__ == "__main__":
    import uvicorn
    port = int(os.getenv("PORT", 8000))
    uvicorn.run(app, host="0.0.0.0", port=port)
