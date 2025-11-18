"""
Database Schemas for Classroom Scheduler

Each Pydantic model corresponds to a collection (lowercased class name) in MongoDB.
"""
from pydantic import BaseModel, Field, EmailStr
from typing import Optional, List, Literal, Dict, Any
from datetime import datetime

Role = Literal["student", "teacher", "admin"]

class User(BaseModel):
    name: str
    email: EmailStr
    password_hash: str
    role: Role = "student"
    is_verified: bool = True  # teachers require admin verification; students default True
    is_active: bool = True

class Session(BaseModel):
    user_id: str
    token: str
    created_at: Optional[datetime] = None
    expires_at: Optional[datetime] = None

class Event(BaseModel):
    title: str
    description: Optional[str] = None
    start_time: datetime
    end_time: datetime
    created_by: str  # teacher id
    audience: Literal["all_students", "specific"] = "all_students"
    audience_ids: List[str] = []  # when audience == specific -> list of student user_ids

class Task(BaseModel):
    title: str
    description: Optional[str] = None
    due_date: datetime
    created_by: str  # teacher id
    audience: Literal["all_students", "specific"] = "all_students"
    audience_ids: List[str] = []
    notified: bool = False  # whether overdue notification was sent

class Notification(BaseModel):
    user_id: str
    title: str
    message: str
    kind: Literal["info", "deadline", "system"] = "info"
    is_read: bool = False
    related_type: Optional[Literal["task", "event"]] = None
    related_id: Optional[str] = None

# The Flames database viewer will read these via the /schema endpoint in main.py
