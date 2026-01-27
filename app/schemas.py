from pydantic import BaseModel, EmailStr
from datetime import datetime
from typing import Optional, List

class RegisterIn(BaseModel):
    full_name: str
    email: EmailStr
    password: str
    role: str = "student"


class LoginIn(BaseModel):
    email: EmailStr
    password: str


class TokenOut(BaseModel):
    access_token: str
    token_type: str = "bearer"
    role: str


class RequestCreate(BaseModel):
    subject: str
    topic: str
    urgency: str = "Medium"
    description: str


class RequestUpdate(BaseModel):
    status: str
    mentor_notes: Optional[str] = None


class RequestOut(BaseModel):
    id: int
    student_id: int
    subject: str
    topic: str
    urgency: str
    description: str
    status: str
    mentor_notes: Optional[str]
    created_at: datetime

    class Config:
        from_attributes = True
