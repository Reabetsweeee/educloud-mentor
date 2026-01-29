import os
from typing import List, Optional

from fastapi import FastAPI, Depends, HTTPException, Header
from fastapi.middleware.cors import CORSMiddleware
from jose import jwt, JWTError
from sqlalchemy.orm import Session
from sqlalchemy import func

from app.database import Base, engine, SessionLocal
from app import models, schemas
from app.auth import hash_password, verify_password, create_access_token

# =========================
# Config
# =========================
SECRET_KEY = os.getenv("SECRET_KEY", "change-me")
ALGORITHM = "HS256"

# Put your Netlify domain here once you have it, e.g. "https://educloud-mentor.netlify.app"
ALLOWED_ORIGINS = [
    "http://127.0.0.1:8000",
    "http://localhost:8000",
    "http://127.0.0.1:5500",
    "http://localhost:5500",
    # "https://YOUR-SITE.netlify.app",
]

app = FastAPI(title="EduCloud Mentor API")

# CORS (so your public website can call your API)
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # quick for now; restrict to ALLOWED_ORIGINS later
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Create tables safely on startup (Railway-friendly)
@app.on_event("startup")
def on_startup():
    Base.metadata.create_all(bind=engine)

# =========================
# DB dependency
# =========================
def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

# =========================
# Auth helpers
# =========================
def require_role(user: models.User, allowed: List[str]):
    if user.role not in allowed:
        raise HTTPException(status_code=403, detail="Not allowed")

def get_current_user(
    authorization: str = Header(None),
    db: Session = Depends(get_db),
) -> models.User:
    if not authorization or not authorization.startswith("Bearer "):
        raise HTTPException(status_code=401, detail="Missing or invalid Authorization header")

    token = authorization.split(" ", 1)[1]
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        user_id = payload.get("user_id")
        if not user_id:
            raise HTTPException(status_code=401, detail="Invalid token payload")
    except JWTError:
        raise HTTPException(status_code=401, detail="Invalid token")

    user = db.query(models.User).filter(models.User.id == user_id).first()
    if not user:
        raise HTTPException(status_code=401, detail="User not found")
    return user

# =========================
# Health
# =========================
@app.get("/")
def root():
    return {"message": "EduCloud Mentor API is running"}

@app.get("/health")
def health():
    return {"status": "ok"}

# =========================
# Auth endpoints
# =========================
@app.post("/auth/register")
def register(payload: schemas.RegisterIn, db: Session = Depends(get_db)):
    if payload.role not in ["student", "mentor", "admin"]:
        raise HTTPException(status_code=400, detail="role must be student, mentor, or admin")

    existing = db.query(models.User).filter(models.User.email == payload.email).first()
    if existing:
        raise HTTPException(status_code=400, detail="Email already registered")

    user = models.User(
        full_name=payload.full_name,
        email=payload.email,
        password_hash=hash_password(payload.password),
        role=payload.role,
    )
    db.add(user)
    db.commit()
    db.refresh(user)
    return {"message": "Registered successfully", "user_id": user.id, "role": user.role}

@app.post("/auth/login", response_model=schemas.TokenOut)
def login(payload: schemas.LoginIn, db: Session = Depends(get_db)):
    user = db.query(models.User).filter(models.User.email == payload.email).first()
    if not user or not verify_password(payload.password, user.password_hash):
        raise HTTPException(status_code=401, detail="Invalid email or password")

    token = create_access_token({"user_id": user.id, "role": user.role})
    return {"access_token": token, "token_type": "bearer", "role": user.role}

# =========================
# Public student submission (no login)
# For your Netlify student form
# =========================
@app.post("/public/requests")
def public_create_request(payload: dict, db: Session = Depends(get_db)):
    """
    Accepts the simple payload from your public form:
    {
      "student_name": "...",
      "subject": "...",
      "description": "...",
      "status": "Pending"
    }
    """
    student_name = (payload.get("student_name") or "").strip()
    subject = (payload.get("subject") or "").strip()
    description = (payload.get("description") or "").strip()

    if not student_name or not subject or not description:
        raise HTTPException(status_code=400, detail="student_name, subject, and description are required")

    # If your DB schema doesn't have student_name column, we store it in mentor_notes for now.
    # Recommended: add a student_name column later.
    req = models.MentorshipRequest(
        student_id=1,  # placeholder (we’ll improve this later)
        subject=subject,
        topic="General",
        urgency="Medium",
        description=description,
        status="Pending",
        mentor_notes=f"Submitted by: {student_name}",
    )

    db.add(req)
    db.commit()
    db.refresh(req)
    return {"message": "Request submitted", "request_id": req.id}

# =========================
# Student (logged in)
# =========================
@app.post("/requests", response_model=schemas.RequestOut)
def create_request(
    payload: schemas.RequestCreate,
    db: Session = Depends(get_db),
    user: models.User = Depends(get_current_user),
):
    require_role(user, ["student"])

    req = models.MentorshipRequest(
        student_id=user.id,
        subject=payload.subject,
        topic=payload.topic,
        urgency=payload.urgency,
        description=payload.description,
        status="Pending",
    )
    db.add(req)
    db.commit()
    db.refresh(req)
    return req

@app.get("/my-requests", response_model=List[schemas.RequestOut])
def my_requests(
    db: Session = Depends(get_db),
    user: models.User = Depends(get_current_user),
):
    require_role(user, ["student"])
    return (
        db.query(models.MentorshipRequest)
        .filter(models.MentorshipRequest.student_id == user.id)
        .order_by(models.MentorshipRequest.id.desc())
        .all()
    )

# =========================
# Mentor/Admin
# =========================
@app.get("/requests", response_model=List[schemas.RequestOut])
def all_requests(
    db: Session = Depends(get_db),
    user: models.User = Depends(get_current_user),
):
    require_role(user, ["mentor", "admin"])
    return db.query(models.MentorshipRequest).order_by(models.MentorshipRequest.id.desc()).all()

@app.put("/requests/{request_id}", response_model=schemas.RequestOut)
def update_request(
    request_id: int,
    payload: schemas.RequestUpdate,
    db: Session = Depends(get_db),
    user: models.User = Depends(get_current_user),
):
    require_role(user, ["mentor", "admin"])

    req = db.query(models.MentorshipRequest).filter(models.MentorshipRequest.id == request_id).first()
    if not req:
        raise HTTPException(status_code=404, detail="Request not found")

    req.status = payload.status
    req.mentor_notes = payload.mentor_notes
    db.commit()
    db.refresh(req)
    return req

# =========================
# Admin metrics
# =========================
@app.get("/admin/metrics")
def admin_metrics(
    db: Session = Depends(get_db),
    user: models.User = Depends(get_current_user),
):
    require_role(user, ["admin"])

    total = db.query(func.count(models.MentorshipRequest.id)).scalar()
    pending = db.query(func.count(models.MentorshipRequest.id)).filter(models.MentorshipRequest.status == "Pending").scalar()
    in_progress = db.query(func.count(models.MentorshipRequest.id)).filter(models.MentorshipRequest.status == "In Progress").scalar()
    resolved = db.query(func.count(models.MentorshipRequest.id)).filter(models.MentorshipRequest.status == "Resolved").scalar()

    return {
        "total_requests": total,
        "pending": pending,
        "in_progress": in_progress,
        "resolved": resolved,
    }
