import os
from typing import List

from fastapi import FastAPI, Depends, HTTPException, Header
from fastapi.middleware.cors import CORSMiddleware
from jose import jwt, JWTError
from sqlalchemy.orm import Session
from sqlalchemy import func

from app.database import Base, engine, SessionLocal
from app import models, schemas
from app.auth import hash_password, verify_password, create_access_token

SECRET_KEY = os.getenv("SECRET_KEY", "change-me")
ALGORITHM = "HS256"

app = FastAPI(title="EduCloud Mentor API")

# CORS so your frontend can call the API
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # later restrict to your deployed frontend domain
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Create DB tables (simple MVP)
Base.metadata.create_all(bind=engine)

def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

def decode_user_from_token(token: str) -> dict:
    return jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])

def get_current_user(
    authorization: str = Header(None),
    db: Session = Depends(get_db),
) -> models.User:
    if not authorization or not authorization.startswith("Bearer "):
        raise HTTPException(status_code=401, detail="Missing or invalid Authorization header")

    token = authorization.split(" ", 1)[1]
    try:
        payload = decode_user_from_token(token)
        user_id = payload.get("user_id")
        if not user_id:
            raise HTTPException(status_code=401, detail="Invalid token payload")
    except JWTError:
        raise HTTPException(status_code=401, detail="Invalid token")

    user = db.query(models.User).filter(models.User.id == user_id).first()
    if not user:
        raise HTTPException(status_code=401, detail="User not found")
    return user

def require_role(user: models.User, allowed: List[str]):
    if user.role not in allowed:
        raise HTTPException(status_code=403, detail="Not allowed")

@app.get("/")
def root():
    return {"message": "EduCloud Mentor API is running"}

# ---------- AUTH ----------
@app.post("/auth/register")
def register(payload: schemas.RegisterIn, db: Session = Depends(get_db)):
    if payload.role not in ["student", "mentor", "admin"]:
        raise HTTPException(status_code=400, detail="role must be student, mentor, or admin")

    if db.query(models.User).filter(models.User.email == payload.email).first():
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

# ---------- STUDENT ----------
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

# ---------- MENTOR ----------
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

# ---------- ADMIN ----------
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
