from fastapi import FastAPI
from pydantic import BaseModel
from typing import List
from datetime import datetime

app = FastAPI(title="EduCloud Mentor API")

requests_db = []

class MentorshipRequest(BaseModel):
    student_name: str
    subject: str
    description: str
    status: str = "Pending"
    created_at: datetime = datetime.now()

@app.get("/")
def root():
    return {"message": "EduCloud Mentor API is running"}

@app.post("/requests")
def create_request(req: MentorshipRequest):
    requests_db.append(req)
    return {"message": "Request submitted successfully"}

@app.get("/requests", response_model=List[MentorshipRequest])
def get_requests():
    return requests_db

@app.put("/requests/{request_id}")
def update_request_status(request_id: int, status: str):
    if request_id >= len(requests_db):
        return {"error": "Request not found"}
    requests_db[request_id].status = status
    return {"message": "Status updated"}
