# EduCloud Mentor API

A cloud-hosted mentorship request API built with **FastAPI (Python)** and deployed to production using **Railway**.

This project demonstrates real-world cloud deployment, API design, and debugging of build/runtime issues in a production environment.


Live Demo :

- **API Root:**  
  https://educloud-mentor-api-production-67c5.up.railway.app/

- **Swagger Docs:**  
  https://educloud-mentor-api-production-67c5.up.railway.app/docs

---

 What the API Does :

- Students can submit mentorship requests
- Mentors can view all submitted requests
- Requests can be updated with a status (e.g. Pending, Approved)

---

 Tech Stack :

- **Backend:** Python, FastAPI
- **Server:** Uvicorn
- **Cloud Platform:** Railway
- **Version Control:** GitHub
- **API Docs:** Swagger (OpenAPI)

---

 Key Endpoints :

| Method | Endpoint | Description |
|------|--------|------------|
| GET | `/` | Health check |
| POST | `/requests` | Create a mentorship request |
| GET | `/requests` | View all requests |
| PUT | `/requests/{request_id}` | Update request status |

---

 Example Request (POST `/requests`) :

```json
{
  "student_name": "Reabetswe Selepe",
  "subject": "Computer Science",
  "description": "Looking for guidance on choosing final year modules"
}
