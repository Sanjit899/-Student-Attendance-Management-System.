# Student Attendance Management System

A **full-stack web application** for managing student attendance, designed for teachers and school administrators. Built with **Python (Flask)**, **MongoDB**, and **Bootstrap**, this system allows managing students, classes, daily attendance, notifications, and reporting — all in a responsive, user-friendly interface.

---

## Table of Contents

- [Features](#features)  
- [Technologies Used](#technologies-used)  
- [Project Structure](#project-structure)  
- [Setup & Installation](#setup--installation)  
- [Usage](#usage)  
- [Screenshots](#screenshots)  
- [Future Enhancements](#future-enhancements)  
- [Author](#author)  

---

## Features

### 1. User Authentication
- Secure login for **teachers/admins**.  
- Passwords hashed using **bcrypt**.  
- Session management for secure access.  

### 2. Student & Class Management
- Add, edit, and delete **students**.  
- Add, edit, and delete **classes**.  
- Assign students to specific classes.

### 3. Attendance Management
- **Mark daily attendance** for students.  
- Mark **absent students** specifically.  
- Attendance history by date and class.  
- Dashboard showing total students, total classes, and recent absences.

### 4. Notifications System
- Write and store notifications/messages for teachers or admin.  
- View all notifications in a single page.  

### 5. Reporting
- Generate reports for **attendance history**.  
- Dashboard displays **quick statistics**.  

### 6. Responsive UI
- Built using **Bootstrap 5** for mobile-friendly design.  
- Sidebar navigation with quick access to all modules.  

### 7. Images & Assets
- All images stored in `/static/images`.  
- Easily customizable icons and logos.

---

## Technologies Used

| Layer | Technology |
|-------|------------|
| Backend | Python, Flask |
| Database | MongoDB (NoSQL) |
| Frontend | HTML, CSS, JavaScript, Bootstrap 5 |
| Security | Flask-Login, bcrypt for password hashing |
| Others | Jinja2 templates, Flask session management |


students_attendance/
│
├─ app.py # Main Flask application
├─ requirements.txt # Python dependencies
├─ templates/ # HTML templates
│ ├─ base.html
│ ├─ dashboard.html
│ ├─ login.html
│ ├─ register.html
│ ├─ students.html
│ ├─ classes.html
│ ├─ mark_attendance.html
│ ├─ attendance_history.html
│ ├─ absent_marking.html
│ ├─ absent_history.html
│ └─ notifications.html
│
├─ static/
│ ├─ css/ # Optional additional CSS files
│ ├─ js/ # Optional additional JS files
│ └─ images/ # All project images
│ └─ footer-icon.png
│
└─ README.md


---

## Setup & Installation

### 1. Clone Repository
```bash
git clone https://github.com/<your-username>/students_attendance.git
cd students_attendance

2. Create Virtual Environment
python -m venv venv
source venv/bin/activate  # Linux/Mac
venv\Scripts\activate     # Windows

3. Install Dependencies
pip install -r requirements.txt


4. Configure MongoDB

Install MongoDB or use MongoDB Atlas cloud service.

Update the MongoDB URI in app.py if using cloud database:client = MongoClient('mongodb+srv://<username>:<password>@cluster0.mongodb.net/attendance_db')
db = client.attendance_db

5. Run the App
python app.py
Open your browser at http://127.0.0.1:5000.

Usage

Register/Login as a teacher or admin.

Navigate through the sidebar to manage students, classes, and attendance.

Mark daily attendance or absents using the Mark Attendance and Absent Marking pages.

Check history and generate attendance reports.

Write and view notifications in the Notifications section.


Future Enhancements

Add PDF/Excel export for attendance reports.

Add email notifications for absent students or messages.

Implement role-based access control for multiple teachers/admins.

Deploy the project online using Heroku or Render.

Improve UI/UX with charts and analytics for attendance trends.


Project Status: ✅ Complete for Resume & Portfolio
License: MIT.
---

## Project Structure

