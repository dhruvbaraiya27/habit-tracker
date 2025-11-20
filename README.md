# 🎯 Habit Tracker

Full-stack habit tracking application with Go backend and JavaScript frontend.

## Features
- User authentication with JWT
- Create, read, update, delete habits
- Track daily habit streaks
- Responsive design
- Docker support

## Tech Stack
- **Backend:** Go, Chi Router, SQLite, JWT
- **Frontend:** HTML, CSS, JavaScript

## Quick Start

### Backend
```bash
cd backend
go run main.go
```

### Frontend
```bash
cd frontend
python3 -m http.server 3000
```

## API Endpoints

**Authentication:**
- POST `/api/auth/register` - Register user
- POST `/api/auth/login` - Login user

**Habits (Protected):**
- GET `/api/habits` - Get all habits
- POST `/api/habits` - Create habit
- GET `/api/habits/:id` - Get single habit
- PUT `/api/habits/:id` - Update habit
- DELETE `/api/habits/:id` - Delete habit
