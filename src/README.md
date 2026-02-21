# Mergington High School Activities API

A super simple FastAPI application that allows students to view and sign up for extracurricular activities.

## Features

- View all available extracurricular activities
- User registration and login with JWT authentication
- Role-based access control (`super_admin`, `club_admin`, `member`, `student`)
- Protected sign-up and unregister actions

## Getting Started

1. Install the dependencies:

   ```
   pip install -r ../requirements.txt
   ```

2. Run the application:

   ```
   python app.py
   ```

3. Open your browser and go to:
   - API documentation: http://localhost:8000/docs
   - Alternative documentation: http://localhost:8000/redoc

## API Endpoints

| Method | Endpoint | Description |
| ------ | -------- | ----------- |
| POST | `/auth/register` | Register a new user (`student` or `member`) and return JWT |
| POST | `/auth/login` | Login and return JWT |
| GET | `/auth/me` | Get current authenticated user from bearer token |
| GET | `/activities` | Get all activities with details and participants |
| POST | `/activities/{activity_name}/signup?email=student@mergington.edu` | Protected: sign up for an activity |
| DELETE | `/activities/{activity_name}/unregister?email=student@mergington.edu` | Protected: unregister a student from an activity |

## Authentication and Roles

- Public endpoint: `/activities`
- Protected endpoints require header: `Authorization: Bearer <token>`
- Self-registration is limited to `student` and `member` roles
- Seeded users for local testing:
   - `admin@mergington.edu` / `adminpass123` (`super_admin`)
   - `clubadmin@mergington.edu` / `clubadmin123` (`club_admin`)

### Role Rules

- `student`, `member`, `club_admin`, `super_admin` can call signup
- `student` and `member` can only sign up their own email
- `club_admin` and `super_admin` can unregister students
- Missing/invalid token returns `401`
- Insufficient role permissions returns `403`

## Data Model

The application uses a simple data model with meaningful identifiers:

1. **Activities** - Uses activity name as identifier:

   - Description
   - Schedule
   - Maximum number of participants allowed
   - List of student emails who are signed up

2. **Students** - Uses email as identifier:
   - Name
   - Grade level

All data is stored in memory, which means data will be reset when the server restarts.
