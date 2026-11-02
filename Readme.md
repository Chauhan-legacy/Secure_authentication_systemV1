# Secure Authentication System

A backend authentication and session management service built with **Python, Flask, PyJWT, bcrypt, and PostgreSQL**.

The project implements secure credential storage, JWT-based authentication, protected API endpoints, and session revocation through a structured backend architecture.

## Features

- **Password Hashing:** Secure password storage using bcrypt with salted hashing.
- **JWT Authentication:** Token-based authentication using JSON Web Tokens and the HS256 signing algorithm.
- **Protected Endpoints:** Access control for restricted routes through token verification.
- **Session Management:** Token revocation and logout functionality.
- **Database Integration:** PostgreSQL-backed persistence for user credentials and account records.
- **SQLAlchemy Support:** Structured database interaction through an ORM.

## Technology Stack

| Component | Technology |
|---|---|
| Language | Python |
| Backend Framework | Flask |
| Authentication | PyJWT |
| Password Security | bcrypt |
| Database | PostgreSQL |
| ORM | SQLAlchemy |

## Getting Started

### Prerequisites

Ensure the following are installed:

- Python 3.10 or later
- PostgreSQL
- Git

### 1. Clone the Repository

```bash
git clone https://github.com/YOUR_USERNAME/secure-authentication-system.git
cd secure-authentication-system
```

### 2. Create a Virtual Environment

```bash
python -m venv venv
```

Activate the environment:

**Windows**
```bash
venv\Scripts\activate
```

**macOS / Linux**
```bash
source venv/bin/activate
```

### 3. Install Dependencies

```bash
pip install -r requirements.txt
```

### 4. Configure Environment Variables

Create a `.env` file in the project root and configure the required credentials:

```env
SECRET_KEY=your_secret_key
DATABASE_URL=postgresql://username:password@localhost:5432/auth_db
```

Replace the placeholder values with your local configuration.

### 5. Run the Application

```bash
python app.py
```

The application will start using the configured Flask environment.

## Security Considerations

- Store sensitive configuration values in environment variables.
- Never commit database credentials, secret keys, or `.env` files.
- Use HTTPS when deploying outside a local development environment.
- Configure secure token expiration and revocation policies.
- Use a strong, randomly generated JWT signing key.
- Apply appropriate database access controls.

## Project Status

This project is intended for authentication-system development, backend engineering practice, and security-focused experimentation.

Production deployment requires additional security review, configuration hardening, and testing.

## License

Specify the appropriate license before distributing or reusing this project.
