import os
from datetime import datetime, timedelta, timezone
from functools import wraps
from flask import Flask, request, jsonify, make_response, render_template
import bcrypt
import jwt
from sqlalchemy import create_engine, Column, Integer, String, DateTime
from sqlalchemy.orm import declarative_base, sessionmaker

app = Flask(__name__)
SECRET_KEY = os.environ.get("JWT_SECRET_KEY", "super-secret-jwt-key-change-in-production")
DATABASE_URL = os.environ.get("DATABASE_URL", "sqlite:///auth_users.db")

engine = create_engine(DATABASE_URL)
Base = declarative_base()
SessionLocal = sessionmaker(bind=engine)

class User(Base):
    __tablename__ = "users"
    id = Column(Integer, primary_key=True, index=True)
    username = Column(String(80), unique=True, nullable=False)
    email = Column(String(120), unique=True, nullable=False)
    password_hash = Column(String(255), nullable=False)
    created_at = Column(DateTime, default=lambda: datetime.now(timezone.utc))

class RevokedToken(Base):
    __tablename__ = "revoked_tokens"
    id = Column(Integer, primary_key=True)
    jti = Column(String(120), unique=True, nullable=False)
    revoked_at = Column(DateTime, default=lambda: datetime.now(timezone.utc))

Base.metadata.create_all(bind=engine)

def log_security_event(event_type: str, details: dict):
    """Outputs structured authentication & JWT audit logs directly to the terminal."""
    ts = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    print("\n" + "=" * 65)
    print(f"[{ts}] SECURITY AUDIT | {event_type}")
    print("-" * 65)
    for k, v in details.items():
        print(f"  {k:<18}: {v}")
    print("=" * 65, flush=True)

def create_jwt_token(user_id: int, username: str) -> tuple[str, str]:
    now = datetime.now(timezone.utc)
    jti = f"{user_id}-{int(now.timestamp())}"
    payload = {
        "sub": str(user_id),
        "username": username,
        "iat": now,
        "exp": now + timedelta(hours=2),
        "jti": jti
    }
    token = jwt.encode(payload, SECRET_KEY, algorithm="HS256")
    return token, jti

def token_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token = None
        auth_header = request.headers.get("Authorization", "")
        if auth_header.startswith("Bearer "):
            token = auth_header.split(" ")[1]
        elif "access_token" in request.cookies:
            token = request.cookies.get("access_token")

        if not token:
            log_security_event("UNAUTHORIZED ACCESS BLOCKED", {"Reason": "Missing JWT Token", "Endpoint": request.path})
            return jsonify({"error": "Authentication token is missing"}), 401

        try:
            payload = jwt.decode(token, SECRET_KEY, algorithms=["HS256"])
            session = SessionLocal()
            is_revoked = session.query(RevokedToken).filter_by(jti=payload["jti"]).first()
            user = session.query(User).filter_by(id=int(payload["sub"])).first()
            session.close()
            if is_revoked or not user:
                log_security_event("REVOKED TOKEN REJECTED", {"JTI": payload.get("jti"), "Endpoint": request.path})
                return jsonify({"error": "Token has been revoked or user does not exist"}), 401
            request.current_user = {"id": user.id, "username": user.username, "email": user.email, "jti": payload["jti"]}
        except jwt.ExpiredSignatureError:
            log_security_event("EXPIRED TOKEN REJECTED", {"Endpoint": request.path})
            return jsonify({"error": "Token has expired"}), 401
        except jwt.InvalidTokenError:
            log_security_event("INVALID TOKEN REJECTED", {"Endpoint": request.path})
            return jsonify({"error": "Invalid token"}), 401

        return f(*args, **kwargs)
    return decorated

@app.route("/", methods=["GET"])
def index():
    return render_template("index.html")

@app.route("/register", methods=["POST"])
def register():
    data = request.get_json() or {}
    username = data.get("username", "").strip()
    email = data.get("email", "").strip()
    password = data.get("password", "")

    if not username or not email or len(password) < 8:
        return jsonify({"error": "Username, email, and a password (min 8 chars) are required"}), 400

    hashed = bcrypt.hashpw(password.encode("utf-8"), bcrypt.gensalt()).decode("utf-8")

    session = SessionLocal()
    existing = session.query(User).filter((User.username == username) | (User.email == email)).first()
    if existing:
        session.close()
        log_security_event("REGISTRATION FAILED", {"Username": username, "Reason": "Duplicate user/email"})
        return jsonify({"error": "Username or email already registered"}), 409

    new_user = User(username=username, email=email, password_hash=hashed)
    session.add(new_user)
    session.commit()
    user_id = new_user.id
    session.close()

    log_security_event("USER REGISTERED", {
        "User ID": user_id,
        "Username": username,
        "Email": email,
        "Bcrypt Hash": hashed[:29] + "..."
    })
    return jsonify({"message": "User registered successfully"}), 201

@app.route("/login", methods=["POST"])
def login():
    data = request.get_json() or {}
    username = data.get("username", "").strip()
    password = data.get("password", "")

    session = SessionLocal()
    user = session.query(User).filter_by(username=username).first()
    session.close()

    if not user or not bcrypt.checkpw(password.encode("utf-8"), user.password_hash.encode("utf-8")):
        log_security_event("LOGIN FAILED", {"Username": username, "Reason": "Invalid credentials"})
        return jsonify({"error": "Invalid username or password"}), 401

    token, jti = create_jwt_token(user.id, user.username)
    log_security_event("JWT ISSUED (LOGIN SUCCESS)", {
        "User ID": user.id,
        "Username": user.username,
        "Session JTI": jti,
        "Algorithm": "HS256",
        "JWT Token": token[:36] + "..."
    })

    resp = make_response(jsonify({
        "message": "Login successful",
        "token": token,
        "user": {"id": user.id, "username": user.username, "email": user.email}
    }))
    resp.set_cookie("access_token", token, httponly=True, samesite="Lax")
    return resp

@app.route("/profile", methods=["GET"])
@token_required
def profile():
    u = request.current_user
    log_security_event("PROTECTED ROUTE ACCESSED", {
        "Endpoint": "/profile",
        "Authenticated User": u["username"],
        "Session JTI": u["jti"]
    })
    return jsonify({"profile": u})

@app.route("/logout", methods=["POST"])
@token_required
def logout():
    u = request.current_user
    session = SessionLocal()
    session.add(RevokedToken(jti=u["jti"]))
    session.commit()
    session.close()

    log_security_event("SESSION REVOKED (LOGOUT)", {
        "Username": u["username"],
        "Revoked JTI": u["jti"],
        "Status": "Blacklisted in DB"
    })

    resp = make_response(jsonify({"message": "Logged out and token revoked"}))
    resp.delete_cookie("access_token")
    return resp

if __name__ == "__main__":
    app.run(debug=True, port=5003)