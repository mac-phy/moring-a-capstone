from fastapi import FastAPI, HTTPException, Depends
from sqlalchemy.orm import Session
from passlib.context import CryptContext

from database import SessionLocal, engine
from models import UserDB
from schemas import User
import models

# Create tables
models.Base.metadata.create_all(bind=engine)

app = FastAPI()

# Password hashing
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

# Dependency
def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

# Hash password
def hash_password(password: str):
    return pwd_context.hash(password)

# Verify password
def verify_password(plain_password, hashed_password):
    return pwd_context.verify(plain_password, hashed_password)

# Home route
@app.get("/")
def home():
    return {"message": "FastAPI Auth System is running 🚀"}

# Register
@app.post("/register")
def register(user: User, db: Session = Depends(get_db)):

    existing_user = db.query(UserDB).filter(UserDB.username == user.username).first()

    if existing_user:
        raise HTTPException(status_code=400, detail="User already exists")

    hashed_pwd = hash_password(user.password)

    new_user = UserDB(
        username=user.username,
        password=hashed_pwd
    )

    db.add(new_user)
    db.commit()
    db.refresh(new_user)

    return {"message": "User registered successfully"}

# Login
@app.post("/login")
def login(user: User, db: Session = Depends(get_db)):

    db_user = db.query(UserDB).filter(UserDB.username == user.username).first()

    if not db_user:
        raise HTTPException(status_code=401, detail="Invalid credentials")

    if not verify_password(user.password, db_user.password):
        raise HTTPException(status_code=401, detail="Invalid credentials")

    return {"message": "Login successful ✅"}