import os
import secrets
from datetime import datetime, timedelta
from typing import Optional

import httpx
from fastapi import FastAPI, HTTPException, Request, Response, Cookie, Depends
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, EmailStr
from sqlalchemy import create_engine, text
from sqlalchemy.exc import IntegrityError
from pwdlib import PasswordHash
from itsdangerous import URLSafeSerializer, BadSignature

app = FastAPI()

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

DIFY_API_KEY = os.getenv("DIFY_API_KEY")
DIFY_BASE_URL = os.getenv("DIFY_BASE_URL", "https://api.dify.ai/v1")
DATABASE_URL = os.getenv("DATABASE_URL")
SESSION_SECRET = os.getenv("SESSION_SECRET")

if not DATABASE_URL:
    raise RuntimeError("DATABASE_URL non configurata")

if not SESSION_SECRET:
    raise RuntimeError("SESSION_SECRET non configurata")

engine = create_engine(DATABASE_URL, pool_pre_ping=True)
password_hash = PasswordHash.recommended()
serializer = URLSafeSerializer(SESSION_SECRET, salt="ethi-auth")

SESSION_COOKIE_NAME = "ethi_session"
SESSION_MAX_AGE_SECONDS = 60 * 60 * 24 * 7  # 7 giorni


class ChatRequest(BaseModel):
    query: str
    conversation_id: str = ""
    user: str = "user"


class SignupRequest(BaseModel):
    email: EmailStr
    password: str


class LoginRequest(BaseModel):
    email: EmailStr
    password: str


def hash_password(password: str) -> str:
    return password_hash.hash(password)


def verify_password(password: str, stored_hash: str) -> bool:
    return password_hash.verify(password, stored_hash)


def create_session_token(user_id: str, email: str) -> str:
    payload = {
        "user_id": user_id,
        "email": email,
        "issued_at": datetime.utcnow().isoformat(),
        "nonce": secrets.token_hex(8),
    }
    return serializer.dumps(payload)


def decode_session_token(token: str) -> dict:
    return serializer.loads(token)


def set_session_cookie(response: Response, token: str) -> None:
    response.set_cookie(
        key=SESSION_COOKIE_NAME,
        value=token,
        max_age=SESSION_MAX_AGE_SECONDS,
        httponly=True,
        secure=True,
        samesite="lax",
    )


def clear_session_cookie(response: Response) -> None:
    response.delete_cookie(
        key=SESSION_COOKIE_NAME,
        httponly=True,
        secure=True,
        samesite="lax",
    )


def get_current_user(ethi_session: Optional[str] = Cookie(default=None)) -> dict:
    if not ethi_session:
        raise HTTPException(status_code=401, detail="Non autenticato")

    try:
        data = decode_session_token(ethi_session)
        return data
    except BadSignature:
        raise HTTPException(status_code=401, detail="Sessione non valida")


@app.get("/")
def root():
    return {"message": "Backend attivo", "status": "ok"}


@app.get("/health")
def health_check():
    try:
        with engine.connect() as conn:
            conn.execute(text("SELECT 1"))
        return {"status": "healthy"}
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"DB error: {str(e)}")


@app.post("/auth/signup")
def signup(payload: SignupRequest, response: Response):
    email = payload.email.strip().lower()
    password = payload.password

    if len(password) < 8:
        raise HTTPException(status_code=400, detail="La password deve avere almeno 8 caratteri")

    if len(password) > 200:
        raise HTTPException(status_code=400, detail="La password è troppo lunga")

    password_hash = hash_password(password)

    try:
        with engine.begin() as conn:
            result = conn.execute(
                text("""
                    INSERT INTO users (email, password_hash)
                    VALUES (:email, :password_hash)
                    RETURNING id, email, created_at
                """),
                {"email": email, "password_hash": password_hash},
            )
            user = result.mappings().first()
    except IntegrityError:
        raise HTTPException(status_code=409, detail="Utente già esistente")
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Errore database: {str(e)}")

    token = create_session_token(str(user["id"]), user["email"])
    set_session_cookie(response, token)

    return {
        "message": "Registrazione completata",
        "user": {
            "id": str(user["id"]),
            "email": user["email"],
            "created_at": str(user["created_at"]),
        },
    }


@app.post("/auth/login")
def login(payload: LoginRequest, response: Response):
    email = payload.email.strip().lower()
    password = payload.password

    try:
        with engine.connect() as conn:
            result = conn.execute(
                text("""
                    SELECT id, email, password_hash, created_at
                    FROM users
                    WHERE email = :email
                """),
                {"email": email},
            )
            user = result.mappings().first()
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Errore database: {str(e)}")

    if not user or not verify_password(password, user["password_hash"]):
        raise HTTPException(status_code=401, detail="Credenziali non valide")

    token = create_session_token(str(user["id"]), user["email"])
    set_session_cookie(response, token)

    return {
        "message": "Login effettuato",
        "user": {
            "id": str(user["id"]),
            "email": user["email"],
        },
    }


@app.post("/auth/logout")
def logout(response: Response):
    clear_session_cookie(response)
    return {"message": "Logout effettuato"}


@app.get("/auth/me")
def auth_me(user: dict = Depends(get_current_user)):
    return {
        "authenticated": True,
        "user": {
            "id": user["user_id"],
            "email": user["email"],
        },
    }


@app.post("/chat")
async def chat(request: ChatRequest, user: dict = Depends(get_current_user)):
    if not DIFY_API_KEY:
        raise HTTPException(status_code=500, detail="DIFY_API_KEY non configurata")

    headers = {
        "Authorization": f"Bearer {DIFY_API_KEY}",
        "Content-Type": "application/json"
    }
    payload = {
        "inputs": {},
        "query": request.query,
        "response_mode": "blocking",
        "conversation_id": request.conversation_id,
        "user": f"user-{user['user_id']}"
    }

    try:
        async with httpx.AsyncClient(timeout=30.0) as client:
            resp = await client.post(
                f"{DIFY_BASE_URL}/chat-messages",
                json=payload,
                headers=headers
            )
            resp.raise_for_status()
            return resp.json()
    except httpx.HTTPError as e:
        raise HTTPException(status_code=502, detail=f"Dify API error: {str(e)}")
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Internal error: {str(e)}")