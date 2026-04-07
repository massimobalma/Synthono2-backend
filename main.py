import os
import secrets
from datetime import datetime, timedelta
from typing import Optional

import httpx
from fastapi import FastAPI, HTTPException, Response, Cookie, Depends
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import StreamingResponse
from pydantic import BaseModel, EmailStr
from sqlalchemy import create_engine, text
from sqlalchemy.exc import IntegrityError
from pwdlib import PasswordHash
from itsdangerous import URLSafeSerializer, BadSignature

app = FastAPI()

app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        "https://www.synthono.com",
        "https://synthono.com",
        "https://synthono2-backend.onrender.com",
    ],
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
class ForgotPasswordRequest (BaseModel):
    email: EmailStr

class ResetPasswordRequest (BaseModel):
    token: str
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

def create_reset_token(email: str) -> str:
    payload = {
        "email": email,
        "issued_at": datetime.utcnow().isoformat(),
        "nonce": secrets.token_hex(8),
    }
    reset_serializer = URLSafeSerializer(SESSION_SECRET, salt = "ethi-reset")
    return reset_serializer.dumps(payload)

def decode_reset_token(token: str) -> dict:
    reset_serializer = URLSafeSerializer(SESSION_SECRET, salt = "ethi-reset")
    return reset_serializer.loads(token)


def set_session_cookie(response: Response, token: str) -> None:
    response.set_cookie(
        key=SESSION_COOKIE_NAME,
        value=token,
        max_age=SESSION_MAX_AGE_SECONDS,
        httponly=True,
        secure=True,
        samesite="none",
    )


def clear_session_cookie(response: Response) -> None:
    response.delete_cookie(
        key=SESSION_COOKIE_NAME,
        httponly=True,
        secure=True,
        samesite="none",
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

@app.post("/auth/forgot-password")
def forgot_password(payload: ForgotPasswordRequest):
    email = payload.email.strip().lower()

    try:
        with engine.connect() as conn:
            result = conn.execute(
                text("""
                    SELECT id, email
                    FROM users
                    WHERE email = :email
                """),
                {"email": email},
            )
            user = result.mappings().first()

        if user:
            token = create_reset_token(user["email"])
            token_hash = hash_password(token)
            expires_at = datetime.utcnow() + timedelta(hours=1)

            with engine.begin() as conn:
                conn.execute(
                    text("""
                        INSERT INTO password_reset_tokens (user_id, token_hash, expires_at)
                        VALUES (:user_id, :token_hash, :expires_at)
                    """),
                    {
                        "user_id": str(user["id"]),
                        "token_hash": token_hash,
                        "expires_at": expires_at,
                    },
                )

            print(f"RESET LINK per {user['email']}: https://www.synthono.com/reset-password.html?token={token}")

    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Errore database: {str(e)}")

    return {
        "message": "Se l'indirizzo email è registrato, riceverai un link per reimpostare la password."
    }

@app.post("/auth/reset-password")
def reset_password(payload: ResetPasswordRequest):
    token = payload.token
    new_password = payload.password

    if len(new_password) < 8:
        raise HTTPException(status_code=400, detail="La password deve avere almeno 8 caratteri")

    if len(new_password) > 200:
        raise HTTPException(status_code=400, detail="La password è troppo lunga")

    try:
        token_data = decode_reset_token(token)
        email = token_data["email"].strip().lower()
    except Exception:
        raise HTTPException(status_code=400, detail="Token non valido")

    try:
        with engine.connect() as conn:
            user_result = conn.execute(
                text("""
                    SELECT id, email
                    FROM users
                    WHERE email = :email
                """),
                {"email": email},
            )
            user = user_result.mappings().first()

            if not user:
                raise HTTPException(status_code=400, detail="Token non valido")

            token_rows = conn.execute(
                text("""
                    SELECT id, token_hash, expires_at, used_at
                    FROM password_reset_tokens
                    WHERE user_id = :user_id
                    ORDER BY created_at DESC
                """),
                {"user_id": str(user["id"])},
            ).mappings().all()

        valid_token_row = None
        now = datetime.utcnow()

        for row in token_rows:
            if row["used_at"] is not None:
                continue
            if row["expires_at"] < now:
                continue
            if verify_password(token, row["token_hash"]):
                valid_token_row = row
                break

        if not valid_token_row:
            raise HTTPException(status_code=400, detail="Token non valido o scaduto")

        new_password_hash = hash_password(new_password)

        with engine.begin() as conn:
            conn.execute(
                text("""
                    UPDATE users
                    SET password_hash = :password_hash
                    WHERE id = :user_id
                """),
                {
                    "password_hash": new_password_hash,
                    "user_id": str(user["id"]),
                },
            )

            conn.execute(
                text("""
                    UPDATE password_reset_tokens
                    SET used_at = NOW()
                    WHERE id = :token_id
                """),
                {"token_id": str(valid_token_row["id"])},
            )

        return {"message": "Password aggiornata con successo"}

    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Errore interno: {str(e)}")

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
        "Content-Type": "application/json",
        "Accept": "text/event-stream",
    }

    payload = {
        "inputs": {},
        "query": request.query,
        "response_mode": "streaming",
        "conversation_id": request.conversation_id,
        "user": f"user-{user['user_id']}"
    }

    timeout = httpx.Timeout(120.0, connect=20.0)

    async def event_generator():
        import json

        try:
            async with httpx.AsyncClient(timeout=timeout) as client:
                async with client.stream(
                    "POST",
                    f"{DIFY_BASE_URL}/chat-messages",
                    json=payload,
                    headers=headers
                ) as resp:
                    resp.raise_for_status()

                    async for line in resp.aiter_lines():
                        if not line:
                            continue

                        if line.startswith("data: "):
                            raw = line[6:].strip()

                            if raw == "[DONE]":
                                yield "data: [DONE]\n\n"
                                break

                            try:
                                data = json.loads(raw)
                                event_type = data.get("event")

                                if event_type in ("message", "agent_message"):
                                    answer = data.get("answer", "")
                                    if answer:
                                        yield f"data: {json.dumps({'chunk': answer})}\n\n"

                                elif event_type == "message_end":
                                    yield "data: [DONE]\n\n"
                                    break

                            except Exception:
                                continue

        except httpx.HTTPStatusError as e:
            if e.response.status_code == 504:
                yield f"data: {json.dumps({'error': 'L’assistente sta impiegando più tempo del previsto. Riprova tra qualche secondo.'})}\n\n"
                yield "data: [DONE]\n\n"
                return

            yield f"data: {json.dumps({'error': f'Dify API status error: {e.response.status_code}'})}\n\n"
            yield "data: [DONE]\n\n"

        except httpx.RequestError:
            yield f"data: {json.dumps({'error': 'Errore di comunicazione con il motore AI.'})}\n\n"
            yield "data: [DONE]\n\n"

        except Exception as e:
            yield f"data: {json.dumps({'error': f'Errore interno: {str(e)}'})}\n\n"
            yield "data: [DONE]\n\n"

    return StreamingResponse(
        event_generator(),
        media_type="text/event-stream",
        headers={
            "Cache-Control": "no-cache",
            "Connection": "keep-alive",
            "X-Accel-Buffering": "no",
        },
    )
