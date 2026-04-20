import os
import secrets
import smtplib
import stripe
import traceback
import json
from datetime import datetime, timedelta, timezone
from typing import Optional

import httpx
from fastapi import FastAPI, HTTPException, Response, Cookie, Depends, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import StreamingResponse
from pydantic import BaseModel, EmailStr
from sqlalchemy import create_engine, text
from sqlalchemy.exc import IntegrityError
from pwdlib import PasswordHash
from itsdangerous import URLSafeSerializer, BadSignature
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart

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
SMTP_HOST = os.getenv("SMTP_HOST")
SMTP_PORT = int(os.getenv("SMTP_PORT", "465"))
SMTP_USER = os.getenv("SMTP_USER")
SMTP_PASSWORD = os.getenv("SMTP_PASSWORD")
MAIL_FROM = os.getenv("MAIL_FROM", SMTP_USER or "synthono@synthono.com")
APP_BASE_URL = os.getenv("APP_BASE_URL", "https://www.synthono.com")
STRIPE_SECRET_KEY = os.getenv("STRIPE_SECRET_KEY")
STRIPE_START_PRICE_ID = os.getenv("STRIPE_START_PRICE_ID")
STRIPE_PRO_PRICE_ID = os.getenv("STRIPE_PRO_PRICE_ID")
FRONTEND_BASE_URL = os.getenv("FRONTEND_BASE_URL", "https://synthono.com/Test")
STRIPE_WEBHOOK_SECRET = os.getenv("STRIPE_WEBHOOK_SECRET")

if not DATABASE_URL:
    raise RuntimeError("DATABASE_URL non configurata")

if not SESSION_SECRET:
    raise RuntimeError("SESSION_SECRET non configurata")

if STRIPE_SECRET_KEY:
    stripe.api_key = STRIPE_SECRET_KEY

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

class VerifyEmailRequest (BaseModel):
    token: str

class ChangePasswordRequest (BaseModel):
    current_password: str
    new_password: str

class CreateConversationRequest (BaseModel):
    title: str = "Nuova conversazione"

class CreateCheckoutSessionRequest (BaseModel):
    plan: str
    

def build_frontend_url(path: str) -> str:
    return f"{FRONTEND_BASE_URL.rstrip('/')}/{path.lstrip('/')}"

def hash_password(password: str) -> str:
    return password_hash.hash(password)


def verify_password(password: str, stored_hash: str) -> bool:
    return password_hash.verify(password, stored_hash)


def create_session_token(user_id: str, email: str) -> str:
    payload = {
        "user_id": user_id,
        "email": email,
        "issued_at": datetime.now(timezone.utc).isoformat(),
        "nonce": secrets.token_hex(8),
    }
    return serializer.dumps(payload)


def decode_session_token(token: str) -> dict:
    return serializer.loads(token)

def create_reset_token(email: str) -> str:
    payload = {
        "email": email,
        "issued_at": datetime.now(timezone.utc).isoformat(),
        "nonce": secrets.token_hex(8),
    }
    reset_serializer = URLSafeSerializer(SESSION_SECRET, salt = "ethi-reset")
    return reset_serializer.dumps(payload)

def decode_reset_token(token: str) -> dict:
    reset_serializer = URLSafeSerializer(SESSION_SECRET, salt="ethi-reset")
    return reset_serializer.loads(token)

def create_email_verification_token(email: str) -> str:
    payload = {
        "email": email,
        "issued_at": datetime.now(timezone.utc).isoformat(),
        "nonce": secrets.token_hex(8),
    }
    verify_serializer = URLSafeSerializer(SESSION_SECRET, salt="ethi-verify-email")
    return verify_serializer.dumps(payload)


def decode_email_verification_token(token: str) -> dict:
    verify_serializer = URLSafeSerializer(SESSION_SECRET, salt="ethi-verify-email")
    return verify_serializer.loads(token)

def send_reset_email(to_email: str, token: str) -> None:
    if not SMTP_HOST or not SMTP_USER or not SMTP_PASSWORD:
        raise RuntimeError("Configurazione SMTP incompleta")

    reset_link = f"{build_frontend_url('reset-password.html')}?token={token}"

    subject = "Reimposta la tua password SynthONO"

    text_body = f"""
    Abbiamo ricevuto una richiesta di reimpostazione della password per il tuo account SynthONO.

    Apri questo link per reimpostare la password:
    {reset_link}

    Il link scade tra 1 ora.

    Se non hai richiesto tu questa operazione, puoi ignorare questa email.
    """.strip()

    html_body = f"""
<html>
    <body style="font-family: Arial, sans-serif; color: #222; line-height: 1.6;">
        <h2 style="color: #2c6fbb;">Reimposta la tua password</h2>
        <p>Abbiamo ricevuto una richiesta di reimpostazione della password per il tuo account SynthONO.</p>
        <p>
          <a href="{reset_link}" style="display:inline-block;padding:12px 18px;background:#2c6fbb;color:#ffffff;text-decoration:none;border-radius:8px;">
            Reimposta password
          </a>
        </p>
        <p>Se il pulsante non funziona, copia e incolla questo link nel browser:</p>
        <p>{reset_link}</p>
        <p>Il link scade tra 1 ora.</p>
        <p>Se non hai richiesto tu questa operazione, puoi ignorare questa email.</p>
    </body>
</html>
""".strip()

    msg = MIMEMultipart("alternative")
    msg["Subject"] = subject
    msg["From"] = MAIL_FROM
    msg["To"] = to_email
    msg.attach(MIMEText(text_body, "plain", "utf-8"))
    msg.attach(MIMEText(html_body, "html", "utf-8"))

    with smtplib.SMTP_SSL(SMTP_HOST, SMTP_PORT) as server:
        server.login(SMTP_USER, SMTP_PASSWORD)
        server.sendmail(MAIL_FROM, [to_email], msg.as_string())

def send_verification_email(to_email: str, token: str) -> None:
    if not SMTP_HOST or not SMTP_USER or not SMTP_PASSWORD:
        raise RuntimeError("Configurazione SMTP incompleta")

    verify_link = f"{build_frontend_url('verify-email.html')}?token={token}"

    subject = "Verifica il tuo account SynthONO"

    text_body = f"""
Benvenuto su SynthONO.

Per attivare il tuo account, apri questo link:
{verify_link}

Se non hai richiesto tu la registrazione, puoi ignorare questa email.
""".strip()

    html_body = f"""
<html>
  <body style="font-family: Arial, sans-serif; color: #222; line-height: 1.6;">
    <h2 style="color: #2c6fbb;">Verifica il tuo account</h2>
    <p>Benvenuto su SynthONO.</p>
    <p>Per attivare il tuo account, clicca qui:</p>
    <p>
      <a href="{verify_link}" style="display:inline-block;padding:12px 18px;background:#2c6fbb;color:#ffffff;text-decoration:none;border-radius:8px;">
        Verifica account
      </a>
    </p>
    <p>Se il pulsante non funziona, copia e incolla questo link nel browser:</p>
    <p>{verify_link}</p>
    <p>Se non hai richiesto tu la registrazione, puoi ignorare questa email.</p>
  </body>
</html>
""".strip()

    msg = MIMEMultipart("alternative")
    msg["Subject"] = subject
    msg["From"] = MAIL_FROM
    msg["To"] = to_email

    msg.attach(MIMEText(text_body, "plain", "utf-8"))
    msg.attach(MIMEText(html_body, "html", "utf-8"))

    with smtplib.SMTP_SSL(SMTP_HOST, SMTP_PORT) as server:
        server.login(SMTP_USER, SMTP_PASSWORD)
        server.sendmail(MAIL_FROM, [to_email], msg.as_string())

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

def get_verified_user(user: dict = Depends(get_current_user)) -> dict:
    try:
        with engine.connect() as conn:
            result = conn.execute(
                text("""
                    SELECT id, email, is_verified
                    FROM users
                    WHERE id = :user_id
                """),
                {"user_id": user["user_id"]},
            )
            db_user = result.mappings().first()

        if not db_user:
            raise HTTPException(status_code=401, detail="Utente non trovato")

        if not db_user["is_verified"]:
            raise HTTPException(
                status_code=403,
                detail="Devi verificare la tua email prima di usare l'app"
            )

        return user

    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Errore interno: {str(e)}")

def get_plan_config_from_price_id(price_id: str) -> tuple[str, int]:
    if price_id == STRIPE_START_PRICE_ID:
        return "start", 20
    if price_id == STRIPE_PRO_PRICE_ID:
        return "pro", 60
    return "free", 2


def ts_to_datetime(ts):
    if not ts:
        return None
    return datetime.fromtimestamp(ts, timezone.utc)

def stripe_field(obj, key, default=None):
    return obj[key] if obj and key in obj else default
    
def get_effective_subscription_status(subscription) -> str:
    status = stripe_field(subscription, "status", "unknown")
    cancel_at_period_end = stripe_field(subscription, "cancel_at_period_end", False)

    if cancel_at_period_end:
        return "cancel_at_period_end"

    return status

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

    verify_token = create_email_verification_token(user["email"])
    send_verification_email(user["email"], verify_token)

    return {
        "message": "Registrazione completata. Controlla la tua email per verificare l'account.",
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
                    SELECT id, email, password_hash, created_at, is_verified
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

    if not user["is_verified"]:
        raise HTTPException(
            status_code=403,
            detail="Devi verificare la tua email prima di accedere"
            )

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
            expires_at = datetime.now(timezone.utc) + timedelta(hours=1)

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

            send_reset_email(user["email"], token)

    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Errore interno: {str(e)}")

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
        now = datetime.now(timezone.utc)

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


@app.post("/auth/verify-email")
def verify_email(payload: VerifyEmailRequest):
    token = payload.token

    try:
        token_data = decode_email_verification_token(token)
        email = token_data["email"].strip().lower()
    except Exception:
        raise HTTPException(status_code=400, detail="Token non valido")

    try:
        with engine.begin() as conn:
            result = conn.execute(
                text("""
                    UPDATE users
                    SET is_verified = TRUE,
                        verified_at = NOW()
                    WHERE email = :email
                    RETURNING id, email, is_verified, verified_at
                """),
                {"email": email},
            )
            user = result.mappings().first()

        if not user:
            raise HTTPException(status_code=404, detail="Utente non trovato")

        return {"message": "Email verificata con successo"}

    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Errore interno: {str(e)}")

@app.post("/auth/change-password")
def change_password(payload: ChangePasswordRequest, user: dict = Depends(get_verified_user)):
    current_password = payload.current_password
    new_password = payload.new_password

    if len(new_password) < 8:
        raise HTTPException(status_code=400, detail="La nuova password deve avere almeno 8 caratteri")

    if len(new_password) > 200:
        raise HTTPException(status_code=400, detail="La nuova password è troppo lunga")
        
    try:
        with engine.connect() as conn:
            result = conn.execute(
                text("""
                    SELECT id, email, password_hash
                    FROM users
                    WHERE id = :user_id
                """),
                {"user_id": user["user_id"]},
                )
            db_user = result.mappings().first()

        if not db_user:
            raise HTTPException(status_code=404, detail="Utente non trovato")
        
        if not verify_password(current_password, db_user["password_hash"]):
            raise HTTPException(status_code=401, detail="La password attuale non è corretta")

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
                    "user_id": user["user_id"],
                },
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
def auth_me(user: dict = Depends(get_verified_user)):
    return {
        "authenticated": True,
        "user": {
            "id": user["user_id"],
            "email": user["email"],
        },
    }

@app.get("/auth/profile")
def auth_profile(user: dict = Depends(get_verified_user)):
    try:
        with engine.connect() as conn:
            result = conn.execute(
                text("""
                    SELECT
                        u.id,
                        u.email,
                        u.created_at,
                        u.is_verified,
                        u.verified_at,
                        s.plan_name,
                        s.subscription_status,
                        s.usage_limit,
                        s.usage_count,
                        s.stripe_customer_id,
                        s.stripe_subscription_id,
                        s.current_period_start,
                        s.current_period_end
                    FROM users u
                    LEFT JOIN subscriptions s ON s.user_id = u.id
                    WHERE u.id = :user_id
                """),
                {"user_id": user["user_id"]},
            )
            row = result.mappings().first()

        if not row:
            raise HTTPException(status_code=404, detail="Utente non trovato")

        return {
            "user": {
                "id": str(row["id"]),
                "email": row["email"],
                "created_at": str(row["created_at"]),
                "is_verified": bool(row["is_verified"]),
                "verified_at": str(row["verified_at"]) if row["verified_at"] else None,
            },
            "subscription": {
                "plan_name": row["plan_name"] or "free",
                "status": row["subscription_status"] or "inactive",
                "stripe_customer_id": row["stripe_customer_id"],
                "stripe_subscription_id": row["stripe_subscription_id"],
                "current_period_start": str(row["current_period_start"]) if row["current_period_start"] else None,
                "current_period_end": str(row["current_period_end"]) if row["current_period_end"] else None,
            },
            "usage": {
                "analyses_used": row["usage_count"] if row["usage_count"] is not None else 0,
                "analyses_available": row["usage_limit"] if row["usage_limit"] is not None else 0,
                "analyses_remaining": max(
                    (row["usage_limit"] if row["usage_limit"] is not None else 0) -
                    (row["usage_count"] if row["usage_count"] is not None else 0),
                    0
                )
            }
        }

    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Errore interno: {str(e)}")


@app.post("/conversations")
def create_conversation(
    payload: CreateConversationRequest,
    user: dict = Depends(get_verified_user)
):
    title = (payload.title or "Nuova conversazione").strip()
    if not title:
        title = "Nuova conversazione"

    try:
        with engine.begin() as conn:
            result = conn.execute(
                text("""
                    INSERT INTO conversations (user_id, title)
                    VALUES (:user_id, :title)
                    RETURNING id, title, dify_conversation_id, created_at, updated_at, last_message_at
                """),
                {
                    "user_id": user["user_id"],
                    "title": title,
                },
            )
            conversation = result.mappings().first()

        return {
            "conversation": {
                "id": str(conversation["id"]),
                "title": conversation["title"],
                "dify_conversation_id": conversation["dify_conversation_id"],
                "created_at": str(conversation["created_at"]),
                "updated_at": str(conversation["updated_at"]),
                "last_message_at": str(conversation["last_message_at"]),
            }
        }

    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Errore interno: {str(e)}")


@app.get("/conversations")
def list_conversations(user: dict = Depends(get_verified_user)):
    try:
        with engine.connect() as conn:
            result = conn.execute(
                text("""
                    SELECT id, title, dify_conversation_id, created_at, updated_at, last_message_at
                    FROM conversations
                    WHERE user_id = :user_id
                      AND is_archived = FALSE
                    ORDER BY last_message_at DESC
                    LIMIT 8
                """),
                {"user_id": user["user_id"]},
            )
            rows = result.mappings().all()

        return {
            "conversations": [
                {
                    "id": str(row["id"]),
                    "title": row["title"],
                    "dify_conversation_id": row["dify_conversation_id"],
                    "created_at": str(row["created_at"]),
                    "updated_at": str(row["updated_at"]),
                    "last_message_at": str(row["last_message_at"]),
                }
                for row in rows
            ]
        }

    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Errore interno: {str(e)}")


@app.get("/conversations/{conversation_id}/messages")
def get_conversation_messages(
    conversation_id: str,
    user: dict = Depends(get_verified_user)
):
    try:
        with engine.connect() as conn:
            conversation_result = conn.execute(
                text("""
                    SELECT id, title
                    FROM conversations
                    WHERE id = :conversation_id
                      AND user_id = :user_id
                      AND is_archived = FALSE
                """),
                {
                    "conversation_id": conversation_id,
                    "user_id": user["user_id"],
                },
            )
            conversation = conversation_result.mappings().first()

            if not conversation:
                raise HTTPException(status_code=404, detail="Conversazione non trovata")

            messages_result = conn.execute(
                text("""
                    SELECT id, role, content, dify_message_id, created_at
                    FROM messages
                    WHERE conversation_id = :conversation_id
                    ORDER BY created_at ASC
                """),
                {"conversation_id": conversation_id},
            )
            rows = messages_result.mappings().all()

        return {
            "conversation": {
                "id": str(conversation["id"]),
                "title": conversation["title"],
            },
            "messages": [
                {
                    "id": str(row["id"]),
                    "role": row["role"],
                    "content": row["content"],
                    "dify_message_id": row["dify_message_id"],
                    "created_at": str(row["created_at"]),
                }
                for row in rows
            ]
        }

    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Errore interno: {str(e)}")

@app.post("/billing/create-checkout-session")
def create_checkout_session(
    payload: CreateCheckoutSessionRequest,
    user: dict = Depends(get_verified_user)
):
    if not STRIPE_SECRET_KEY:
        raise HTTPException(status_code=500, detail="STRIPE_SECRET_KEY non configurata")

    plan = (payload.plan or "").strip().lower()

    price_map = {
        "start": STRIPE_START_PRICE_ID,
        "pro": STRIPE_PRO_PRICE_ID,
    }

    price_id = price_map.get(plan)

    if not price_id:
        raise HTTPException(status_code=400, detail="Piano non valido")

    try:
        session = stripe.checkout.Session.create(
            mode="subscription",
            line_items=[
                {
                    "price": price_id,
                    "quantity": 1,
                }
            ],
            customer_email=user["email"],
            success_url=f"{APP_BASE_URL}/Test/billing-success.html?session_id={{CHECKOUT_SESSION_ID}}",
            cancel_url=f"{APP_BASE_URL}/Test/billing-cancel.html",
            metadata={
                "user_id": user["user_id"],
                "plan": plan,
            },
        )

        return {
            "checkout_url": session.url
        }

    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Errore creazione checkout Stripe: {str(e)}")

@app.post("/billing/webhook")
async def stripe_webhook(request: Request):
    if not STRIPE_SECRET_KEY:
        raise HTTPException(status_code=500, detail="STRIPE_SECRET_KEY non configurata")

    if not STRIPE_WEBHOOK_SECRET:
        raise HTTPException(status_code=500, detail="STRIPE_WEBHOOK_SECRET non configurata")

    payload = await request.body()
    sig_header = request.headers.get("stripe-signature")

    if not sig_header:
        raise HTTPException(status_code=400, detail="Stripe-Signature mancante")

    try:
        event = stripe.Webhook.construct_event(
            payload=payload,
            sig_header=sig_header,
            secret=STRIPE_WEBHOOK_SECRET,
        )
    except ValueError:
        raise HTTPException(status_code=400, detail="Payload webhook non valido")
    except stripe.error.SignatureVerificationError:
        raise HTTPException(status_code=400, detail="Firma webhook Stripe non valida")

    try:
        event_type = event["type"]
        obj = event["data"]["object"]
        
        print("WEBHOOK STRIPE EVENT:", event_type)
        print("WEBHOOK STRIPE OBJECT:", json.dumps(obj, default=str)[:3000])

        if event_type == "checkout.session.completed":
            if stripe_field(obj, "mode") != "subscription":
                return {"received": True}
            
            metadata = stripe_field(obj, "metadata", {})
            user_id = stripe_field(metadata, "user_id")
            customer_id = stripe_field(obj, "customer")
            subscription_id = stripe_field(obj, "subscription")

            if user_id and customer_id and subscription_id:
                subscription = stripe.Subscription.retrieve(subscription_id)

                price_id = subscription["items"]["data"][0]["price"]["id"]
                plan_name, usage_limit = get_plan_config_from_price_id(price_id)

                with engine.begin() as conn:
                    conn.execute(
                        text("""
                            UPDATE subscriptions
                            SET plan_name = :plan_name,
                                subscription_status = :get_effective_subscription_status(subscription),
                                usage_limit = :usage_limit,
                                usage_count = 0,
                                stripe_customer_id = :stripe_customer_id,
                                stripe_subscription_id = :stripe_subscription_id,
                                current_period_start = :current_period_start,
                                current_period_end = :current_period_end,
                                updated_at = NOW()
                            WHERE user_id = :user_id
                        """),
                        {
                            "plan_name": plan_name,
                            "subscription_status": subscription["status"],
                            "usage_limit": usage_limit,
                            "stripe_customer_id": customer_id,
                            "stripe_subscription_id": subscription_id,
                            "current_period_start": ts_to_datetime(subscription["current_period_start"] if "current_period_start" in subscription else None),
                            "current_period_end": ts_to_datetime(subscription["current_period_end"] if "current_period_end" in subscription else None),
                            "user_id": user_id,
                        },
                    )

        elif event_type == "customer.subscription.updated":
            subscription = obj
            customer_id = stripe_field(subscription, "customer")
            subscription_id = stripe_field(subscription, "id")
            price_id = subscription["items"]["data"][0]["price"]["id"]
            plan_name, usage_limit = get_plan_config_from_price_id(price_id)

            subscription_status = get_effective_subscription_status(subscription)

            with engine.begin() as conn:
                conn.execute(
                    text("""
                        UPDATE subscriptions
                        SET plan_name = :plan_name,
                            subscription_status = :subscription_status,
                            usage_limit = :usage_limit,
                            stripe_customer_id = :stripe_customer_id,
                            stripe_subscription_id = :stripe_subscription_id,
                            current_period_start = :current_period_start,
                            current_period_end = :current_period_end,
                            updated_at = NOW()
                        WHERE stripe_customer_id = :stripe_customer_id
                           OR stripe_subscription_id = :stripe_subscription_id
                    """),
                    {
                        "plan_name": plan_name,
                        "subscription_status": subscription_status,
                        "usage_limit": usage_limit,
                        "stripe_customer_id": customer_id,
                        "stripe_subscription_id": subscription_id,
                        "current_period_start": ts_to_datetime(stripe_field(subscription, "current_period_start")),
                        "current_period_end": ts_to_datetime(stripe_field(subscription, "current_period_end")),
                    },
                )

        elif event_type == "customer.subscription.deleted":
            subscription = obj
            customer_id = stripe_field(subscription, "customer")
            subscription_id = stripe_field(subscription, "id")

            with engine.begin() as conn:
                conn.execute(
                    text("""
                        UPDATE subscriptions
                        SET plan_name = 'free',
                            subscription_status = 'canceled',
                            usage_limit = 2,
                            usage_count = 0,
                            current_period_start = NULL,
                            current_period_end = NULL,
                            updated_at = NOW()
                        WHERE stripe_customer_id = :stripe_customer_id
                           OR stripe_subscription_id = :stripe_subscription_id
                    """),
                    {
                        "stripe_customer_id": customer_id,
                        "stripe_subscription_id": subscription_id,
                    },
                )

        elif event_type == "invoice.paid":
            customer_id = stripe_field(obj, "customer")
            subscription_id = stripe_field(obj, "subscription")

            if customer_id and subscription_id:
                subscription = stripe.Subscription.retrieve(subscription_id)
                price_id = subscription["items"]["data"][0]["price"]["id"]
                plan_name, usage_limit = get_plan_config_from_price_id(price_id)

                with engine.begin() as conn:
                    conn.execute(
                        text("""
                            UPDATE subscriptions
                            SET plan_name = :plan_name,
                                subscription_status = :subscription_status,
                                usage_limit = :usage_limit,
                                usage_count = 0,
                                stripe_customer_id = :stripe_customer_id,
                                stripe_subscription_id = :stripe_subscription_id,
                                current_period_start = :current_period_start,
                                current_period_end = :current_period_end,
                                updated_at = NOW()
                            WHERE stripe_customer_id = :stripe_customer_id
                               OR stripe_subscription_id = :stripe_subscription_id
                        """),
                        {
                            "plan_name": plan_name,
                            "subscription_status": get_effective_subscription_status(subscription),
                            "usage_limit": usage_limit,
                            "stripe_customer_id": customer_id,
                            "stripe_subscription_id": subscription_id,
                            "current_period_start": ts_to_datetime(stripe_field(subscription, "current_period_start")),
                            "current_period_end": ts_to_datetime(stripe_field(subscription, "current_period_end")),
                        },
                    )

        return {"received": True}

    except HTTPException:
        raise
    except Exception as e:
        print("ERRORE WEBHOOK STRIPE:", repr(e))
        traceback.print_exc()
        raise HTTPException(status_code=500, detail=f"Errore webhook Stripe: {str(e)}")

@app.post("/billing/create-portal-session")
def create_portal_session(user: dict = Depends(get_verified_user)):
    if not STRIPE_SECRET_KEY:
        raise HTTPException(status_code=500, detail="STRIPE_SECRET_KEY non configurata")

    try:
        with engine.connect() as conn:
            result = conn.execute(
                text("""
                    SELECT plan_name, stripe_customer_id
                    FROM subscriptions
                    WHERE user_id = :user_id
                """),
                {"user_id": user["user_id"]},
            )
            row = result.mappings().first()

        if not row:
            raise HTTPException(status_code=404, detail="Abbonamento non trovato")

        plan_name = (row["plan_name"] or "free").lower()
        stripe_customer_id = row["stripe_customer_id"]

        if plan_name == "free" or not stripe_customer_id:
            raise HTTPException(status_code=400, detail="Nessun abbonamento attivo da gestire")

        session = stripe.billing_portal.Session.create(
            customer=stripe_customer_id,
            return_url=f"{APP_BASE_URL}/Test/account.html",
        )

        return {
            "portal_url": session.url
        }

    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Errore creazione portale Stripe: {str(e)}")

@app.post("/chat")
async def chat(request: ChatRequest, user: dict = Depends(get_verified_user)):
    if not DIFY_API_KEY:
        raise HTTPException(status_code=500, detail="DIFY_API_KEY non configurata")

    try:
        with engine.connect() as conn:
            usage_result = conn.execute(
                text("""
                    SELECT usage_count, usage_limit
                    FROM subscriptions
                    WHERE user_id = :user_id
                """),
                {"user_id": user["user_id"]},
            )
            usage_row = usage_result.mappings().first()
    
        if not usage_row:
            raise HTTPException(status_code=403, detail="Nessun piano associato all'account")
    
        usage_count = usage_row["usage_count"] or 0
        usage_limit = usage_row["usage_limit"] or 0
    
        if usage_limit > 0 and usage_count >= usage_limit:
            raise HTTPException(
                status_code=402,
                detail="Hai esaurito le analisi disponibili nel tuo piano"
            )
    
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Errore controllo utilizzi: {str(e)}")

    local_conversation_id = (request.conversation_id or "").strip()
    if not local_conversation_id:
        raise HTTPException(status_code=400, detail="conversation_id mancante")

    try:
        with engine.connect() as conn:
            result = conn.execute(
                text("""
                    SELECT id, title, dify_conversation_id
                    FROM conversations
                    WHERE id = :conversation_id
                      AND user_id = :user_id
                      AND is_archived = FALSE
                """),
                {
                    "conversation_id": local_conversation_id,
                    "user_id": user["user_id"],
                },
            )
            conversation = result.mappings().first()

        if not conversation:
            raise HTTPException(status_code=404, detail="Conversazione non trovata")

    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Errore interno: {str(e)}")

    user_message = request.query.strip()
    if not user_message:
        raise HTTPException(status_code=400, detail="Messaggio vuoto")

    try:
        with engine.begin() as conn:
            conn.execute(
                text("""
                    INSERT INTO messages (conversation_id, role, content)
                    VALUES (:conversation_id, 'user', :content)
                """),
                {
                    "conversation_id": local_conversation_id,
                    "content": user_message,
                },
            )

            conn.execute(
                text("""
                    UPDATE conversations
                    SET updated_at = NOW(),
                        last_message_at = NOW()
                    WHERE id = :conversation_id
                """),
                {"conversation_id": local_conversation_id},
            )

    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Errore salvataggio messaggio utente: {str(e)}")

    headers = {
        "Authorization": f"Bearer {DIFY_API_KEY}",
        "Content-Type": "application/json",
        "Accept": "text/event-stream",
    }

    payload = {
        "inputs": {},
        "query": user_message,
        "response_mode": "streaming",
        "conversation_id": conversation["dify_conversation_id"] or "",
        "user": f"user-{user['user_id']}"
    }

    timeout = httpx.Timeout(120.0, connect=20.0)

    async def event_generator():
        import json

        assistant_chunks = []
        dify_conversation_id = conversation["dify_conversation_id"]
        dify_message_id = None

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
                                break

                            try:
                                data = json.loads(raw)
                                event_type = data.get("event")

                                if data.get("conversation_id"):
                                    dify_conversation_id = data.get("conversation_id")

                                if data.get("message_id") and not dify_message_id:
                                    dify_message_id = data.get("message_id")

                                if event_type in ("message", "agent_message"):
                                    answer = data.get("answer", "")
                                    if answer:
                                        assistant_chunks.append(answer)
                                        yield f"data: {json.dumps({'chunk': answer})}\n\n"

                                elif event_type == "message_end":
                                    if data.get("conversation_id"):
                                        dify_conversation_id = data.get("conversation_id")
                                    break

                            except Exception:
                                continue

            assistant_text = "".join(assistant_chunks).strip()

            with engine.begin() as conn:
                conn.execute(
                    text("""
                        UPDATE conversations
                        SET dify_conversation_id = :dify_conversation_id,
                            updated_at = NOW(),
                            last_message_at = NOW()
                        WHERE id = :conversation_id
                    """),
                    {
                        "dify_conversation_id": dify_conversation_id,
                        "conversation_id": local_conversation_id,
                    },
                )
            
                if assistant_text:
                    conn.execute(
                        text("""
                            INSERT INTO messages (conversation_id, role, content, dify_message_id)
                            VALUES (:conversation_id, 'assistant', :content, :dify_message_id)
                        """),
                        {
                            "conversation_id": local_conversation_id,
                            "content": assistant_text,
                            "dify_message_id": dify_message_id,
                        },
                    )
            
                    conn.execute(
                        text("""
                            UPDATE subscriptions
                            SET usage_count = usage_count + 1,
                                updated_at = NOW()
                            WHERE user_id = :user_id
                        """),
                        {
                            "user_id": user["user_id"],
                        },
                    )

            yield "data: [DONE]\n\n"

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
