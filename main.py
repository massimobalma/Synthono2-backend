import os
import httpx
from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel

app = FastAPI()

# Permetti a tutti di accedere (per semplicità)
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

DIFY_API_KEY = os.getenv("DIFY_API_KEY")
DIFY_BASE_URL = os.getenv("DIFY_BASE_URL", "https://api.dify.ai/v1")

class ChatRequest(BaseModel):
    query: str
    conversation_id: str = ""
    user: str = "user"

@app.post("/chat")
async def chat(request: ChatRequest):
    headers = {"Authorization": f"Bearer {DIFY_API_KEY}", "Content-Type": "application/json"}
    payload = {
        "inputs": {},
        "query": request.query,
        "response_mode": "blocking",
        "conversation_id": request.conversation_id,
        "user": request.user
    }
    async with httpx.AsyncClient() as client:
        resp = await client.post(f"{DIFY_BASE_URL}/chat-messages", json=payload, headers=headers)
        return resp.json()

@app.get("/")
def root():
    return {"message": "Backend attivo"}