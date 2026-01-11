from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
import asyncpg
import httpx
import os
import logging
from dotenv import load_dotenv
from typing import Literal, Optional

load_dotenv()

app = FastAPI()
logger = logging.getLogger("pedagogia.api")

allow_origins = [
    origin.strip()
    for origin in os.getenv("ALLOW_ORIGINS", "").split(",")
    if origin.strip()
]

app.add_middleware(
    CORSMiddleware,
    allow_origins=allow_origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

class PromptRequest(BaseModel):
    prompt: str

class FeedbackRequest(BaseModel):
    prompt: str
    serie: str
    resposta: str
    utilidade: Literal["util", "nao_util"]
    comentario: Optional[str] = None

@app.on_event("startup")
async def startup():
    database_url = os.getenv("DATABASE_URL")
    if database_url:
        app.state.db_pool = await asyncpg.create_pool(dsn=database_url, min_size=1, max_size=5)
    else:
        app.state.db_pool = None

@app.on_event("shutdown")
async def shutdown():
    db_pool = getattr(app.state, "db_pool", None)
    if db_pool:
        await db_pool.close()

@app.post("/gerar")
async def gerar_exercicio(data: PromptRequest):
    api_key = os.getenv("OPENAI_API_KEY")
    api_url = os.getenv("OPENAI_API_URL")

    if not api_key:
        raise HTTPException(status_code=500, detail="API key não configurada.")

    headers = {
        "Authorization": f"Bearer {api_key}",
        "Content-Type": "application/json"
    }

    contexto = f"""
Você é um assistente especializado em criar exercícios educativos para crianças de Jardim 1, 2 e 1º ano.
Crie um exercício com base no seguinte pedido do professor:

"{data.prompt}"

- A resposta deve ser em PORTUGUES BRASILEIRO
- OMITA o início das conversas e o fim
- DESCREVA bem a atividade, com contexto e bibliografia.
""".strip()

    body = {
        "model": "gpt-4",
        "messages": [
            { "role": "system", "content": "Você é um gerador de exercícios pedagógicos para educação infantil." },
            { "role": "user", "content": contexto }
        ],
        "temperature": 0.7
    }

    try:
        async with httpx.AsyncClient(timeout=httpx.Timeout(30.0)) as client:
            response = await client.post(api_url, headers=headers, json=body)
    except httpx.HTTPError as exc:
        logger.exception("Erro ao chamar OpenAI API")
        raise HTTPException(status_code=502, detail="Falha ao chamar OpenAI API.") from exc

    if response.status_code != 200:
        logger.error(
            "Resposta OpenAI API inesperada: status=%s body=%s",
            response.status_code,
            response.text,
        )
        raise HTTPException(status_code=response.status_code, detail=response.text)

    data = response.json()
    return {
        "resposta": data["choices"][0]["message"]["content"].strip()
    }

@app.post("/feedback")
async def enviar_feedback(data: FeedbackRequest):
    db_pool = getattr(app.state, "db_pool", None)
    if not db_pool:
        raise HTTPException(status_code=500, detail="Banco de dados não configurado.")

    query = """
        insert into feedback (prompt, serie, resposta, utilidade, comentario)
        values ($1, $2, $3, $4, $5)
    """
    try:
        async with db_pool.acquire() as connection:
            await connection.execute(
                query,
                data.prompt,
                data.serie,
                data.resposta,
                data.utilidade,
                data.comentario,
            )
    except asyncpg.PostgresError as exc:
        logger.exception("Erro ao inserir feedback no banco")
        raise HTTPException(status_code=500, detail="Erro ao salvar feedback.") from exc

    return {"status": "ok"}
