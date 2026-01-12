from fastapi import FastAPI, HTTPException, Response
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

def resolve_database_url() -> Optional[str]:
    database_url = os.getenv("DATABASE_URL")
    if database_url:
        return database_url

    prefix = os.getenv("DATABASE_URL_PREFIX")
    if prefix:
        for env_name in (f"{prefix}DATABASE_URL", f"{prefix}_DATABASE_URL"):
            prefixed_url = os.getenv(env_name)
            if prefixed_url:
                logger.info("Usando DATABASE_URL a partir de %s", env_name)
                return prefixed_url

    prefixed_urls = [
        value
        for name, value in os.environ.items()
        if name.endswith("_DATABASE_URL") and value
    ]
    if len(prefixed_urls) == 1:
        logger.info("Usando DATABASE_URL a partir da única *_DATABASE_URL disponível.")
        return prefixed_urls[0]

    return None

app.add_middleware(
    CORSMiddleware,
    allow_origins=allow_origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

@app.get("/favicon.ico")
async def favicon():
    svg_icon = (
        "<svg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 64 64'>"
        "<rect width='64' height='64' rx='12' fill='#2563eb'/>"
        "<path d='M20 44V20h24v6H28v6h14v6H28v6z' fill='#ffffff'/>"
        "</svg>"
    )
    return Response(content=svg_icon, media_type="image/svg+xml")

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
    database_url = resolve_database_url()
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
    logger.info("Entrada /gerar: prompt=%s", data.prompt)
    api_key = os.getenv("OPENAI_API_KEY")
    api_url = os.getenv("OPENAI_API_URL")

    if not api_key:
        logger.error("Erro /gerar: API key não configurada.")
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
    resposta = data["choices"][0]["message"]["content"].strip()
    logger.info("Sucesso /gerar")
    return {
        "resposta": resposta
    }

@app.post("/feedback")
async def enviar_feedback(data: FeedbackRequest):
    logger.info(
        "Entrada /feedback: prompt=%s serie=%s utilidade=%s",
        data.prompt,
        data.serie,
        data.utilidade,
    )
    db_pool = getattr(app.state, "db_pool", None)
    if not db_pool:
        logger.error("Erro /feedback: Banco de dados não configurado.")
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

    logger.info("Sucesso /feedback")
    return {"status": "ok"}
