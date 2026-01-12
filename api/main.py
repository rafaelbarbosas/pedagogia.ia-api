from fastapi import FastAPI, HTTPException, Response, Header
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
    """
    <svg width='128' height='128' viewBox='0 0 256 256' fill='none' xmlns='http://www.w3.org/2000/svg'>
    <defs>
        <linearGradient id='bg' x1='36' y1='20' x2='220' y2='236' gradientUnits='userSpaceOnUse'>
        <stop offset='0' stop-color='#3B82F6' />
        <stop offset='0.5' stop-color='#60A5FA' />
        <stop offset='1' stop-color='#F59E0B' />
        </linearGradient>
    </defs>
    <rect x='16' y='16' width='224' height='224' rx='48' fill='url(#bg)' />
    <g fill='#FFFFFF'>
        <path d='M128 60L44 92l84 30 84-30-84-32Z' />
        <path d='M76 116v30c0 6 4 12 10 14l36 12c4 2 8 2 12 0l36-12c6-2 10-8 10-14v-30l-52 18-52-18Z' />
    </g>
    </svg>
    """
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

class RegisterRequest(BaseModel):
    email: str
    senha: str
    nome: str
    endereco: Optional[str] = None
    colegio: Optional[str] = None
    foto_perfil: Optional[str] = None

class VerifyEmailRequest(BaseModel):
    token: str
    tipo: Literal["signup", "invite", "magiclink", "recovery", "email_change"] = "signup"

class LoginRequest(BaseModel):
    email: str
    senha: str

class ChangePasswordRequest(BaseModel):
    access_token: str
    nova_senha: str

class UpdateProfileRequest(BaseModel):
    access_token: str
    nome: Optional[str] = None
    endereco: Optional[str] = None
    colegio: Optional[str] = None
    foto_perfil: Optional[str] = None

class ActivityCreateRequest(BaseModel):
    prompt: str
    atividade_gerada: str
    compartilhar: bool = False

class ActivityUpdateRequest(BaseModel):
    prompt: Optional[str] = None
    atividade_gerada: Optional[str] = None
    compartilhar: Optional[bool] = None

def extract_bearer_token(authorization: Optional[str]) -> str:
    if not authorization:
        raise HTTPException(status_code=401, detail="Token ausente.")
    if not authorization.startswith("Bearer "):
        raise HTTPException(status_code=401, detail="Token inválido.")
    return authorization.removeprefix("Bearer ").strip()

async def get_verified_user(access_token: str) -> dict:
    headers = {"Authorization": f"Bearer {access_token}"}
    user = await supabase_request("GET", "/auth/v1/user", headers=headers)
    user_id = user.get("id")
    if not user_id:
        raise HTTPException(status_code=401, detail="Token inválido.")
    email_verified = bool(user.get("email_confirmed_at") or user.get("confirmed_at"))
    if not email_verified:
        raise HTTPException(status_code=403, detail="Email não verificado.")
    return user

def resolve_supabase_url() -> Optional[str]:
    return os.getenv("SUPABASE_URL")

def resolve_supabase_anon_key() -> Optional[str]:
    return os.getenv("SUPABASE_ANON_KEY")

async def supabase_request(method: str, path: str, *, json: Optional[dict] = None, headers: Optional[dict] = None):
    supabase_url = resolve_supabase_url()
    supabase_key = resolve_supabase_anon_key()
    if not supabase_url or not supabase_key:
        logger.error("Supabase não configurado.")
        raise HTTPException(status_code=500, detail="Supabase não configurado.")

    request_headers = {
        "apikey": supabase_key,
        "Content-Type": "application/json",
    }
    if headers:
        request_headers.update(headers)

    async with httpx.AsyncClient(timeout=httpx.Timeout(30.0)) as client:
        response = await client.request(
            method,
            f"{supabase_url.rstrip('/')}{path}",
            headers=request_headers,
            json=json,
        )

    if response.status_code >= 400:
        logger.error("Erro Supabase: status=%s body=%s", response.status_code, response.text)
        raise HTTPException(status_code=response.status_code, detail=response.text)

    if response.text:
        return response.json()
    return {}

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

@app.post("/auth/register")
async def registrar_usuario(data: RegisterRequest):
    logger.info("Entrada /auth/register: email=%s", data.email)
    payload = {
        "email": data.email,
        "password": data.senha,
        "data": {
            "nome": data.nome,
            "endereco": data.endereco,
            "colegio": data.colegio,
            "foto_perfil": data.foto_perfil,
        },
    }
    response = await supabase_request("POST", "/auth/v1/signup", json=payload)
    logger.info("Sucesso /auth/register")
    return response

@app.post("/auth/verify-email")
async def verificar_email(data: VerifyEmailRequest):
    logger.info("Entrada /auth/verify-email: tipo=%s", data.tipo)
    payload = {
        "token": data.token,
        "type": data.tipo,
    }
    response = await supabase_request("POST", "/auth/v1/verify", json=payload)
    logger.info("Sucesso /auth/verify-email")
    return response

@app.post("/auth/login")
async def login(data: LoginRequest):
    logger.info("Entrada /auth/login: email=%s", data.email)
    payload = {
        "email": data.email,
        "password": data.senha,
    }
    response = await supabase_request("POST", "/auth/v1/token?grant_type=password", json=payload)
    logger.info("Sucesso /auth/login")
    return response

@app.post("/auth/change-password")
async def alterar_senha(data: ChangePasswordRequest):
    logger.info("Entrada /auth/change-password")
    payload = {"password": data.nova_senha}
    headers = {"Authorization": f"Bearer {data.access_token}"}
    response = await supabase_request("PUT", "/auth/v1/user", json=payload, headers=headers)
    logger.info("Sucesso /auth/change-password")
    return response

@app.put("/auth/profile")
async def atualizar_perfil(data: UpdateProfileRequest):
    logger.info("Entrada /auth/profile")
    headers = {"Authorization": f"Bearer {data.access_token}"}
    user = await supabase_request("GET", "/auth/v1/user", headers=headers)
    user_id = user.get("id")
    if not user_id:
        raise HTTPException(status_code=401, detail="Token inválido.")

    updates = {
        "nome": data.nome,
        "endereco": data.endereco,
        "colegio": data.colegio,
        "foto_perfil": data.foto_perfil,
    }
    updates = {key: value for key, value in updates.items() if value is not None}
    if not updates:
        raise HTTPException(status_code=400, detail="Nenhum dado para atualizar.")

    response = await supabase_request(
        "PATCH",
        f"/rest/v1/profiles?id=eq.{user_id}",
        json=updates,
        headers={
            **headers,
            "Prefer": "return=representation",
        },
    )
    logger.info("Sucesso /auth/profile")
    return response

@app.post("/activities")
async def salvar_atividade(
    data: ActivityCreateRequest,
    authorization: Optional[str] = Header(None),
):
    logger.info("Entrada /activities (POST)")
    access_token = extract_bearer_token(authorization)
    user = await get_verified_user(access_token)
    payload = {
        "user_id": user["id"],
        "prompt": data.prompt,
        "atividade_gerada": data.atividade_gerada,
        "compartilhar": data.compartilhar,
    }
    response = await supabase_request(
        "POST",
        "/rest/v1/activities",
        json=payload,
        headers={
            "Authorization": f"Bearer {access_token}",
            "Prefer": "return=representation",
        },
    )
    logger.info("Sucesso /activities (POST)")
    return response[0] if isinstance(response, list) and response else response

@app.get("/activities")
async def listar_atividades(authorization: Optional[str] = Header(None)):
    logger.info("Entrada /activities (GET)")
    access_token = extract_bearer_token(authorization)
    user = await get_verified_user(access_token)
    response = await supabase_request(
        "GET",
        f"/rest/v1/activities?user_id=eq.{user['id']}&order=created_at.desc",
        headers={"Authorization": f"Bearer {access_token}"},
    )
    logger.info("Sucesso /activities (GET)")
    return response

@app.put("/activities/{activity_id}")
async def editar_atividade(
    activity_id: str,
    data: ActivityUpdateRequest,
    authorization: Optional[str] = Header(None),
):
    logger.info("Entrada /activities/%s (PUT)", activity_id)
    access_token = extract_bearer_token(authorization)
    user = await get_verified_user(access_token)
    updates = {
        "prompt": data.prompt,
        "atividade_gerada": data.atividade_gerada,
        "compartilhar": data.compartilhar,
    }
    updates = {key: value for key, value in updates.items() if value is not None}
    if not updates:
        raise HTTPException(status_code=400, detail="Nenhum dado para atualizar.")
    response = await supabase_request(
        "PATCH",
        f"/rest/v1/activities?id=eq.{activity_id}&user_id=eq.{user['id']}",
        json=updates,
        headers={
            "Authorization": f"Bearer {access_token}",
            "Prefer": "return=representation",
        },
    )
    logger.info("Sucesso /activities/%s (PUT)", activity_id)
    return response[0] if isinstance(response, list) and response else response

@app.delete("/activities/{activity_id}")
async def deletar_atividade(
    activity_id: str,
    authorization: Optional[str] = Header(None),
):
    logger.info("Entrada /activities/%s (DELETE)", activity_id)
    access_token = extract_bearer_token(authorization)
    user = await get_verified_user(access_token)
    await supabase_request(
        "DELETE",
        f"/rest/v1/activities?id=eq.{activity_id}&user_id=eq.{user['id']}",
        headers={"Authorization": f"Bearer {access_token}"},
    )
    logger.info("Sucesso /activities/%s (DELETE)", activity_id)
    return {"status": "ok"}
