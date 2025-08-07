from fastapi import FastAPI, HTTPException, Request
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
import httpx
import os
from dotenv import load_dotenv

load_dotenv()

app = FastAPI()

app.add_middleware(
    CORSMiddleware,
    allow_origins=[os.getenv("ALLOW_ORIGINS")],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

class PromptRequest(BaseModel):
    prompt: str

# Rota principal
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

"${data.prompt}"

---

- A resposta deve ser em PORTUGUES BRASILEIRO
- OMITA o início das conversas ("Claro", "aqui está...") e o fim ("este é...").
- DESCREVA bem a atividade. Se possível, adicione contexto e bibliografia.
    """.strip()

    body = {
        "model": "gpt-4",
        "messages": [
            { "role": "system", "content": "Você é um gerador de exercícios pedagógicos para educação infantil." },
            { "role": "user", "content": contexto }
        ],
        "temperature": 0.7
    }

    async with httpx.AsyncClient(timeout=httpx.Timeout(30.0)) as client:
        response = await client.post(api_url, headers=headers, json=body)

    if response.status_code != 200:
        raise HTTPException(status_code=response.status_code, detail=response.text)

    data = response.json()
    return {
        "resposta": data["choices"][0]["message"]["content"].strip()
    }
