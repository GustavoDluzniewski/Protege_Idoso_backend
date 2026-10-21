
import os
import httpx

URLHAUS_API_URL = "https://urlhaus-api.abuse.ch/v1/url/"


async def consultar_urlhaus(url: str) -> dict:
    """
    Consulta uma URL no URLhaus.

    Retorna:
    - encontrada: True se a URL estiver listada como maliciosa.
    - encontrada: False se não estiver listada.
    - encontrada: None se não foi possível consultar.
    """

    auth_key = os.getenv("URLHAUS_AUTH_KEY", "").strip()

    if not auth_key:
        return {
            "encontrada": None,
            "status": "erro",
            "mensagem": "Chave do URLhaus não configurada.",
        }

    try:
        async with httpx.AsyncClient(timeout=10.0) as client:
            resposta = await client.post(
                URLHAUS_API_URL,
                data={"url": url},
                headers={"Auth-Key": auth_key},
            )

        if resposta.status_code != 200:
            return {
                "encontrada": None,
                "status": "erro",
                "mensagem": "Falha na consulta ao URLhaus.",
            }

        dados = resposta.json()
        resultado = dados.get("query_status")

        if resultado == "ok":
            return {
                "encontrada": True,
                "status": "encontrada",
                "mensagem": "URL encontrada na base do URLhaus.",
            }

        if resultado == "no_results":
            return {
                "encontrada": False,
                "status": "nao_encontrada",
                "mensagem": "URL não encontrada na base do URLhaus.",
            }

        return {
            "encontrada": None,
            "status": "erro",
            "mensagem": "Resposta inesperada do URLhaus.",
        }

    except (httpx.HTTPError, ValueError):
        return {
            "encontrada": None,
            "status": "erro",
            "mensagem": "Não foi possível consultar o URLhaus.",
        }
