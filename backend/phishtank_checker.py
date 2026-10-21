import base64
import hashlib
import os
import time
import httpx

PHISHTANK_API_URL = os.getenv(
    "PHISHTANK_CHECK_URL",
    "https://checkurl.phishtank.com/checkurl/",
)
PHISHTANK_USER_AGENT = os.getenv(
    "PHISHTANK_USER_AGENT",
    "phishtank/protegeidoso",
)

MAX_URLS_PHISHTANK = 3
CACHE_TTL_SEGUNDOS = 600
CACHE_MAX_ITENS = 500

_cache: dict[str, tuple[float, dict]] = {}


def _verdadeiro(valor) -> bool:
    """A API pode devolver true/false ou 'y'/'yes' conforme o formato."""
    if valor is True:
        return True
    return str(valor).strip().lower() in {"y", "yes", "true", "1"}


def _ler_cache(chave: str):
    item = _cache.get(chave)
    if item is None:
        return None
    criado_em, resultado = item
    if time.monotonic() - criado_em > CACHE_TTL_SEGUNDOS:
        _cache.pop(chave, None)
        return None
    return resultado


def _gravar_cache(chave: str, resultado: dict) -> None:
    if len(_cache) >= CACHE_MAX_ITENS:
        mais_antiga = min(_cache, key=lambda k: _cache[k][0])
        _cache.pop(mais_antiga, None)
    _cache[chave] = (time.monotonic(), resultado)


def _erro(mensagem: str) -> dict:
    return {"encontrada": None, "status": "erro", "mensagem": mensagem}


async def consultar_phishtank(
    url: str,
    client: httpx.AsyncClient | None = None,
) -> dict:
    """
    Consulta uma URL no PhishTank.

    Retorna:
    - encontrada: True se a URL for phishing verificado e válido.
    - encontrada: False se não for phishing confirmado.
    - encontrada: None se não foi possível consultar.

    Não encontrada ou erro NUNCA significam que a URL é segura.
    """

    chave = hashlib.sha256(url.encode("utf-8")).hexdigest()
    em_cache = _ler_cache(chave)
    if em_cache is not None:
        return em_cache

    dados = {
        "url": base64.b64encode(url.encode("utf-8")).decode("ascii"),
        "format": "json",
    }

    app_key = os.getenv("PHISHTANK_APP_KEY", "").strip()
    if app_key:
        dados["app_key"] = app_key

    criou_client = client is None
    if criou_client:
        client = httpx.AsyncClient(timeout=5.0)

    try:
        resposta = await client.post(
            PHISHTANK_API_URL,
            data=dados,
            headers={"User-Agent": PHISHTANK_USER_AGENT},
        )

        if resposta.status_code == 509:
            return _erro("Limite de consultas do PhishTank atingido.")

        if resposta.status_code != 200:
            return _erro("Falha na consulta ao PhishTank.")

        resultados = resposta.json().get("results") or {}

        no_banco = _verdadeiro(resultados.get("in_database"))
        verificada = _verdadeiro(resultados.get("verified"))
        valida = _verdadeiro(resultados.get("valid"))

        if no_banco and verificada and valida:
            resultado = {
                "encontrada": True,
                "status": "encontrada",
                "mensagem": "URL confirmada como phishing no PhishTank.",
            }
        else:
            resultado = {
                "encontrada": False,
                "status": "nao_encontrada",
                "mensagem": "URL sem phishing confirmado no PhishTank.",
            }

        _gravar_cache(chave, resultado)
        return resultado

    except (httpx.HTTPError, ValueError, AttributeError):
        return _erro("Não foi possível consultar o PhishTank.")

    finally:
        if criou_client:
            await client.aclose()