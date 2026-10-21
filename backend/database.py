
import os

import psycopg


DATABASE_URL = os.getenv("DATABASE_URL", "")


def conectar():
    if not DATABASE_URL:
        raise RuntimeError(
            "DATABASE_URL não foi configurada."
        )

    return psycopg.connect(
        DATABASE_URL,
        connect_timeout=5
    )


def inicializar_banco():
    with conectar() as conexao:
        with conexao.cursor() as cursor:
            cursor.execute(
                """
                CREATE TABLE IF NOT EXISTS app_installations (
                    id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
                    token_hash CHAR(64) UNIQUE NOT NULL,
                    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
                    revoked_at TIMESTAMPTZ NULL,
                    last_used_at TIMESTAMPTZ NULL
                )
                """
            )
