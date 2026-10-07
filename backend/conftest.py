"""测试夹具：在导入应用模块之前准备好数据库。

优先级：
1. 已设置且可连通的 DATABASE_URL（如 docker compose 内连 db:5432）——直接使用。
2. 本地无外部库时，回退到内嵌 Postgres（pgserver），无需 root / docker。
3. 两者都没有则跳过需要数据库的用例，避免导入期硬失败。

内嵌库依赖仅用于本地测试：`pip install -r requirements-dev.txt`。
"""
import os
import sys
from urllib.parse import parse_qs, urlparse

import psycopg

DEFAULT_DSN = "postgresql://app:app@localhost:54402/pvivscan"


def _reachable(dsn: str) -> bool:
    try:
        with psycopg.connect(dsn, connect_timeout=3) as conn:
            conn.execute("SELECT 1")
        return True
    except Exception:
        return False


def _start_embedded() -> str | None:
    try:
        import pgserver
    except ImportError:
        return None
    server = pgserver.get_server("/tmp/pvivscan_pgtest_data")
    admin = server.get_uri("postgres")
    host = parse_qs(urlparse(admin).query)["host"][0]
    with psycopg.connect(admin, autocommit=True) as conn:
        conn.execute(
            "DO $$ BEGIN "
            "IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname='app') THEN "
            "CREATE ROLE app LOGIN PASSWORD 'app' SUPERUSER; END IF; END $$;"
        )
        if not conn.execute(
            "SELECT 1 FROM pg_database WHERE datname='pvivscan'"
        ).fetchone():
            conn.execute("CREATE DATABASE pvivscan OWNER app")
    return f"postgresql://app:app@/pvivscan?host={host}"


dsn = os.environ.get("DATABASE_URL") or DEFAULT_DSN
if not _reachable(dsn):
    embedded = _start_embedded()
    if embedded is None:
        # 无任何可用 Postgres：跳过依赖数据库的测试模块。
        collect_ignore = ["tests/test_h01.py"]
    else:
        os.environ["DATABASE_URL"] = embedded

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
