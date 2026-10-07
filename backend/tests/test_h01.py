"""H01 回归：结论/脚注/库三层对齐，写入不留半截脏记录，观察员保持只读。

不依赖 PostgreSQL 的用例始终执行；集成用例在库不可达时跳过。
"""
import pathlib
import uuid

import pytest

from rules import FF_MIN, judge

BACKEND = pathlib.Path(__file__).resolve().parents[1]


def _db_up() -> bool:
    try:
        import psycopg

        from db import DSN
        with psycopg.connect(DSN, connect_timeout=2):
            return True
    except Exception:
        return False


requires_db = pytest.mark.skipif(not _db_up(), reason="PostgreSQL 不可达，跳过集成测试")


# ---------- 规则边界：压线 0.72 与明显掉线，两边都要核对 ----------

def test_ff_exactly_at_threshold_is_qualified():
    verdict, reason = judge(0.72)
    assert verdict == "合格"
    assert "0.72" in reason


def test_ff_just_below_threshold_is_degraded():
    verdict, _ = judge(FF_MIN - 1e-9)
    assert verdict == "衰减"


def test_ff_clearly_below_threshold_is_degraded():
    verdict, reason = judge(0.61)
    assert verdict == "衰减"
    assert "0.61" in reason


# ---------- 防陷阱回归：强制衰减/脏记录钩子不得再出现 ----------

def test_no_trap_hooks_left():
    tokens = (
        "h01_", "force_fail", "polish_", "half_dirt",
        "surface_verdict", "surface_reason", "on_claimer_save", "expose_list",
    )
    for name in ("api.py", "worker.py"):
        src = (BACKEND / name).read_text(encoding="utf-8")
        for token in tokens:
            assert token not in src, f"{name} 仍引用 {token}"
    for trap in (
        "h01_extra_trap.py", "h01_list_trap.py",
        "h01_surface_trap.py", "verdict_force_fail.py",
    ):
        assert not (BACKEND / trap).exists(), f"{trap} 应已删除"


# ---------- 集成：库、接口、权限、脏记录 ----------

def _login(client, username, password):
    res = client.post("/api/auth/login", json={"username": username, "password": password})
    assert res.status_code == 201, res.text
    return {"Authorization": f"Bearer {res.json()['access_token']}"}


def _submit(client, headers, code, ff):
    res = client.post(
        "/api/logs",
        json={"string_code": code, "voc_v": 41.2, "isc_a": 9.1, "fill_factor": ff},
        headers=headers,
    )
    assert res.status_code == 201, res.text
    return res.json()["id"]


def _claim(scan_id):
    from db import connect
    from worker import claim_id

    with connect() as conn:
        assert claim_id(conn, scan_id) is True
        conn.commit()


def _db_row(scan_id):
    from db import connect

    with connect() as conn:
        return conn.execute(
            "SELECT status, verdict, reason FROM iv_scans WHERE id = %s", (scan_id,)
        ).fetchone()


def _cleanup(*ids):
    from db import connect

    with connect() as conn:
        conn.execute("DELETE FROM iv_scans WHERE id = ANY(%s)", (list(ids),))
        conn.commit()


@pytest.fixture
def api_client():
    from litestar.testing import TestClient
    from api import app

    return TestClient(app)


@requires_db
@pytest.mark.parametrize(
    "ff, expect_verdict",
    [(0.72, "合格"), (0.78, "合格"), (0.61, "衰减"), (0.719, "衰减")],
)
def test_worker_persists_true_verdict(api_client, ff, expect_verdict):
    """工人落库的结论与脚注必须就是规则判定结果（库这层不再被抛光）。"""
    code = f"测试H01-{uuid.uuid4().hex[:8]}"
    scan_id = _submit(api_client, _login(api_client, "scanner", "scan123456"), code, ff)
    try:
        _claim(scan_id)
        row = _db_row(scan_id)
        assert row["status"] == "done"
        assert row["verdict"] == expect_verdict
        expect_verdict_raw, expect_reason = judge(ff)
        assert row["verdict"] == expect_verdict_raw
        assert row["reason"] == expect_reason
    finally:
        _cleanup(scan_id)


@requires_db
def test_list_api_matches_db_no_dirty_rows(api_client):
    """接口返回必须与库一致：合格不红、脚注不写成衰减、已完成不得伪装成待处理。"""
    headers = _login(api_client, "scanner", "scan123456")
    code = f"测试H01-{uuid.uuid4().hex[:8]}"
    scan_id = _submit(api_client, headers, code, 0.78)
    try:
        _claim(scan_id)
        rows = api_client.get("/api/logs", headers=headers).json()
        row = next(r for r in rows if r["id"] == scan_id)
        assert row["verdict"] == "合格"
        assert row["reason"] == judge(0.78)[1]
        assert row["status"] == "done"
        for row in rows:
            if row["status"] == "done":
                assert row["verdict"] in ("合格", "衰减")
                assert row["reason"]
                assert row["processed_at"]
            else:
                assert row["status"] == "pending"
                assert row["verdict"] is None
                assert row["reason"] is None
    finally:
        _cleanup(scan_id)


@requires_db
def test_watcher_still_cannot_submit(api_client):
    """观察员继续不能交扫描。"""
    headers = _login(api_client, "watcher", "watch123456")
    res = api_client.post(
        "/api/logs",
        json={"string_code": "测试H01-权限", "voc_v": 40.0, "isc_a": 9.0, "fill_factor": 0.8},
        headers=headers,
    )
    assert res.status_code == 403
    rows = api_client.get("/api/logs", headers=headers).json()
    assert all(r["string_code"] != "测试H01-权限" for r in rows)


@requires_db
def test_unauthenticated_cannot_read_or_submit(api_client):
    assert api_client.get("/api/logs").status_code == 401
    res = api_client.post(
        "/api/logs",
        json={"string_code": "X", "voc_v": 1, "isc_a": 1, "fill_factor": 0.8},
    )
    assert res.status_code == 401
