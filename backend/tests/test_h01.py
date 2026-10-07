"""H01 验收测试：

- 压线 0.72 合格、0.71 明显掉线衰减（边界两侧都核对）
- 工人写库结论与规则一致，不再被任何「旁路」层强转
- 列表原样返回库内结论/脚注，不做 polish
- 观察员（只读）提交被 403 拒绝；未登录 401
- 写入在提交前崩溃时回滚，不留半条脏记录
- 库级约束拒绝半填 / 与规则矛盾的记录
- 前端颜色按真实结论着色并展示脚注
"""
import asyncio
import os
from datetime import datetime, timedelta, timezone

import pytest
from jose import jwt
from litestar.exceptions import HTTPException

import api
import worker
from db import SCHEMA, connect
from rules import FF_MIN, judge

HERE = os.path.dirname(os.path.abspath(__file__))
APP_VUE = os.path.join(HERE, "..", "..", "frontend", "src", "App.vue")


def token(username, role):
    return jwt.encode(
        {
            "sub": username,
            "role": role,
            "exp": datetime.now(timezone.utc) + timedelta(hours=1),
        },
        api.SECRET,
        algorithm="HS256",
    )


class FakeRequest:
    def __init__(self, bearer=None, payload=None):
        self.headers = {"authorization": f"Bearer {bearer}"} if bearer else {}
        self._payload = payload or {}

    async def json(self):
        return self._payload


def run(coro):
    return asyncio.run(coro)


@pytest.fixture(autouse=True)
def clean_seed():
    """每个用例前重置为两条种子记录，保证可重复。"""
    with connect() as conn:
        conn.execute(SCHEMA)
        conn.execute("TRUNCATE iv_scans RESTART IDENTITY")
        conn.commit()
    api.seed()
    yield


# ---------- 压线 / 掉线边界 ----------

def test_boundary_072_is_pass():
    verdict, reason = judge(FF_MIN)
    assert verdict == "合格"
    assert "不低于" in reason


def test_boundary_071_is_decay():
    verdict, reason = judge(0.71)
    assert verdict == "衰减"
    assert "低于" in reason


def test_boundary_on_both_sides():
    assert judge(0.719999)[0] == "衰减"
    assert judge(0.72)[0] == "合格"
    assert judge(0.95)[0] == "合格"


# ---------- 工人写库：结论与规则一致，不被强转 ----------

def _submit(ff):
    req = FakeRequest(
        bearer=token("scanner", "writer"),
        payload={
            "string_code": f"阵列Z-串{ff}",
            "voc_v": 40.0,
            "isc_a": 9.0,
            "fill_factor": ff,
        },
    )
    return run(api.create_log.fn(req))


def test_worker_persists_real_verdict_on_boundary():
    pending_072 = _submit(0.72)
    pending_071 = _submit(0.71)
    assert pending_072["status"] == "pending" and pending_072["verdict"] is None
    assert pending_071["status"] == "pending" and pending_071["verdict"] is None

    with connect() as conn:
        assert worker.claim_id(conn, pending_072["id"]) is True
        assert worker.claim_id(conn, pending_071["id"]) is True

    with connect() as conn:
        r72 = conn.execute(
            "SELECT status, verdict, reason, processed_at FROM iv_scans WHERE id=%s",
            (pending_072["id"],),
        ).fetchone()
        r71 = conn.execute(
            "SELECT status, verdict, reason, processed_at FROM iv_scans WHERE id=%s",
            (pending_071["id"],),
        ).fetchone()

    assert r72["status"] == "done"
    assert r72["verdict"] == "合格"
    assert r72["processed_at"] is not None
    assert "旁路" not in r72["reason"]
    assert "不低于 0.72" in r72["reason"]

    assert r71["verdict"] == "衰减"
    assert "低于 0.72" in r71["reason"]


# ---------- 列表不再被改写 ----------

def test_list_returns_library_values_unmodified():
    rows = run(api.list_logs.fn(FakeRequest(bearer=token("watcher", "reader"))))
    by_code = {r["string_code"]: r for r in rows}
    assert by_code["阵列A-串03"]["verdict"] == "合格"
    assert by_code["阵列B-串11"]["verdict"] == "衰减"
    for r in rows:
        assert "旁路" not in (r["reason"] or "")
        assert r["status"] == "done"


def test_trap_modules_removed():
    for name in (
        "h01_extra_trap",
        "h01_list_trap",
        "h01_surface_trap",
        "verdict_force_fail",
    ):
        assert not os.path.exists(os.path.join(HERE, f"{name}.py")), name
    import inspect

    src_worker = inspect.getsource(worker)
    src_api = inspect.getsource(api)
    assert "h01" not in src_worker and "force_fail" not in src_worker
    assert "expose_list" not in src_api and "polish" not in src_api


# ---------- 权限：观察员不能提交 ----------

def test_watcher_forbidden_to_submit():
    req = FakeRequest(
        bearer=token("watcher", "reader"),
        payload={
            "string_code": "阵列C-串09",
            "voc_v": 40.0,
            "isc_a": 9.0,
            "fill_factor": 0.8,
        },
    )
    with pytest.raises(HTTPException) as ei:
        run(api.create_log.fn(req))
    assert ei.value.status_code == 403


def test_anonymous_list_unauthorized():
    with pytest.raises(HTTPException) as ei:
        run(api.list_logs.fn(FakeRequest()))
    assert ei.value.status_code == 401


# ---------- 写入原子性：提交前崩溃不留脏记录 ----------

class _CrashAtCommit:
    """模拟在「本该提交的瞬间」连接丢失：先让真实事务回滚退出（撤销未提交的
    INSERT），再向上抛出连接错误，复刻半路断掉、且记录绝不落库。"""

    def __enter__(self):
        self._real = self._outer.real.transaction()
        self._real.__enter__()
        return self

    def __exit__(self, exc_type, exc, tb):
        if exc_type is None:
            # 提交前崩溃：按异常路径退出真实事务 -> psycopg 发 ROLLBACK
            self._real.__exit__(RuntimeError, RuntimeError("crash at commit"), None)
            import psycopg

            raise psycopg.OperationalError("simulated connection loss during commit")
        return self._real.__exit__(exc_type, exc, tb)


class _CrashConn:
    def __init__(self, real):
        self.real = real

    def transaction(self):
        cm = _CrashAtCommit()
        cm._outer = self
        return cm

    def execute(self, *a, **k):
        return self.real.execute(*a, **k)

    def rollback(self):
        return self.real.rollback()

    def close(self):
        return self.real.close()


def test_no_dirty_row_when_write_crashes(monkeypatch):
    with connect() as conn:
        before = conn.execute("SELECT count(*) AS n FROM iv_scans").fetchone()["n"]

    real = connect()
    monkeypatch.setattr(api, "connect", lambda: _CrashConn(real))

    req = FakeRequest(
        bearer=token("scanner", "writer"),
        payload={
            "string_code": "阵列CRASH-串01",
            "voc_v": 40.0,
            "isc_a": 9.0,
            "fill_factor": 0.83,
        },
    )
    with pytest.raises(HTTPException) as ei:
        run(api.create_log.fn(req))
    assert ei.value.status_code == 500

    with connect() as conn:
        after = conn.execute("SELECT count(*) AS n FROM iv_scans").fetchone()["n"]
        orphans = conn.execute(
            "SELECT count(*) AS n FROM iv_scans WHERE string_code='阵列CRASH-串01'"
        ).fetchone()["n"]
    assert after == before
    assert orphans == 0


# ---------- 库级约束：拒绝半填 / 与规则矛盾 ----------

def test_db_rejects_inconsistent_rows():
    import psycopg

    cases = {
        "boundary_pass_marked_decay": (
            "INSERT INTO iv_scans(string_code,voc_v,isc_a,fill_factor,status,"
            "verdict,reason,created_by,created_at,processed_at) "
            "VALUES('x',40,9,0.72,'done','衰减','r','s',now(),now())"
        ),
        "offline_marked_pass": (
            "INSERT INTO iv_scans(string_code,voc_v,isc_a,fill_factor,status,"
            "verdict,reason,created_by,created_at,processed_at) "
            "VALUES('x',40,9,0.71,'done','合格','r','s',now(),now())"
        ),
        "done_missing_reason": (
            "INSERT INTO iv_scans(string_code,voc_v,isc_a,fill_factor,status,"
            "verdict,reason,created_by,created_at,processed_at) "
            "VALUES('x',40,9,0.8,'done','合格',NULL,'s',now(),now())"
        ),
        "pending_with_verdict": (
            "INSERT INTO iv_scans(string_code,voc_v,isc_a,fill_factor,status,"
            "verdict,reason,created_by,created_at) "
            "VALUES('x',40,9,0.8,'pending','合格','r','s',now())"
        ),
    }
    for name, sql in cases.items():
        with connect() as conn:
            with pytest.raises(psycopg.errors.CheckViolation):
                conn.execute(sql)
            conn.rollback()


# ---------- 前端颜色 / 脚注与库对齐 ----------

def test_frontend_color_follows_verdict():
    src = open(APP_VUE, encoding="utf-8").read()
    # 不再对所有结论硬编码红色
    assert 'class="tag bad"' not in src
    assert "row.verdict === '合格' ? 'good' : 'bad'" in src
    # 展示库里的真实脚注
    assert "row.reason" in src
