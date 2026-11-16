#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
自动化测试：并发、幂等窗口、撤销交错、崩溃恢复。

运行：python tests\\run_tests.py  （或 python -m unittest discover -s tests -v）

约定：
* 测试只通过公开 HTTP 接口观察认证结果；
  另用 `server.py check`（只读）核对数据库一致性。
* 崩溃测试用 os._exit 真实终止服务进程（非捕获异常模拟），
  通过进程退出码 + marker 文件确认崩溃点真实到达。
* 时钟通过 --clock-file 注入，30 秒窗口边界无需真实等待。
"""
import http.client
import json
import os
import socket
import subprocess
import sys
import tempfile
import threading
import time
import unittest
import urllib.error
import urllib.request

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SERVER_PY = os.path.join(ROOT, "server.py")
sys.path.insert(0, ROOT)
import server  # noqa: E402  -- 读取 TEST_CLIENTS / TEST_USERS 常量

ALPHA = {"client_id": "client-alpha", "client_secret": server.TEST_CLIENTS["client-alpha"]}
BETA = {"client_id": "client-beta", "client_secret": server.TEST_CLIENTS["client-beta"]}


# ---------------------------------------------------------------------------
# 基础设施
# ---------------------------------------------------------------------------

def free_port() -> int:
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    return port


def http_post(port: int, path: str, payload: dict, timeout: float = 15.0):
    """返回 (status, body)。HTTP 错误状态码也正常返回，不抛异常。"""
    req = urllib.request.Request(
        f"http://127.0.0.1:{port}{path}",
        data=json.dumps(payload).encode("utf-8"),
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            raw = resp.read()
            return resp.status, json.loads(raw) if raw else None
    except urllib.error.HTTPError as exc:
        raw = exc.read()
        return exc.code, json.loads(raw) if raw else None


def wait_ready(port: int, timeout: float = 15.0) -> bool:
    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            with urllib.request.urlopen(f"http://127.0.0.1:{port}/health", timeout=2) as resp:
                if resp.status == 200:
                    return True
        except Exception:
            time.sleep(0.1)
    return False


def run_concurrently(fn, n: int):
    """n 个线程经同一屏障同时出发执行 fn(i)，返回结果列表。"""
    barrier = threading.Barrier(n)
    results = [None] * n

    def worker(i):
        try:
            barrier.wait(timeout=20)
            results[i] = fn(i)
        except Exception as exc:  # noqa: BLE001
            results[i] = exc

    threads = [threading.Thread(target=worker, args=(i,)) for i in range(n)]
    for t in threads:
        t.start()
    for t in threads:
        t.join(timeout=60)
    for r in results:
        if isinstance(r, Exception):
            raise AssertionError(f"worker raised: {r!r}")
        if r is None:
            raise AssertionError("worker did not finish in time")
    return results


class Cluster:
    """4 个独立服务进程共享一个 SQLite 数据库 + 一个注入时钟文件。"""

    def __init__(self, num_servers: int = 4, access_ttl: float = 60.0):
        self.tmp = tempfile.TemporaryDirectory(prefix="sessvc-", ignore_cleanup_errors=True)
        self.db = os.path.join(self.tmp.name, "service.db")
        self.clock_file = os.path.join(self.tmp.name, "clock.txt")
        self.access_ttl = access_ttl
        self._clock = 0.0
        self.set_clock(1_000_000.0)
        subprocess.run(
            [sys.executable, SERVER_PY, "init", "--db", self.db],
            check=True, capture_output=True, text=True,
        )
        self.ports = [free_port() for _ in range(num_servers)]
        self.procs = [self._start_server(p) for p in self.ports]
        for p in self.ports:
            if not wait_ready(p):
                raise RuntimeError(f"server on port {p} did not become ready")

    def _start_server(self, port: int, extra_args=None) -> subprocess.Popen:
        args = [
            sys.executable, SERVER_PY, "serve",
            "--db", self.db,
            "--port", str(port),
            "--clock-file", self.clock_file,
            "--access-ttl", str(self.access_ttl),
        ]
        if extra_args:
            args += extra_args
        return subprocess.Popen(args, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

    def set_clock(self, t: float):
        self._clock = t
        with open(self.clock_file, "w", encoding="utf-8") as fh:
            fh.write(repr(t))

    def post(self, path: str, payload: dict, server_index: int = 0):
        return http_post(self.ports[server_index % len(self.ports)], path, payload)

    def create_session(self, client=ALPHA, user_id="alice", server_index=0) -> dict:
        status, body = self.post("/sessions", {**client, "user_id": user_id}, server_index)
        assert status == 201, f"create session failed: {status} {body}"
        return body

    def check_db(self):
        proc = subprocess.run(
            [sys.executable, SERVER_PY, "check", "--db", self.db],
            capture_output=True, text=True,
        )
        return proc.returncode, (proc.stdout + proc.stderr).strip()

    def stop(self):
        for p in self.procs:
            p.terminate()
        for p in self.procs:
            try:
                p.wait(timeout=10)
            except subprocess.TimeoutExpired:
                p.kill()
        self.tmp.cleanup()


def rid(seed: str) -> str:
    """生成合法的 128 位十六进制 request_id。"""
    return (seed * 32)[:32]


# ---------------------------------------------------------------------------
# 集群测试：4 进程共享 1 个 SQLite
# ---------------------------------------------------------------------------

class ClusterTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.fx = Cluster(num_servers=4, access_ttl=60.0)

    @classmethod
    def tearDownClass(cls):
        cls.fx.stop()

    # 1. 同一请求的并发重试：全部返回同一令牌对，且只轮换一次
    def test_same_request_concurrent_retry(self):
        fx = self.fx
        sess = fx.create_session()
        req_id = rid("a1")
        payload = {**ALPHA, "refresh_token": sess["refresh_token"], "request_id": req_id}

        results = run_concurrently(lambda i: fx.post("/sessions/refresh", payload, i), 16)

        for status, body in results:
            self.assertEqual(status, 200, body)
        pairs = {(b["refresh_token"], b["access_token"]) for _, b in results}
        self.assertEqual(len(pairs), 1, f"所有重试必须返回完全相同的令牌对，实际 {len(pairs)} 种")
        rotated = [b for _, b in results if b.get("rotated")]
        self.assertEqual(len(rotated), 1, "并发重试中最多只能发生一次轮换")
        replays = [b for _, b in results if b.get("idempotent_replay")]
        self.assertEqual(len(replays), 15)

        # 新令牌是链上唯一后继，可以继续轮换
        status, body = fx.post(
            "/sessions/refresh",
            {**ALPHA, "refresh_token": rotated[0]["refresh_token"], "request_id": rid("a2")},
            1,
        )
        self.assertEqual(status, 200, body)
        self.assertTrue(body["rotated"])

        code, out = fx.check_db()
        self.assertEqual(code, 0, out)

    # 2. 不同 request_id 并发争用：最多一次轮换，之后家族被撤销
    def test_different_request_ids_race(self):
        fx = self.fx
        sess = fx.create_session()
        rids = [rid("b1"), rid("b2")]

        def attempt(i):
            return fx.post(
                "/sessions/refresh",
                {**ALPHA, "refresh_token": sess["refresh_token"], "request_id": rids[i % 2]},
                i,
            )

        results = run_concurrently(attempt, 16)
        oks = [b for status, b in results if status == 200]
        conflicts = [b for status, b in results if status == 409]

        self.assertTrue(oks, f"应当恰好有一个 request_id 轮换成功: {results}")
        win_pairs = {(b["refresh_token"], b["access_token"]) for b in oks}
        self.assertEqual(len(win_pairs), 1, "最多只能发生一次轮换")
        self.assertEqual(len({b["request_id"] for b in oks}), 1)
        self.assertTrue(conflicts, "失败的 request_id 必须触发 token_reuse")
        for b in conflicts:
            self.assertEqual(b["error"]["code"], "token_reuse")

        # 胜出的令牌对也随着家族撤销一起失效
        status, body = fx.post("/sessions/validate", {**ALPHA, "access_token": oks[0]["access_token"]})
        self.assertEqual(status, 401)
        self.assertEqual(body["error"]["code"], "family_revoked")
        # 旧的成功缓存不得再返回成功
        status, body = fx.post(
            "/sessions/refresh",
            {**ALPHA, "refresh_token": sess["refresh_token"], "request_id": rids[0]},
        )
        self.assertEqual(status, 401)
        self.assertEqual(body["error"]["code"], "family_revoked")

        code, out = fx.check_db()
        self.assertEqual(code, 0, out)

    # 3. 30 秒幂等窗口边界（注入时钟，无需真实等待）
    def test_idempotency_window_boundary(self):
        fx = self.fx
        fx.set_clock(2_000_000.0)
        sess = fx.create_session()
        req_id = rid("c1")
        payload = {**ALPHA, "refresh_token": sess["refresh_token"], "request_id": req_id}

        status, first = fx.post("/sessions/refresh", payload)
        self.assertEqual(status, 200, first)
        pair = (first["refresh_token"], first["access_token"])

        # 窗口内（含恰好 30.0 秒边界）：返回同一令牌对，不再轮换
        for offset in (15.0, 29.999, 30.0):
            fx.set_clock(2_000_000.0 + offset)
            status, body = fx.post("/sessions/refresh", payload)
            self.assertEqual(status, 200, f"offset={offset}: {body}")
            self.assertEqual((body["refresh_token"], body["access_token"]), pair)
            self.assertTrue(body["idempotent_replay"])

        # 超过窗口：判定重放，原子撤销整个家族
        fx.set_clock(2_000_000.0 + 30.001)
        status, body = fx.post("/sessions/refresh", payload)
        self.assertEqual(status, 409)
        self.assertEqual(body["error"]["code"], "token_reuse")

        # 家族撤销后，即使把时钟拨回窗口内，旧缓存也不得再成功
        fx.set_clock(2_000_000.0 + 1.0)
        status, body = fx.post("/sessions/refresh", payload)
        self.assertEqual(status, 401)
        self.assertEqual(body["error"]["code"], "family_revoked")
        status, body = fx.post("/sessions/validate", {**ALPHA, "access_token": pair[1]})
        self.assertEqual(status, 401)
        self.assertEqual(body["error"]["code"], "family_revoked")

        code, out = fx.check_db()
        self.assertEqual(code, 0, out)

    # 4. 退出与刷新交错：无论谁先提交，最终家族必须撤销、缓存不得复活
    def test_logout_and_refresh_interleave(self):
        fx = self.fx
        sess = fx.create_session()
        req_id = rid("d1")

        def attempt(i):
            if i % 2 == 0:
                return fx.post("/sessions/logout",
                               {**ALPHA, "refresh_token": sess["refresh_token"]}, i)
            return fx.post("/sessions/refresh",
                           {**ALPHA, "refresh_token": sess["refresh_token"], "request_id": req_id}, i)

        results = run_concurrently(attempt, 8)
        logouts = [b for status, b in results if status == 204]
        refresh_ok = [b for status, b in results if status == 200]
        refresh_denied = [b for status, b in results if status == 401]

        self.assertEqual(len(logouts), 4, "退出是幂等的，4 次都应返回 204")
        self.assertEqual(len(refresh_ok) + len(refresh_denied), 4)
        for b in refresh_denied:
            self.assertEqual(b["error"]["code"], "family_revoked")
        if refresh_ok:
            pairs = {(b["refresh_token"], b["access_token"]) for b in refresh_ok}
            self.assertEqual(len(pairs), 1, "交错中最多一次轮换，重试必须拿到同一令牌对")

        # 交错结束后：任何已发出的访问令牌都必须被拒绝
        latest_access = refresh_ok[0]["access_token"] if refresh_ok else sess["access_token"]
        status, body = fx.post("/sessions/validate", {**ALPHA, "access_token": latest_access})
        self.assertEqual(status, 401)
        self.assertEqual(body["error"]["code"], "family_revoked")
        # 即使刷新曾成功，退出撤销后其幂等缓存也不得再返回成功
        status, body = fx.post(
            "/sessions/refresh",
            {**ALPHA, "refresh_token": sess["refresh_token"], "request_id": req_id},
        )
        self.assertEqual(status, 401)
        self.assertEqual(body["error"]["code"], "family_revoked")

        code, out = fx.check_db()
        self.assertEqual(code, 0, out)

    # 5. 旧幂等缓存与家族撤销交错：缓存在家族撤销后必须失效
    def test_cached_success_dies_with_family(self):
        fx = self.fx
        sess = fx.create_session()
        req_id = rid("e1")
        payload = {**ALPHA, "refresh_token": sess["refresh_token"], "request_id": req_id}

        status, first = fx.post("/sessions/refresh", payload)
        self.assertEqual(status, 200, first)
        status, replay = fx.post("/sessions/refresh", payload)
        self.assertEqual(status, 200)
        self.assertEqual(replay["refresh_token"], first["refresh_token"], "撤销前缓存可用")

        # 换一个 request_id 重放旧令牌 → 撤销整个家族
        status, body = fx.post(
            "/sessions/refresh",
            {**ALPHA, "refresh_token": sess["refresh_token"], "request_id": rid("e2")},
        )
        self.assertEqual(status, 409)
        self.assertEqual(body["error"]["code"], "token_reuse")

        # 旧的幂等缓存不得再返回成功
        status, body = fx.post("/sessions/refresh", payload)
        self.assertEqual(status, 401)
        self.assertEqual(body["error"]["code"], "family_revoked")
        status, body = fx.post("/sessions/validate",
                               {**ALPHA, "access_token": first["access_token"]})
        self.assertEqual(status, 401)

        code, out = fx.check_db()
        self.assertEqual(code, 0, out)

    # 6. 伪造令牌/错误凭据不能误伤他人会话
    def test_forged_token_causes_no_collateral_damage(self):
        fx = self.fx
        sess = fx.create_session()

        status, body = fx.post("/sessions/refresh",
                               {**ALPHA, "refresh_token": "forged-" + "0" * 40,
                                "request_id": rid("f1")})
        self.assertEqual(status, 401)
        self.assertEqual(body["error"]["code"], "invalid_token")

        status, body = fx.post("/sessions/refresh",
                               {"client_id": "client-alpha", "client_secret": "wrong-secret",
                                "refresh_token": sess["refresh_token"], "request_id": rid("f1")})
        self.assertEqual(status, 401)
        self.assertEqual(body["error"]["code"], "invalid_client")

        status, body = fx.post("/sessions/refresh",
                               {**ALPHA, "refresh_token": sess["refresh_token"],
                                "request_id": "tooshort"})
        self.assertEqual(status, 400)

        # 合法家族毫发无损：仍可正常轮换与校验
        status, body = fx.post("/sessions/refresh",
                               {**ALPHA, "refresh_token": sess["refresh_token"],
                                "request_id": rid("f1")})
        self.assertEqual(status, 200, body)
        status, vbody = fx.post("/sessions/validate",
                                {**ALPHA, "access_token": body["access_token"]})
        self.assertEqual(status, 200, vbody)

        code, out = fx.check_db()
        self.assertEqual(code, 0, out)

    # 7. 令牌不可跨客户端使用，且跨客户端探测不得撤销对方家族
    def test_tokens_not_usable_across_clients(self):
        fx = self.fx
        sess = fx.create_session(client=ALPHA)

        status, body = fx.post("/sessions/refresh",
                               {**BETA, "refresh_token": sess["refresh_token"],
                                "request_id": rid("a7")})
        self.assertEqual(status, 401)
        self.assertEqual(body["error"]["code"], "invalid_token")
        status, body = fx.post("/sessions/validate",
                               {**BETA, "access_token": sess["access_token"]})
        self.assertEqual(status, 401)
        status, body = fx.post("/sessions/logout",
                               {**BETA, "refresh_token": sess["refresh_token"]})
        self.assertEqual(status, 401)

        # alpha 的家族未被误伤
        status, body = fx.post("/sessions/validate",
                               {**ALPHA, "access_token": sess["access_token"]})
        self.assertEqual(status, 200, body)
        status, body = fx.post("/sessions/refresh",
                               {**ALPHA, "refresh_token": sess["refresh_token"],
                                "request_id": rid("a8")})
        self.assertEqual(status, 200, body)

        code, out = fx.check_db()
        self.assertEqual(code, 0, out)

    # 8. 访问令牌短期有效：过期即拒（注入时钟推进）
    def test_access_token_expiry(self):
        fx = self.fx
        fx.set_clock(3_000_000.0)
        sess = fx.create_session()
        status, body = fx.post("/sessions/validate",
                               {**ALPHA, "access_token": sess["access_token"]})
        self.assertEqual(status, 200, body)
        fx.set_clock(3_000_059.9)
        status, _ = fx.post("/sessions/validate",
                            {**ALPHA, "access_token": sess["access_token"]})
        self.assertEqual(status, 200)
        fx.set_clock(3_000_060.0)
        status, body = fx.post("/sessions/validate",
                               {**ALPHA, "access_token": sess["access_token"]})
        self.assertEqual(status, 401)
        self.assertEqual(body["error"]["code"], "token_expired")


# ---------------------------------------------------------------------------
# 故障测试：在同步点真实杀死进程，重启后重放原请求
# ---------------------------------------------------------------------------

class CrashTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(prefix="sessvc-crash-", ignore_cleanup_errors=True)
        self.db = os.path.join(self.tmp.name, "service.db")
        subprocess.run(
            [sys.executable, SERVER_PY, "init", "--db", self.db],
            check=True, capture_output=True, text=True,
        )
        self.procs = []

    def tearDown(self):
        for p in self.procs:
            if p.poll() is None:
                p.terminate()
                try:
                    p.wait(timeout=10)
                except subprocess.TimeoutExpired:
                    p.kill()
        self.tmp.cleanup()

    def start_server(self, port: int, extra_args=None) -> subprocess.Popen:
        args = [sys.executable, SERVER_PY, "serve", "--db", self.db, "--port", str(port)]
        if extra_args:
            args += extra_args
        proc = subprocess.Popen(args, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        self.procs.append(proc)
        self.assertTrue(wait_ready(port), f"server on port {port} did not start")
        return proc

    def check_db(self):
        proc = subprocess.run(
            [sys.executable, SERVER_PY, "check", "--db", self.db],
            capture_output=True, text=True,
        )
        return proc.returncode, (proc.stdout + proc.stderr).strip()

    def create_session(self, port: int) -> dict:
        status, body = http_post(port, "/sessions", {**ALPHA, "user_id": "alice"})
        self.assertEqual(status, 201, body)
        return body

    # 同步点 1：写入轮换记录但未提交时进程死亡 → 事务必须整体回滚
    def test_crash_after_write_before_commit(self):
        port = free_port()
        req_id = rid("c0")
        marker = os.path.join(self.tmp.name, "marker-pre.txt")
        proc = self.start_server(port, [
            "--crash-point", "pre_commit",
            "--crash-request-id", req_id,
            "--crash-marker", marker,
        ])
        sess = self.create_session(port)

        with self.assertRaises((ConnectionError, OSError, urllib.error.URLError,
                                http.client.HTTPException)):
            http_post(port, "/sessions/refresh",
                      {**ALPHA, "refresh_token": sess["refresh_token"], "request_id": req_id})
        rc = proc.wait(timeout=15)
        self.assertNotEqual(rc, 0, "进程必须真实死亡（非零退出码）")
        with open(marker, encoding="utf-8") as fh:
            self.assertEqual(fh.read(), "pre_commit", "必须真实到达 pre_commit 同步点")

        # 重启（不再带崩溃参数），重放原请求
        self.start_server(port)
        status, body = http_post(port, "/sessions/refresh",
                                 {**ALPHA, "refresh_token": sess["refresh_token"],
                                  "request_id": req_id})
        self.assertEqual(status, 200, body)
        self.assertTrue(body["rotated"], "未提交的写入必须整体回滚，重放按首次轮换处理")

        # 再次重放：命中幂等缓存，返回同一令牌对
        status, replay = http_post(port, "/sessions/refresh",
                                   {**ALPHA, "refresh_token": sess["refresh_token"],
                                    "request_id": req_id})
        self.assertEqual(status, 200)
        self.assertEqual(replay["refresh_token"], body["refresh_token"])
        self.assertEqual(replay["access_token"], body["access_token"])

        # 令牌链无分叉：新令牌可以继续轮换
        status, nxt = http_post(port, "/sessions/refresh",
                                {**ALPHA, "refresh_token": body["refresh_token"],
                                 "request_id": rid("c1")})
        self.assertEqual(status, 200, nxt)
        status, vbody = http_post(port, "/sessions/validate",
                                  {**ALPHA, "access_token": nxt["access_token"]})
        self.assertEqual(status, 200, vbody)

        code, out = self.check_db()
        self.assertEqual(code, 0, out)

    # 同步点 2：提交完成但 HTTP 响应未发出时进程死亡 → 幂等结果不得丢失
    def test_crash_after_commit_before_response(self):
        port = free_port()
        req_id = rid("d0")
        marker = os.path.join(self.tmp.name, "marker-post.txt")
        proc = self.start_server(port, [
            "--crash-point", "post_commit",
            "--crash-request-id", req_id,
            "--crash-marker", marker,
        ])
        sess = self.create_session(port)

        with self.assertRaises((ConnectionError, OSError, urllib.error.URLError,
                                http.client.HTTPException)):
            http_post(port, "/sessions/refresh",
                      {**ALPHA, "refresh_token": sess["refresh_token"], "request_id": req_id})
        rc = proc.wait(timeout=15)
        self.assertNotEqual(rc, 0, "进程必须真实死亡（非零退出码）")
        with open(marker, encoding="utf-8") as fh:
            self.assertEqual(fh.read(), "post_commit", "必须真实到达 post_commit 同步点")

        # 重启，重放原请求：客户端从未见过第一次的响应，
        # 必须从已提交的幂等记录中恢复出同一令牌对，而不是再次轮换或报错。
        self.start_server(port)
        status, body = http_post(port, "/sessions/refresh",
                                 {**ALPHA, "refresh_token": sess["refresh_token"],
                                  "request_id": req_id})
        self.assertEqual(status, 200, body)
        self.assertTrue(body.get("idempotent_replay"),
                        "已提交的幂等结果必须随重放恢复，不得丢失")
        self.assertFalse(body["rotated"])

        # 恢复出的令牌对完全可用
        status, vbody = http_post(port, "/sessions/validate",
                                  {**ALPHA, "access_token": body["access_token"]})
        self.assertEqual(status, 200, vbody)
        # 再次重放仍是同一令牌对
        status, replay = http_post(port, "/sessions/refresh",
                                   {**ALPHA, "refresh_token": sess["refresh_token"],
                                    "request_id": req_id})
        self.assertEqual(status, 200)
        self.assertEqual(replay["refresh_token"], body["refresh_token"])
        # 链上只有一个后继：恢复出的新令牌可以继续轮换
        status, nxt = http_post(port, "/sessions/refresh",
                                {**ALPHA, "refresh_token": body["refresh_token"],
                                 "request_id": rid("d1")})
        self.assertEqual(status, 200, nxt)

        code, out = self.check_db()
        self.assertEqual(code, 0, out)

    # 撤销一旦提交，重启进程也不得复活已撤销家族
    def test_revocation_survives_restart(self):
        port = free_port()
        self.start_server(port)
        sess = self.create_session(port)

        status, first = http_post(port, "/sessions/refresh",
                                  {**ALPHA, "refresh_token": sess["refresh_token"],
                                   "request_id": rid("e0")})
        self.assertEqual(status, 200, first)
        # 换 request_id 重放 → 撤销家族
        status, body = http_post(port, "/sessions/refresh",
                                 {**ALPHA, "refresh_token": sess["refresh_token"],
                                  "request_id": rid("e1")})
        self.assertEqual(status, 409)

        # 杀掉进程并重启
        victim = self.procs[-1]
        victim.terminate()
        victim.wait(timeout=10)
        self.start_server(port)

        # 已撤销家族不得复活：缓存、校验一律拒绝
        status, body = http_post(port, "/sessions/refresh",
                                 {**ALPHA, "refresh_token": sess["refresh_token"],
                                  "request_id": rid("e0")})
        self.assertEqual(status, 401)
        self.assertEqual(body["error"]["code"], "family_revoked")
        status, body = http_post(port, "/sessions/validate",
                                 {**ALPHA, "access_token": first["access_token"]})
        self.assertEqual(status, 401)
        self.assertEqual(body["error"]["code"], "family_revoked")

        code, out = self.check_db()
        self.assertEqual(code, 0, out)


if __name__ == "__main__":
    unittest.main(verbosity=2)
