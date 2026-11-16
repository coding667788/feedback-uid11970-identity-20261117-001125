#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
本地登录会话服务：刷新令牌轮换 + 重放撤销。

设计要点
--------
* 每次创建会话（POST /sessions）生成一个独立的令牌家族 (family)。
* 每次刷新：在同一个 SQLite 事务 (BEGIN IMMEDIATE) 内完成三件事——
  旧刷新令牌标记消费、新刷新令牌 + 短期访问令牌签发、幂等结果记录，
  三者一起提交，绝不出现只持久化一部分的中间态。
* 幂等重试：以 (client_id, 旧令牌哈希, request_id) 为键缓存首次成功结果，
  首次成功提交后 30 秒窗口内的相同重试返回完全相同的令牌对，不再轮换。
* 重放检测：旧令牌已消费，但 request_id 不同、或超出 30 秒窗口，
  在同一事务内原子撤销整个家族（含已发出的后继令牌）。
* 家族一旦撤销，旧的幂等缓存也不得再返回成功（先查家族撤销状态）。
* 多进程正确性完全依赖 SQLite 事务与唯一约束，不使用任何进程内锁。
* 崩溃注入（仅供测试）：--crash-point pre_commit|post_commit 在指定
  request_id 的轮换路径上真实终止进程 (os._exit)，用于故障恢复测试。
"""
from __future__ import annotations

import argparse
import hashlib
import hmac
import json
import os
import secrets
import sqlite3
import sys
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

IDEMPOTENCY_WINDOW_SECONDS = 30.0
DEFAULT_ACCESS_TTL_SECONDS = 60.0
TOKEN_BYTES = 32  # 256 位随机令牌

# 预置测试用户与已认证客户端（由 init 命令写入数据库）
TEST_CLIENTS = {
    "client-alpha": "alpha-secret-7f3d9c2b",
    "client-beta": "beta-secret-51a8e04d",
    "client-gamma": "gamma-secret-c6b27f93",
    "client-delta": "delta-secret-98d4e1a6",
}
TEST_USERS = ["alice", "bob", "carol"]

SCHEMA = """
CREATE TABLE IF NOT EXISTS clients (
    client_id   TEXT PRIMARY KEY,
    secret_hash TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS users (
    user_id TEXT PRIMARY KEY
);
CREATE TABLE IF NOT EXISTS families (
    family_id      TEXT PRIMARY KEY,
    user_id        TEXT NOT NULL REFERENCES users(user_id),
    client_id      TEXT NOT NULL REFERENCES clients(client_id),
    revoked        INTEGER NOT NULL DEFAULT 0,
    revoked_reason TEXT,
    created_at     REAL NOT NULL,
    revoked_at     REAL
);
CREATE TABLE IF NOT EXISTS refresh_tokens (
    token_hash  TEXT PRIMARY KEY,
    family_id   TEXT NOT NULL REFERENCES families(family_id),
    request_id  TEXT,
    parent_hash TEXT,
    issued_at   REAL NOT NULL,
    consumed_at REAL
);
-- 同一父令牌在家族内最多允许一个后继：防分叉令牌链的最后一道约束。
-- SQLite 唯一索引中 NULL 互不相等，初始令牌 (parent_hash=NULL) 不受限。
CREATE UNIQUE INDEX IF NOT EXISTS ux_refresh_one_child
    ON refresh_tokens(family_id, parent_hash);
CREATE TABLE IF NOT EXISTS access_tokens (
    token_hash         TEXT PRIMARY KEY,
    family_id          TEXT NOT NULL REFERENCES families(family_id),
    refresh_token_hash TEXT NOT NULL,
    issued_at          REAL NOT NULL,
    expires_at         REAL NOT NULL
);
CREATE TABLE IF NOT EXISTS idempotency (
    client_id         TEXT NOT NULL,
    old_token_hash    TEXT NOT NULL,
    request_id        TEXT NOT NULL,
    new_refresh_token TEXT NOT NULL,
    new_access_token  TEXT NOT NULL,
    created_at        REAL NOT NULL,
    PRIMARY KEY (client_id, old_token_hash, request_id)
);
"""


def sha256_text(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def err_body(code: str, message: str) -> dict:
    return {"error": {"code": code, "message": message}}


def connect(db_path: str, readonly: bool = False) -> sqlite3.Connection:
    if readonly:
        conn = sqlite3.connect(
            f"file:{db_path}?mode=ro", uri=True, timeout=30, isolation_level=None
        )
    else:
        conn = sqlite3.connect(db_path, timeout=30, isolation_level=None)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA busy_timeout=30000")
    if not readonly:
        conn.execute("PRAGMA journal_mode=WAL")
        conn.execute("PRAGMA foreign_keys=ON")
    return conn


# ---------------------------------------------------------------------------
# 核心业务（全部以数据库事务为一致性边界）
# ---------------------------------------------------------------------------

def create_session(conn, client_id: str, user_id: str, now: float, access_ttl: float):
    row = conn.execute("SELECT user_id FROM users WHERE user_id=?", (user_id,)).fetchone()
    if row is None:
        return 400, err_body("unknown_user", f"user '{user_id}' does not exist")
    family_id = secrets.token_hex(16)
    refresh_token = secrets.token_urlsafe(TOKEN_BYTES)
    access_token = secrets.token_urlsafe(TOKEN_BYTES)
    conn.execute("BEGIN IMMEDIATE")
    try:
        conn.execute(
            "INSERT INTO families (family_id, user_id, client_id, created_at) VALUES (?,?,?,?)",
            (family_id, user_id, client_id, now),
        )
        conn.execute(
            "INSERT INTO refresh_tokens (token_hash, family_id, request_id, parent_hash, issued_at)"
            " VALUES (?,?,?,?,?)",
            (sha256_text(refresh_token), family_id, None, None, now),
        )
        conn.execute(
            "INSERT INTO access_tokens (token_hash, family_id, refresh_token_hash, issued_at, expires_at)"
            " VALUES (?,?,?,?,?)",
            (sha256_text(access_token), family_id, sha256_text(refresh_token), now, now + access_ttl),
        )
        conn.execute("COMMIT")
    except Exception:
        conn.execute("ROLLBACK")
        raise
    return 201, {
        "family_id": family_id,
        "user_id": user_id,
        "refresh_token": refresh_token,
        "access_token": access_token,
        "access_expires_at": now + access_ttl,
    }


def rotate_refresh_token(conn, client_id: str, token: str, request_id: str,
                         now: float, access_ttl: float, hooks):
    """刷新轮换核心。整个状态机在一个 BEGIN IMMEDIATE 事务内推进。"""
    old_hash = sha256_text(token)
    conn.execute("BEGIN IMMEDIATE")
    try:
        row = conn.execute(
            "SELECT * FROM refresh_tokens WHERE token_hash=?", (old_hash,)
        ).fetchone()
        if row is None:
            # 伪造/未知令牌：只拒绝，绝不影响任何真实家族。
            conn.execute("ROLLBACK")
            return 401, err_body("invalid_token", "unknown refresh token")
        fam = conn.execute(
            "SELECT * FROM families WHERE family_id=?", (row["family_id"],)
        ).fetchone()
        if fam["client_id"] != client_id:
            # 跨客户端使用：拒绝但不撤销（避免持有他人令牌的客户端误伤对方）。
            conn.execute("ROLLBACK")
            return 401, err_body("invalid_token", "refresh token does not belong to this client")
        if fam["revoked"]:
            # 家族已撤销：包括幂等缓存在内一律拒绝。
            conn.execute("ROLLBACK")
            return 401, err_body("family_revoked", "token family has been revoked")

        if row["consumed_at"] is None:
            # ---- 首次使用：轮换 ----
            new_refresh = secrets.token_urlsafe(TOKEN_BYTES)
            new_access = secrets.token_urlsafe(TOKEN_BYTES)
            new_refresh_hash = sha256_text(new_refresh)
            conn.execute(
                "UPDATE refresh_tokens SET consumed_at=? WHERE token_hash=?",
                (now, old_hash),
            )
            conn.execute(
                "INSERT INTO refresh_tokens (token_hash, family_id, request_id, parent_hash, issued_at)"
                " VALUES (?,?,?,?,?)",
                (new_refresh_hash, row["family_id"], request_id, old_hash, now),
            )
            conn.execute(
                "INSERT INTO access_tokens (token_hash, family_id, refresh_token_hash, issued_at, expires_at)"
                " VALUES (?,?,?,?,?)",
                (sha256_text(new_access), row["family_id"], new_refresh_hash, now, now + access_ttl),
            )
            conn.execute(
                "INSERT INTO idempotency (client_id, old_token_hash, request_id,"
                " new_refresh_token, new_access_token, created_at) VALUES (?,?,?,?,?,?)",
                (client_id, old_hash, request_id, new_refresh, new_access, now),
            )
            hooks.before_commit()  # 崩溃注入点 1：已写入轮换记录但未提交
            conn.execute("COMMIT")
            hooks.after_commit()   # 崩溃注入点 2：已提交但 HTTP 响应未发出
            return 200, {
                "family_id": row["family_id"],
                "request_id": request_id,
                "refresh_token": new_refresh,
                "access_token": new_access,
                "access_expires_at": now + access_ttl,
                "rotated": True,
            }

        # ---- 旧令牌已被消费：幂等重试 或 重放撤销 ----
        idem = conn.execute(
            "SELECT * FROM idempotency WHERE client_id=? AND old_token_hash=? AND request_id=?",
            (client_id, old_hash, request_id),
        ).fetchone()
        if idem is not None and now - idem["created_at"] <= IDEMPOTENCY_WINDOW_SECONDS:
            at_hash = sha256_text(idem["new_access_token"])
            at_row = conn.execute(
                "SELECT expires_at FROM access_tokens WHERE token_hash=?", (at_hash,)
            ).fetchone()
            conn.execute("COMMIT")  # 无写入，释放写锁
            return 200, {
                "family_id": row["family_id"],
                "request_id": request_id,
                "refresh_token": idem["new_refresh_token"],
                "access_token": idem["new_access_token"],
                "access_expires_at": at_row["expires_at"] if at_row else None,
                "rotated": False,
                "idempotent_replay": True,
            }
        # request_id 不同，或同一 request_id 但已超出 30 秒窗口：
        # 判定为重放攻击，原子撤销整个家族。
        conn.execute(
            "UPDATE families SET revoked=1, revoked_reason='token_reuse', revoked_at=?"
            " WHERE family_id=?",
            (now, row["family_id"]),
        )
        conn.execute("COMMIT")
        return 409, err_body(
            "token_reuse",
            "refresh token already consumed with a different request_id or outside the"
            " idempotency window; the whole token family has been revoked",
        )
    except Exception:
        try:
            conn.execute("ROLLBACK")
        except sqlite3.Error:
            pass
        raise


def validate_access(conn, client_id: str, token: str, now: float):
    """访问校验：除令牌本身外，必须核对家族的当前撤销状态。"""
    token_hash = sha256_text(token)
    row = conn.execute(
        "SELECT a.expires_at, a.family_id, f.revoked, f.client_id AS fam_client, f.user_id"
        " FROM access_tokens a JOIN families f ON f.family_id = a.family_id"
        " WHERE a.token_hash=?",
        (token_hash,),
    ).fetchone()
    if row is None:
        return 401, err_body("invalid_token", "unknown access token")
    if row["fam_client"] != client_id:
        return 401, err_body("invalid_token", "access token does not belong to this client")
    if row["revoked"]:
        return 401, err_body("family_revoked", "token family has been revoked")
    if now >= row["expires_at"]:
        return 401, err_body("token_expired", "access token has expired")
    return 200, {
        "active": True,
        "user_id": row["user_id"],
        "family_id": row["family_id"],
        "expires_at": row["expires_at"],
    }


def logout(conn, client_id: str, token: str, now: float):
    """退出：撤销整个令牌家族。重复退出是幂等的（仍返回 204）。"""
    token_hash = sha256_text(token)
    conn.execute("BEGIN IMMEDIATE")
    try:
        row = conn.execute(
            "SELECT family_id FROM refresh_tokens WHERE token_hash=?", (token_hash,)
        ).fetchone()
        if row is None:
            conn.execute("ROLLBACK")
            return 401, err_body("invalid_token", "unknown refresh token")
        fam = conn.execute(
            "SELECT * FROM families WHERE family_id=?", (row["family_id"],)
        ).fetchone()
        if fam["client_id"] != client_id:
            conn.execute("ROLLBACK")
            return 401, err_body("invalid_token", "refresh token does not belong to this client")
        if not fam["revoked"]:
            conn.execute(
                "UPDATE families SET revoked=1, revoked_reason='logout', revoked_at=?"
                " WHERE family_id=?",
                (now, fam["family_id"]),
            )
        conn.execute("COMMIT")
        return 204, None
    except Exception:
        try:
            conn.execute("ROLLBACK")
        except sqlite3.Error:
            pass
        raise


# ---------------------------------------------------------------------------
# HTTP 层
# ---------------------------------------------------------------------------

class Config:
    def __init__(self, db_path, clock_file, access_ttl,
                 crash_point, crash_request_id, crash_marker):
        self.db_path = db_path
        self.clock_file = clock_file
        self.access_ttl = access_ttl
        self.crash_point = crash_point
        self.crash_request_id = crash_request_id
        self.crash_marker = crash_marker


def read_clock(cfg: Config) -> float:
    """可注入时钟：配置了 --clock-file 时从文件读取当前时间（测试用）。"""
    if cfg.clock_file:
        try:
            with open(cfg.clock_file, "r", encoding="utf-8") as fh:
                return float(fh.read().strip())
        except (OSError, ValueError):
            pass
    return time.time()


class CrashHooks:
    """测试专用崩溃注入：仅在 request_id 匹配 --crash-request-id 时触发。"""

    def __init__(self, cfg: Config, request_id: str):
        self.cfg = cfg
        self.request_id = request_id

    def _maybe_crash(self, point: str):
        cfg = self.cfg
        if cfg.crash_point == point and self.request_id == cfg.crash_request_id:
            if cfg.crash_marker:
                with open(cfg.crash_marker, "w", encoding="utf-8") as fh:
                    fh.write(point)
            # 真实、立即的进程终止：无清理、无 finally、无异常捕获。
            os._exit(1)

    def before_commit(self):
        self._maybe_crash("pre_commit")

    def after_commit(self):
        self._maybe_crash("post_commit")


class NoHooks:
    def before_commit(self):
        pass

    def after_commit(self):
        pass


def valid_request_id(value) -> bool:
    """request_id 必须是 32..128 位十六进制字符（>=128 bit 熵由客户端保证）。"""
    if not isinstance(value, str) or not (32 <= len(value) <= 128):
        return False
    return all(c in "0123456789abcdefABCDEF" for c in value)


def authenticate(conn, body: dict):
    """客户端身份只能来自预置凭据校验，不能相信请求自报的 client_id。"""
    client_id = body.get("client_id")
    secret = body.get("client_secret")
    if not isinstance(client_id, str) or not isinstance(secret, str):
        return None
    row = conn.execute(
        "SELECT * FROM clients WHERE client_id=?", (client_id,)
    ).fetchone()
    if row is None:
        return None
    if not hmac.compare_digest(row["secret_hash"], sha256_text(secret)):
        return None
    return row


class Handler(BaseHTTPRequestHandler):
    server_version = "SessionService/1.0"

    def log_message(self, fmt, *args):  # 保持安静，避免子进程管道阻塞
        pass

    # -- 工具 --
    def _read_json(self) -> dict:
        length = int(self.headers.get("Content-Length") or 0)
        raw = self.rfile.read(length) if length else b""
        try:
            body = json.loads(raw.decode("utf-8")) if raw else {}
        except (UnicodeDecodeError, json.JSONDecodeError):
            raise ValueError("invalid JSON")
        if not isinstance(body, dict):
            raise ValueError("JSON body must be an object")
        return body

    def _respond(self, status: int, payload):
        body = b"" if payload is None else json.dumps(payload).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        if body:
            self.wfile.write(body)

    # -- 路由 --
    def do_GET(self):
        if self.path == "/health":
            self._respond(200, {"status": "ok"})
        else:
            self._respond(404, err_body("not_found", "unknown endpoint"))

    def do_POST(self):
        try:
            body = self._read_json()
        except ValueError as exc:
            self._respond(400, err_body("bad_request", str(exc)))
            return
        cfg = self.server.cfg
        conn = None
        try:
            conn = connect(cfg.db_path)
            if self.path == "/sessions":
                status, payload = self._create_session(conn, body, cfg)
            elif self.path == "/sessions/refresh":
                status, payload = self._refresh(conn, body, cfg)
            elif self.path == "/sessions/validate":
                status, payload = self._validate(conn, body, cfg)
            elif self.path == "/sessions/logout":
                status, payload = self._logout(conn, body, cfg)
            else:
                status, payload = 404, err_body("not_found", "unknown endpoint")
        except sqlite3.Error as exc:
            status, payload = 500, err_body("internal", f"database error: {exc}")
        finally:
            if conn is not None:
                conn.close()
        self._respond(status, payload)

    # -- 接口 --
    def _create_session(self, conn, body, cfg):
        client = authenticate(conn, body)
        if client is None:
            return 401, err_body("invalid_client", "client authentication failed")
        user_id = body.get("user_id")
        if not isinstance(user_id, str) or not user_id:
            return 400, err_body("bad_request", "user_id is required")
        now = read_clock(cfg)
        return create_session(conn, client["client_id"], user_id, now, cfg.access_ttl)

    def _refresh(self, conn, body, cfg):
        client = authenticate(conn, body)
        if client is None:
            return 401, err_body("invalid_client", "client authentication failed")
        token = body.get("refresh_token")
        request_id = body.get("request_id")
        if not isinstance(token, str) or not token:
            return 400, err_body("bad_request", "refresh_token is required")
        if not valid_request_id(request_id):
            return 400, err_body(
                "bad_request",
                "request_id must be a hex string of 32..128 characters (>=128 bits of entropy)",
            )
        now = read_clock(cfg)
        hooks = CrashHooks(cfg, request_id) if cfg.crash_point else NoHooks()
        return rotate_refresh_token(
            conn, client["client_id"], token, request_id, now, cfg.access_ttl, hooks
        )

    def _validate(self, conn, body, cfg):
        client = authenticate(conn, body)
        if client is None:
            return 401, err_body("invalid_client", "client authentication failed")
        token = body.get("access_token")
        if not isinstance(token, str) or not token:
            return 400, err_body("bad_request", "access_token is required")
        now = read_clock(cfg)
        return validate_access(conn, client["client_id"], token, now)

    def _logout(self, conn, body, cfg):
        client = authenticate(conn, body)
        if client is None:
            return 401, err_body("invalid_client", "client authentication failed")
        token = body.get("refresh_token")
        if not isinstance(token, str) or not token:
            return 400, err_body("bad_request", "refresh_token is required")
        now = read_clock(cfg)
        return logout(conn, client["client_id"], token, now)


# ---------------------------------------------------------------------------
# CLI：init / serve / check
# ---------------------------------------------------------------------------

def cmd_init(args) -> int:
    conn = connect(args.db)
    conn.executescript(SCHEMA)
    for client_id, secret in TEST_CLIENTS.items():
        conn.execute(
            "INSERT INTO clients (client_id, secret_hash) VALUES (?,?)"
            " ON CONFLICT(client_id) DO UPDATE SET secret_hash=excluded.secret_hash",
            (client_id, sha256_text(secret)),
        )
    for user_id in TEST_USERS:
        conn.execute("INSERT OR IGNORE INTO users (user_id) VALUES (?)", (user_id,))
    conn.close()
    print(f"initialized database: {args.db}")
    print("users:")
    for user_id in TEST_USERS:
        print(f"  - {user_id}")
    print("clients (client_id / client_secret):")
    for client_id, secret in TEST_CLIENTS.items():
        print(f"  - {client_id} / {secret}")
    return 0


def cmd_serve(args) -> int:
    if not os.path.exists(args.db):
        print(f"error: database '{args.db}' not found; run 'init' first", file=sys.stderr)
        return 2
    cfg = Config(
        db_path=args.db,
        clock_file=args.clock_file,
        access_ttl=args.access_ttl,
        crash_point=args.crash_point,
        crash_request_id=args.crash_request_id,
        crash_marker=args.crash_marker,
    )
    httpd = ThreadingHTTPServer((args.host, args.port), Handler)
    httpd.cfg = cfg
    print(f"session service listening on {args.host}:{args.port} (db={args.db})", flush=True)
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        pass
    return 0


def cmd_check(args) -> int:
    """只读一致性检查：分叉令牌链、撤销后签发、消费后无后继。"""
    conn = connect(args.db, readonly=True)
    problems = []

    forks = conn.execute(
        "SELECT family_id, parent_hash, COUNT(*) AS c FROM refresh_tokens"
        " WHERE parent_hash IS NOT NULL GROUP BY family_id, parent_hash HAVING c > 1"
    ).fetchall()
    for f in forks:
        problems.append(
            f"forked token chain: family {f['family_id']} parent {f['parent_hash'][:12]}..."
            f" has {f['c']} successors"
        )

    for table in ("refresh_tokens", "access_tokens"):
        late = conn.execute(
            f"SELECT t.token_hash, t.family_id FROM {table} t"
            " JOIN families f ON f.family_id = t.family_id"
            " WHERE f.revoked = 1 AND t.issued_at > f.revoked_at"
        ).fetchall()
        for row in late:
            problems.append(
                f"{table}: token issued after family revocation"
                f" (family {row['family_id']})"
            )

    orphans = conn.execute(
        "SELECT token_hash, family_id FROM refresh_tokens"
        " WHERE consumed_at IS NOT NULL AND token_hash NOT IN"
        " (SELECT parent_hash FROM refresh_tokens WHERE parent_hash IS NOT NULL)"
    ).fetchall()
    for row in orphans:
        problems.append(
            f"consumed refresh token without successor (family {row['family_id']})"
        )

    counts = {}
    for table in ("clients", "users", "families", "refresh_tokens", "access_tokens", "idempotency"):
        counts[table] = conn.execute(f"SELECT COUNT(*) AS c FROM {table}").fetchone()["c"]
    revoked = conn.execute("SELECT COUNT(*) AS c FROM families WHERE revoked=1").fetchone()["c"]
    conn.close()

    summary = (f"families={counts['families']} (revoked={revoked})"
               f" refresh_tokens={counts['refresh_tokens']}"
               f" access_tokens={counts['access_tokens']}"
               f" idempotency={counts['idempotency']}")
    if problems:
        print("CHECK FAILED:")
        for p in problems:
            print(f"  - {p}")
        print(summary)
        return 1
    print(f"CHECK OK: {summary}")
    return 0


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(
        prog="server.py",
        description="Local login session service (refresh-token rotation + replay revocation)",
    )
    sub = parser.add_subparsers(dest="command", required=True)

    p_init = sub.add_parser("init", help="create schema and seed test users/clients")
    p_init.add_argument("--db", required=True, help="SQLite database path")

    p_serve = sub.add_parser("serve", help="run the HTTP service")
    p_serve.add_argument("--db", required=True)
    p_serve.add_argument("--host", default="127.0.0.1")
    p_serve.add_argument("--port", type=int, required=True)
    p_serve.add_argument("--clock-file", default=None,
                         help="injectable clock: read current time (unix seconds) from this file")
    p_serve.add_argument("--access-ttl", type=float, default=DEFAULT_ACCESS_TTL_SECONDS,
                         help="access token lifetime in seconds (default 60)")
    p_serve.add_argument("--crash-point", choices=["pre_commit", "post_commit"], default=None,
                         help="TEST ONLY: kill the process at this point of the rotation path")
    p_serve.add_argument("--crash-request-id", default=None,
                         help="TEST ONLY: only crash when the refresh request_id matches")
    p_serve.add_argument("--crash-marker", default=None,
                         help="TEST ONLY: write the crash point name to this file before dying")

    p_check = sub.add_parser("check", help="read-only consistency check of the database")
    p_check.add_argument("--db", required=True)

    args = parser.parse_args(argv)
    if args.command == "init":
        return cmd_init(args)
    if args.command == "serve":
        return cmd_serve(args)
    if args.command == "check":
        return cmd_check(args)
    return 2


if __name__ == "__main__":
    sys.exit(main())
