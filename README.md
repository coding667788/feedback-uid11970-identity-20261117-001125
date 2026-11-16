# 本地登录会话服务：刷新令牌轮换与重放撤销

Windows 原生 Python 3.12 + SQLite，仅标准库，无需 Docker / 外部身份平台 / 认证框架。
任意数量（测试使用 4 个）独立服务进程共享同一个 SQLite 数据库，
正确性完全依赖 SQLite 事务（`BEGIN IMMEDIATE`）与唯一约束，**不使用任何进程内锁**。

## 目录结构

```
server.py            # HTTP 服务 + CLI（init / serve / check）
tests/run_tests.py   # 自动化并发与故障测试（unittest，仅标准库）
README.md            # 本文件
```

## 设计要点

| 机制 | 实现 |
|---|---|
| 令牌家族 | 每次 `POST /sessions` 创建独立 family，所有令牌挂在 family 上 |
| 轮换 | 刷新在**单个事务**内完成：旧令牌标记 `consumed_at` + 新刷新/访问令牌落库 + 幂等记录落库，三者一起提交 |
| 幂等重试 | 键 `(client_id, 旧令牌哈希, request_id)`；首次成功提交后 **30 秒**内相同重试返回完全相同的令牌对，不再轮换 |
| 重放撤销 | 旧令牌已消费但 request_id 不同、或超出 30 秒窗口 → 同事务内原子 `UPDATE families SET revoked=1`，已发出的后继令牌随家族一起失效 |
| 撤销优先 | 刷新/校验都先查 family 撤销状态：家族撤销后，旧的幂等缓存也不得再返回成功 |
| 防分叉 | `UNIQUE(family_id, parent_hash)` 保证同一父令牌最多一个后继（`BEGIN IMMEDIATE` 序列化之外的第二道防线） |
| 客户端身份 | 每个接口都校验预置 `client_id + client_secret`（哈希常量时间比较），不信任请求自报身份；跨客户端使用他人令牌 → 401 且**不撤销**对方家族 |
| 伪造令牌 | 查不到哈希 → 401 `invalid_token`，无任何副作用，不能误伤他人会话 |
| 可注入时钟 | `--clock-file`：服务每次请求从该文件读取当前时间，测试用它覆盖 30 秒窗口边界与访问令牌过期，无需真实等待 |
| 崩溃注入 | `--crash-point pre_commit\|post_commit --crash-request-id <id> --crash-marker <file>`：在指定 request_id 的轮换路径上 `os._exit(1)` **真实终止进程**（非异常模拟），marker 文件证明同步点真实到达 |

`request_id` 要求：32–128 位十六进制字符串（≥128 bit 熵由客户端生成），否则 400。

## 快速开始（Windows）

要求：Windows 10/11，Python 3.12（`py -3.12` 或 `python` 均可）。无第三方依赖。

```bat
REM 1. 初始化：建表 + 写入测试用户与已认证客户端
python server.py init --db data\session.db

REM 2. 启动 4 个独立进程共享同一数据库（开 4 个终端各执行一条）
python server.py serve --db data\session.db --port 8401
python server.py serve --db data\session.db --port 8402
python server.py serve --db data\session.db --port 8403
python server.py serve --db data\session.db --port 8404

REM 3. 只读一致性检查（分叉链 / 撤销后签发 / 消费无后继）
python server.py check --db data\session.db
```

`init` 输出的预置凭据（测试用，硬编码于 `server.py`）：

- 用户：`alice` / `bob` / `carol`
- 客户端：`client-alpha / alpha-secret-7f3d9c2b`，`client-beta / beta-secret-51a8e04d`，
  `client-gamma / gamma-secret-c6b27f93`，`client-delta / delta-secret-98d4e1a6`

### 调用示例（curl）

```bat
REM 创建会话（登录）→ 201
curl -X POST http://127.0.0.1:8401/sessions -H "Content-Type: application/json" ^
  -d "{\"client_id\":\"client-alpha\",\"client_secret\":\"alpha-secret-7f3d9c2b\",\"user_id\":\"alice\"}"

REM 刷新（轮换）→ 200；request_id 为 32 位十六进制
curl -X POST http://127.0.0.1:8401/sessions/refresh -H "Content-Type: application/json" ^
  -d "{\"client_id\":\"client-alpha\",\"client_secret\":\"alpha-secret-7f3d9c2b\",\"refresh_token\":\"<旧刷新令牌>\",\"request_id\":\"aaaaaaaabbbbbbbbccccccccdddddddd\"}"

REM 访问校验 → 200 / 401
curl -X POST http://127.0.0.1:8401/sessions/validate -H "Content-Type: application/json" ^
  -d "{\"client_id\":\"client-alpha\",\"client_secret\":\"alpha-secret-7f3d9c2b\",\"access_token\":\"<访问令牌>\"}"

REM 退出（撤销整个家族）→ 204
curl -X POST http://127.0.0.1:8401/sessions/logout -H "Content-Type: application/json" ^
  -d "{\"client_id\":\"client-alpha\",\"client_secret\":\"alpha-secret-7f3d9c2b\",\"refresh_token\":\"<刷新令牌>\"}"
```

## 接口与状态码

所有接口请求体均为 JSON，且都必须携带预置客户端凭据（`client_id` + `client_secret`）。
错误响应统一为 `{"error": {"code": ..., "message": ...}}`。

| 接口 | 成功 | 错误码（HTTP / code） |
|---|---|---|
| `POST /sessions` | **201** `{family_id, refresh_token, access_token, access_expires_at}` | 400 `bad_request`；400 `unknown_user`；401 `invalid_client` |
| `POST /sessions/refresh` | **200** `{refresh_token, access_token, rotated, ...}`（重试时 `rotated=false, idempotent_replay=true`，令牌对与首次完全相同） | 400 `bad_request`（request_id 非法）；401 `invalid_client` / `invalid_token`（未知、伪造或跨客户端令牌）/ `family_revoked`；**409 `token_reuse`**（旧令牌换 request_id 重放或超 30 秒窗口，家族已原子撤销） |
| `POST /sessions/validate` | **200** `{active:true, user_id, family_id, expires_at}` | 401 `invalid_client` / `invalid_token` / `token_expired` / `family_revoked` |
| `POST /sessions/logout` | **204**（幂等，重复退出仍 204） | 401 `invalid_client` / `invalid_token` |
| `GET /health` | 200 `{status:"ok"}` | — |

语义要点：

- 每次刷新生成新的不可预测刷新令牌（256 bit）与短期访问令牌（默认 60 秒，`--access-ttl` 可调），旧刷新令牌立即失效。
- 访问校验**必须查库核对家族撤销状态**，不是只看令牌自身与过期时间；撤销接口（logout / token_reuse）在事务提交后才返回，返回之后新开始的校验必然读到 `revoked=1` 并拒绝（先提交后响应，顺序可解释）。
- 令牌不可跨用户 / 客户端 / 家族使用：不透明令牌按哈希定位唯一家族，客户端不匹配即 401。

## 运行测试

```bat
python tests\run_tests.py
```

测试自动完成：初始化临时数据库 → 启动 **4 个独立服务进程**共享该库 →
并发/边界/交错/崩溃用例 → 每个用例后用 `check` 命令只读核对数据库 → 清理。
时钟经 `--clock-file` 注入，30 秒窗口边界与令牌过期**不需要真实等待**。
崩溃用例用 `os._exit(1)` 真实杀死服务进程（以进程退出码 + marker 文件确认同步点到达），
重启后重放原请求验证恢复行为——不用捕获异常冒充杀进程，也不打印预期值代替断言。

### 覆盖点

| 测试 | 覆盖要求 |
|---|---|
| `test_same_request_concurrent_retry` | 16 线程跨 4 进程、同令牌同 request_id：全部 200 且**同一令牌对**，恰好 1 次轮换 |
| `test_different_request_ids_race` | 16 线程 2 个 request_id 争用：最多 1 次轮换，败者 409，家族撤销，胜出令牌对一并失效 |
| `test_idempotency_window_boundary` | 注入时钟：29.999s / 30.0s 命中缓存，30.001s 触发 409 撤销；撤销后拨回窗口内缓存也不复活 |
| `test_logout_and_refresh_interleave` | 退出与刷新并发交错：退出幂等 204，刷新至多一次轮换，终态家族必撤销、缓存不复活 |
| `test_cached_success_dies_with_family` | 旧幂等缓存与家族撤销交错：撤销前缓存可用，撤销后同一请求 401 |
| `test_forged_token_causes_no_collateral_damage` | 伪造令牌 / 错误凭据 / 非法 request_id：401/400，合法家族毫发无损 |
| `test_tokens_not_usable_across_clients` | 跨客户端刷新/校验/退出均 401，且不撤销对方家族 |
| `test_access_token_expiry` | 访问令牌短期有效，注入时钟推进后 401 `token_expired` |
| `test_crash_after_write_before_commit` | 同步点 1：写入轮换记录但未提交时杀进程 → 重启重放按首次轮换成功，无分叉链 |
| `test_crash_after_commit_before_response` | 同步点 2：提交后响应前杀进程 → 重启重放从已提交幂等记录恢复同一令牌对，不丢失、不二次轮换 |
| `test_revocation_survives_restart` | 撤销提交后杀进程重启：已撤销家族不复活 |

### 实际测试结果（Windows 11，Python 3.12.8）

```
test_access_token_expiry ... ok
test_cached_success_dies_with_family ... ok
test_different_request_ids_race ... ok
test_forged_token_causes_no_collateral_damage ... ok
test_idempotency_window_boundary ... ok
test_logout_and_refresh_interleave ... ok
test_same_request_concurrent_retry ... ok
test_tokens_not_usable_across_clients ... ok
test_crash_after_commit_before_response ... ok
test_crash_after_write_before_commit ... ok
test_revocation_survives_restart ... ok
----------------------------------------------------------------------
Ran 11 tests in 8.014s

OK
```

## 已知简化（本题为本地测试服务）

- 幂等记录表保存新令牌明文以便原样返回；生产环境应加密存储或改为可重放的派生结构。
- 客户端密钥为 `init` 写入的固定测试值；数据库中只存 SHA-256 哈希。
- 访问令牌为不透明随机串（校验必查库）；如需离线验签可换成 HMAC 签名令牌，但撤销核对仍必须查库。
