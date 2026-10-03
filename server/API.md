# jur10n 服务端 API 契约（v1 / v2）

本文档以 `server/src/server.js` 与 `server/src/crypto.js` 的当前实现为准。除非特别说明，客户端接口的业务 JSON 都在加密包内，HTTP 层看到的不是业务 JSON。

## 1. 协议总览

| 协议 | Endpoint | 密钥 | 支持的 op | 适用范围 |
| --- | --- | --- | --- | --- |
| v1 | `POST /api/v1/client` | 服务器 `MASTER_SECRET` | `verify`、`pull_variables`、`report` | 旧版全局资源/旧客户端 |
| v2 | `POST /api/v2/client/:software_slot` | 指定软件槽的 32 字节软件密钥 | `login`、`heartbeat`、`pull_variables`、`report`、`manifest`、`file_chunk`、`announcement` | 按软件槽隔离的客户端 |

v1 与 v2 是两套实际不同的协议，不是同一接口的两个 URL 别名。v1 不会自动转换为 v2，也不会自动创建 v2 session；v2 也不会读取 v1 的 `device_id` 验证状态。

公开健康检查为 `GET /healthz`，返回 JSON：

```json
{
  "ok": true,
  "service": "jur10n-server",
  "time": "2026-08-29T00:00:00.000Z"
}
```

## 2. 传输与加密格式

### 2.1 HTTP

v1、v2 客户端请求都必须使用：

```http
Content-Type: application/octet-stream
```

服务端按忽略参数后的媒体类型判断，因此 `application/octet-stream; charset=binary` 也会被接受；其他媒体类型会产生加密的 `INVALID_REQUEST`。请求体必须是非空二进制包，包大小上限为 **256 KiB（262144 字节，包含 IV 和认证标签）**。

正常匹配到软件槽的客户端响应的 HTTP 状态通常为 `200`，响应头为 `Content-Type: application/octet-stream`，并设置 `Cache-Control: no-store`。真实业务状态位于响应明文的 `status` 字段中。v2 中不存在的 `software_slot` 在解密前无法选取密钥，因此是未加密的 HTTP `404` JSON：

```json
{"error":"NOT_FOUND"}
```

如果 v2 无法找到可用于加密错误响应的软件密钥，服务端会返回空的 `application/octet-stream` 响应（HTTP `200`）；客户端应将此视为无法解析的服务端错误，而不是成功。

客户端请求按 IP 共用服务端内存中的每分钟限流桶，v1 与 v2 不是各自独立的桶。默认每 IP 每分钟 30 次，可由管理接口调整到 1–10000。限流时仍尽量返回可解密的加密错误，业务状态为 `429`、错误码为 `RATE_LIMITED`。

### 2.2 传输密文包

v1 和 v2 的传输包布局相同，均为：

```text
12 字节随机 IV || ciphertext || 16 字节 AES-GCM authentication tag
```

其中：

- 算法为 AES-256-GCM；
- IV 每次加密随机生成，不能从包中省略；
- tag 位于包末尾，不能并入明文或放在 IV 前；
- `ciphertext` 是 UTF-8 JSON 明文加密后的字节；
- 解密或认证失败不会得到部分明文；
- 传输包与数据库 at-rest 密文的布局不同，不要把 at-rest 格式当作客户端协议。

解密后的请求/响应都必须是 JSON 对象。响应成功格式为：

```json
{
  "ok": true,
  "status": 200,
  "data": {},
  "timestamp": 1730000000000
}
```

响应失败格式为：

```json
{
  "ok": false,
  "status": 401,
  "error": "INVALID_CREDENTIALS",
  "timestamp": 1730000000000
}
```

响应中的 `timestamp` 是服务端生成的当前 Unix 毫秒时间戳；不要把它当作请求回显值。

### 2.3 v1 密钥与 AAD

v1 直接使用服务器环境变量 `MASTER_SECRET` 的原始 32 字节值作为 AES-256-GCM 密钥。环境变量值是能解码为恰好 32 字节的 base64url 字符串。

- 请求 AAD：`jur10n:server:v1:request`
- 响应 AAD：`jur10n:server:v1:response`

AAD 必须作为 AES-GCM 的 authenticated additional data 设置，不能作为密文内容，也不能改写大小写、分隔符或编码。

### 2.4 v2 密钥、`key_version` 与 AAD

每个 `software_slot` 有自己的 32 字节软件密钥和递增的整数版本。管理端生成/轮换密钥时会返回客户端配置；软件密钥是敏感凭据，不能放入公开前端资源、日志或仓库。

v2 请求明文必须包含：

```json
{
  "protocol": "jur10n-client-v2",
  "key_version": 1
}
```

`key_version` 必须是大于等于 1 的安全整数，并且必须与实际解密该请求的密钥版本一致。

由于解密前需要先选密钥，客户端可在请求头或查询参数中提供版本：

```http
X-Key-Version: 1
```

或：

```text
/api/v2/client/demo?key_version=1
```

服务端优先使用请求头，其次使用查询参数；未提供时会按当前 active 密钥版本尝试解密。无论是否提供选择器，包内 `key_version` 都是必需的，且会再次校验。请求和响应使用同一个软件槽、同一个密钥版本，但方向不同的 AAD：

- 请求 AAD：`jur10n:client:v2:{software_slot}:{key_version}:request`
- 响应 AAD：`jur10n:client:v2:{software_slot}:{key_version}:response`

例如软件槽为 `demo`、版本为 `3` 时，请求 AAD 是 `jur10n:client:v2:demo:3:request`。

密钥轮换会撤销旧 active 密钥并撤销该软件槽的现有 v2 sessions；客户端不能继续使用旧 session 或旧密钥假定会被接受。

## 3. v2 客户端接口

### 3.1 Endpoint 与公共请求信封

```http
POST /api/v2/client/:software_slot
```

`software_slot` 必须是小写 slug，格式为：

```text
[a-z0-9][a-z0-9-]{0,62}
```

请求明文的公共字段如下：

| 字段 | 类型 | 要求 |
| --- | --- | --- |
| `protocol` | string | 必须严格为 `jur10n-client-v2` |
| `key_version` | integer | 安全整数，`>= 1`，且与使用的密钥版本相同 |
| `timestamp` | integer | Unix 毫秒；默认允许与服务端相差不超过 60 秒（可由 `CLIENT_TIMESTAMP_WINDOW_MS` 调整，服务端下限为 1 秒） |
| `nonce` | string | 只能含 ASCII 字母、数字、`_`、`-`，长度 16–256 |
| `op` | string | 七个值之一：`login`、`heartbeat`、`pull_variables`、`report`、`manifest`、`file_chunk`、`announcement` |
| `machine_proof` | string | 可选；提供时只能含 ASCII 字母、数字、`_`、`-`，长度 16–256。启用机器校验时必须提供；关闭机器校验时非登录操作可省略 |

每一个 v2 请求（包括 `login`）都应使用新的 nonce。服务端以 `(software_id, nonce)` 去重并保存 5 分钟；已成功提交并保留的请求再次使用相同 nonce 会返回 `REPLAY_DETECTED`。部分 v2 业务处理在事务中完成，业务失败可能回滚 nonce 记录，或在 nonce claim 前就失败；客户端仍不得依赖失败请求可以安全重放，应始终生成新的 nonce。时间戳窗口与 nonce 保留时间是两个独立限制。

所有 v2 请求/响应示例中的 JSON 都是**加密前的明文**。实际发送前必须按照第 2 节打包加密。

### 3.2 `login`：许可证登录并建立 session

请求字段：

```json
{
  "protocol": "jur10n-client-v2",
  "key_version": 1,
  "timestamp": 1730000000000,
  "nonce": "随机且未使用的 nonce",
  "op": "login",
  "code": "JUR-...",
  "machine_proof": "客户端生成的机器证明"
}
```

- `code` 必须为 8–128 个字符，首字符为字母或数字，其余字符只能为字母、数字、`.`、`_`、`:`、`-`；服务端按软件槽查找许可证。
- 软件槽启用 `machineCheck`（默认启用）时，`machine_proof` 必填。服务端不保存原始证明，而是计算以软件密钥为 HMAC 密钥的机器摘要。
- 首次登录会创建该许可证的 v2 binding；如果已经存在 binding，则机器证明必须匹配（启用机器校验时），并按 IP policy 校验。
- `maxDevices` 只在首次建立 binding 时参与设备上限检查。当前 `license_bindings.license_id` 是唯一键，因此当前实现每个 v2 许可证实际上只保存一个 binding；要换绑应由管理端执行 reset-binding，而不是假定可以并存多个 v2 机器 binding。
- 登录成功后创建新的 session，并把登录时刻作为 `last_heartbeat_at`。当前实现允许同一 binding 建立多个 session；许可证的 `maxDevices` 不限制同一 binding 的 session 数量。

成功 `data`：

```json
{
  "sessionToken": "后续请求使用的 session token",
  "sessionId": "session 标识",
  "serverTime": 1730000000000,
  "heartbeatInterval": 300,
  "expiresAt": "2026-09-05T00:00:00.000Z",
  "publicId": "许可证公开标识"
}
```

`sessionToken` 只在此次加密响应中返回；数据库只保存其 HMAC 摘要。`expiresAt` 由软件槽 `sessionTtl` 计算，实际最短 60 秒、最长 30 天；管理端配置的默认值为 7 天。`heartbeatInterval` 是软件槽的 `heartbeatTimeout` 秒数，不是服务端强制客户端必须精确采用的定时器。

### 3.3 已认证请求的公共字段

除 `login`、`announcement` 外的五个业务操作都必须带：

```json
{
  "session_token": "login 返回的 sessionToken",
  "session_id": "login 返回的 sessionId",
  "machine_proof": "启用机器校验时必填"
}
```

`session_id` 可省略，提供时长度必须为 16–128；提供后服务端会同时校验 session ID、软件槽和 token。`session_token` 必须是 16–256 字符的 nonce 字符集。

服务端在执行操作前检查：session 存在且未撤销、未过期、距上次心跳未超过软件槽 `heartbeatTimeout`，并且许可证 binding 存在。除 `heartbeat` 外的已认证操作也会更新 `last_heartbeat_at`，因此实际操作可以作为活动信号；但客户端仍应定期发送 heartbeat。

当 `machineCheck=false` 且省略 `machine_proof` 时，服务端允许省略机器证明，并且不会执行机器摘要比较；若提供了 `machine_proof`，仍必须满足格式校验。

### 3.4 `heartbeat`：保持 session 活跃

请求明文示例：

```json
{
  "protocol": "jur10n-client-v2",
  "key_version": 1,
  "timestamp": 1730000000000,
  "nonce": "新的 nonce",
  "op": "heartbeat",
  "session_token": "...",
  "session_id": "...",
  "machine_proof": "..."
}
```

成功 `data`：

```json
{
  "serverTime": 1730000000000,
  "heartbeatInterval": 300,
  "expiresAt": "2026-09-05T00:00:00.000Z"
}
```

heartbeat 会刷新 `last_heartbeat_at`、binding 的 `last_verified_at`，并在 `ipChangePolicy=update` 时更新 session 中记录的 IP 摘要。它不会把 `expiresAt` 延长到新的 session TTL；session 的绝对过期时间仍保持登录时计算的值。

### 3.5 `pull_variables`：拉取变量增量

请求明文示例：

```json
{
  "protocol": "jur10n-client-v2",
  "key_version": 1,
  "timestamp": 1730000000000,
  "nonce": "新的 nonce",
  "op": "pull_variables",
  "session_token": "...",
  "session_id": "...",
  "machine_proof": "...",
  "since_version": 0
}
```

`since_version` 不是安全整数时服务端按 `0` 处理；省略时也是 `0`。服务端只返回该软件槽中 `enabled=1` 且 `version > since_version` 的变量，按变量 key 排序。

成功 `data`：

```json
{
  "variables": [
    {
      "key": "feature.enabled",
      "value": true,
      "version": 2,
      "updatedAt": "2026-08-29T00:00:00.000Z"
    }
  ],
  "latestVersion": 2
}
```

当没有更新时，`variables` 为空数组，`latestVersion` 保持请求的 `since_version`（或默认值 0）。变量值在服务端数据库中加密保存，解密后以 JSON 值返回，不强制为字符串。

### 3.6 `report`：接收客户端数据

请求明文示例：

```json
{
  "protocol": "jur10n-client-v2",
  "key_version": 1,
  "timestamp": 1730000000000,
  "nonce": "新的 nonce",
  "op": "report",
  "session_token": "...",
  "session_id": "...",
  "machine_proof": "...",
  "data_slot": "telemetry",
  "data": {
    "event": "boot"
  }
}
```

`data_slot` 省略时使用 `legacy`。新建软件会自动创建默认 `legacy` 数据槽。指定值必须匹配小写 slug；数据槽必须存在且启用，否则分别为 `INVALID_DATA_SLOT` 或 `DATA_SLOT_NOT_FOUND`。`mode` 默认为 `overwrite`；显式传 `append` 时对象浅合并、数组拼接、字符串连接，类型不兼容返回 `INVALID_APPEND`。每个单码在每个数据槽只保留一条最终快照，最终 JSON 大小不得超过 200 KiB；数据槽本身没有总容量上限。

成功 `data`：

```json
{
  "id": 123,
  "accepted": true,
  "receivedAt": "2026-08-29T00:00:00.000Z",
  "size": 27,
  "sha256": "数据 JSON UTF-8 序列化后的 SHA-256 十六进制摘要",
  "quotaBytes": 204800,
  "usedBytes": 27
}
```

大小和配额按以下顺序实际检查：

1. `data` 使用 `JSON.stringify(data ?? null)` 后按 UTF-8 字节数计算；不可序列化时为 `INVALID_PAYLOAD`。
2. 全局接收开关必须开启；关闭时为 `RECEIVING_DISABLED`。
3. 单条报告不超过 128 KiB，且不超过全局 `receive_settings.maxPayloadBytes`；超出为 `PAYLOAD_TOO_LARGE`。
4. 同一软件槽 + 数据槽 + 单码的**当前累计存量**（`received` 状态记录总和）不得超过固定的 200 KiB；超出为 `QUOTA_EXCEEDED`。该上限不可配置；管理端删除单条记录会立即释放对应额度。
5. 服务器磁盘可用空间和 inode 低于水位时为 `STORAGE_LIMIT`（默认可用空间水位为 256 MiB，具体还受环境变量影响）。

接收后数据以服务器 at-rest AES-GCM 加密保存至 `data_uploads`，不会把明文报告返回给客户端。`sha256` 计算的是序列化 JSON 的摘要，不是传输密文包的摘要。

### 3.7 `manifest`：获取文件资源清单

请求明文只需使用已认证公共字段并将 `op` 设为 `manifest`：

```json
{
  "protocol": "jur10n-client-v2",
  "key_version": 1,
  "timestamp": 1730000000000,
  "nonce": "新的 nonce",
  "op": "manifest",
  "session_token": "...",
  "session_id": "...",
  "machine_proof": "..."
}
```

服务端返回该软件槽当前全部 `ready` 状态的文件资源（管理端随时可上传/删除，没有版本概念）：

```json
{
  "resources": [
    {
      "id": 20,
      "originalName": "client.bin",
      "sha256": "文件内容的 SHA-256 十六进制摘要",
      "size": 1048576,
      "mime": "application/octet-stream",
      "createdAt": "2026-08-29T00:01:00.000Z"
    }
  ]
}
```

manifest 本身没有下载 URL；客户端应使用 `file_chunk` 按 `id` 读取文件。

### 3.8 `announcement`：免登录读取软件公告

`announcement` 需要正确的软件密钥、`key_version`、时间戳和一次性 nonce，但不需要 `session_token`、机器证明或卡密。请求示例：

```json
{
  "protocol": "jur10n-client-v2",
  "key_version": 1,
  "timestamp": 1730000000000,
  "nonce": "新的 nonce",
  "op": "announcement"
}
```

成功 `data`：

```json
{
  "announcement": "当前版本正在维护，请稍后重试。",
  "updatedAt": "2026-08-29T00:01:00.000Z"
}
```

公告没有业务授权含义；它只用于发布公开信息。每个软件槽位独立保存公告，空公告返回空字符串。nonce 仍会被服务端消费，重复提交同一 nonce 返回 `REPLAY_DETECTED`。

同时提供一个返回 JSON 的公开管理入口：

```text
GET /api/public/software/:software_slot/announcement
```

该公开入口不需要 token，但客户端 SDK 推荐使用加密 `announcement` op，以避免公告内容被中间网络直接读取。

### 3.9 `file_chunk`：分块读取文件资源

请求明文示例：

```json
{
  "protocol": "jur10n-client-v2",
  "key_version": 1,
  "timestamp": 1730000000000,
  "nonce": "新的 nonce",
  "op": "file_chunk",
  "session_token": "...",
  "session_id": "...",
  "machine_proof": "...",
  "file_id": 20,
  "offset": 0,
  "length": 65536
}
```

- `file_id` 必须属于同一软件槽的 `ready` 文件，否则为 `FILE_NOT_FOUND`。
- `offset` 省略时为 0，必须是安全整数、且大于等于 0；必须小于文件大小。
- `length` 省略时为 65536；必须至少为 1。服务端将超过 64 KiB 的请求截断为 64 KiB，而不是返回超大错误。
- 最后一块的实际长度可能小于请求长度；不能假定每块都等长。
- 返回的 `chunk` 是**标准 base64**（不是 base64url）。

成功 `data`：

```json
{
  "fileId": 20,
  "offset": 0,
  "length": 65536,
  "totalSize": 1048576,
  "sha256": "完整文件内容的 SHA-256 十六进制摘要",
  "chunk": "AAECAw...",
  "eof": false
}
```

`eof=true` 表示 `offset + length` 已到文件末尾。客户端应根据 `totalSize`、`offset`、实际 `length` 和完整文件 `sha256` 校验下载结果。

## 4. v2 session、绑定与 IP policy

### 4.1 Session 生命周期

- `announcement` 不需要 `session_token`，但仍需要正确软件密钥、key version、timestamp 和 nonce；其余五个业务操作都需要 session token。

session 会在以下任一条件成立时被拒绝：

- token 不存在或已被撤销：`SESSION_REVOKED`；
- `expiresAt` 已到：`SESSION_EXPIRED`；
- 当前时间距离 `last_heartbeat_at` 超过软件槽 `heartbeatTimeout`：`SESSION_INACTIVE`；
- 缺少 token 或 token 格式不合法：`SESSION_REQUIRED`；
- 找不到许可证 binding：`MACHINE_MISMATCH`。

密钥轮换、密钥撤销、管理端撤销 session、管理端 reset-binding 都会撤销相关 v2 session。心跳只维持活动状态，不改变绝对过期时间。

### 4.2 机器绑定

v2 binding 关联软件槽许可证。启用 `machineCheck` 时，登录和后续认证请求必须携带同一机器证明；服务端实际比较的是：

```text
HMAC-SHA256(software_key, "machine:" + machine_proof)
```

原始 `machine_proof` 不落库。机器证明不等于 v1 的 `device_id`，两者不能互换。

`machineCheck=false` 时，服务端不会比较机器摘要；登录时若没有证明会使用 `unverified` 作为 binding 的机器值，并在后续请求中对缺失证明使用固定的未验证证明字符串。关闭机器校验不等于关闭许可证、session、IP 或报告配额检查。

### 4.3 IP policy

只有软件槽 `ipCheck=true` 时才检查 IP。服务端把客户端 IP 保存为：

```text
HMAC-SHA256(MASTER_SECRET, "ip:" + ip)
```

数据库不保存明文 IP。软件槽的 `ipChangePolicy` 有三个值：

- `deny`：binding 已有 IP 摘要且当前摘要不同则返回 `IP_MISMATCH`；
- `update`：IP 改变时允许通过；登录时会更新 binding 的 IP 摘要，heartbeat 会更新 session 的 IP 摘要；
- `allow`：IP 改变时允许通过，不以 IP 改变为拒绝条件。

如果 binding 没有 IP 摘要，或当前摘要相同，则不因 IP policy 拒绝。服务端使用 Fastify 解析的请求 IP；部署在反向代理后时，代理转发配置会影响该值。

## 5. v1 兼容接口

### 5.1 Endpoint、密文和公共请求

```http
POST /api/v1/client
Content-Type: application/octet-stream
```

v1 使用 `MASTER_SECRET` 直接加密，AAD 为：

- 请求：`jur10n:server:v1:request`
- 响应：`jur10n:server:v1:response`

v1 请求明文：

```json
{
  "timestamp": 1730000000000,
  "nonce": "至少 16 个字符的随机 nonce",
  "op": "verify",
  "code": "JUR-...",
  "device_id": "客户端设备标识",
  "since_version": 0,
  "data": {}
}
```

服务端实际接受的公共校验为：

- `timestamp` 必须是安全整数，和服务端相差不超过 120 秒；
- `nonce` 只能含 ASCII 字母、数字、`_`、`-`，长度 16–256；
- `op` 仅允许 `verify`、`pull_variables`、`report`；
- `device_id` 必须是 1–128 个字符的字符串；
- 每个请求都必须能用 `code` 找到 active、未过期的旧版许可证。

原有实现使用 nonce cache 去重并保存 5 分钟。v1 请求没有 `protocol`、`key_version`、`session_token`、`session_id` 或 `machine_proof` 字段要求；把 v2 envelope 发送到 v1 不会升级协议。

除 v2 不存在软件槽这一特殊情况外，v1 的成功和失败均为 HTTP `200`，由加密响应中的 `ok`、`status`、`error` 表示结果。

### 5.2 v1 `verify`

`verify` 使用 `code + device_id` 建立或更新旧版 `license_devices` 记录，不建立 v2 session，也不使用 v2 machine proof 或 IP policy。

成功 `data`：

```json
{
  "publicId": "许可证公开标识",
  "expiresAt": null,
  "deviceCount": 1,
  "maxDevices": 1
}
```

同一许可证的不同 `device_id` 会占用不同设备名额；超过 `maxDevices` 返回 `DEVICE_LIMIT`。这与 v2 当前每许可证一个 binding 的实现不同。

### 5.3 v1 `pull_variables`

请求必须先以同一许可证、同一 `device_id` 成功 `verify`。`since_version` 为整数时按该值查询，否则按 0 查询。

成功 `data`：

```json
{
  "variables": [
    {
      "key": "feature.enabled",
      "value": true,
      "version": 2,
      "updatedAt": "2026-08-29T00:00:00.000Z"
    }
  ],
  "receiveSettings": {
    "enabled": true,
    "maxPayloadBytes": 131072
  },
  "latestVersion": 2
}
```

v1 读取的是全局旧版 `variables`，不是 v2 的按软件槽 `software_variables`。`receiveSettings` 是 v1 特有的全局接收设置返回值。

### 5.4 v1 `report`

请求必须先完成 v1 `verify`。服务端按 `JSON.stringify(data ?? null)` 的 UTF-8 字节数计算大小，受全局接收开关和最多 128 KiB/`maxPayloadBytes` 限制。

成功 `data`：

```json
{
  "accepted": true,
  "receivedAt": "2026-08-29T00:00:00.000Z",
  "size": 27
}
```

v1 report 写入旧版 `reports` 表；当前 v1 路径不选择 `data_slot`，也不执行 v2 数据槽的滚动 24 小时、永久字节数、记录数配额或磁盘水位检查。报告明文仍在服务端 at-rest 加密保存。

### 5.5 v1 兼容边界

- v1 只支持 `verify`、`pull_variables`、`report`，没有 v2 的 `login`、`heartbeat`、`manifest`、`file_chunk`。
- v1 使用全局 `MASTER_SECRET`，v2 使用软件槽密钥；密钥不能混用。
- v1 的 `verify` 是 `device_id` 绑定；v2 是 session + machine binding；v1 验证成功不会让 v2 的 `login` 省略许可证登录。
- v1 使用全局旧版表（`license_keys`、`license_devices`、`variables`、`reports`）；v2 使用软件槽表（`license_codes`、`license_bindings`、`client_sessions`、`software_variables`、`data_uploads` 等）。
- 数据库迁移会复制能明确归属的历史 legacy 资源，但这不等于两条运行时路径共享最新的绑定、session 或配额状态。
- v1 许可证查找使用 `license_keys`；v2 许可证查找使用指定软件槽的 `license_codes`。不要假定当前管理端生成的 scoped license 或 v2 legacy license 必然能被旧 v1 endpoint 使用。
- v1 时间戳窗口为 120 秒；v2 默认为 60 秒，客户端时钟同步要求不同。
- v1 与 v2 共用按 IP 客户端限流；迁移客户端时不能把两条接口的调用次数相加后忽略限额。

## 6. 客户端错误码

客户端错误都位于加密响应中，HTTP 层（正常已匹配的软件槽）仍通常为 200。下表中的“状态”是响应 JSON 的 `status`，不是外层 HTTP 状态。

### 6.1 v2 错误

| 错误码 | 状态 | 含义 |
| --- | ---: | --- |
| `INVALID_REQUEST` | 400 | 包为空/超限、无法解密、明文不是对象、请求格式错误或未分类的请求异常 |
| `INVALID_PROTOCOL` | 400 | `protocol` 不是 `jur10n-client-v2` |
| `INVALID_KEY_VERSION` | 400 | `key_version` 不是合法安全整数，或与请求选择器不一致 |
| `TIMESTAMP_INVALID` | 400 | 时间戳不是安全整数或超出窗口 |
| `INVALID_OPERATION` | 400 | op 不在六个允许值内 |
| `INVALID_MACHINE_PROOF` | 400 | 机器证明格式不符合要求 |
| `SESSION_REQUIRED` | 401 | 缺少或格式不合法的 session token |
| `SESSION_REVOKED` | 401 | session 不存在或已撤销 |
| `SESSION_EXPIRED` | 401 | session 已到绝对过期时间 |
| `SESSION_INACTIVE` | 401 | 超过 heartbeat timeout 未有活动请求 |
| `KEY_REVOKED` | 401 | 已选密钥被判定为撤销（正常 active-key 选择通常会在更早阶段失败） |
| `INVALID_CREDENTIALS` | 401 | code 不存在、格式非法或许可证不是 active |
| `LICENSE_EXPIRED` | 401 | 许可证已过期 |
| `MACHINE_MISMATCH` | 403 | 机器摘要与 binding 不匹配，或 binding 不存在 |
| `MACHINE_PROOF_REQUIRED` | 403 | 启用机器校验时缺少机器证明 |
| `IP_MISMATCH` | 403 | IP 检查开启且 policy=deny 时摘要不匹配 |
| `SOFTWARE_DISABLED` | 403 | 软件槽不是 active |
| `RECEIVING_DISABLED` | 403 | 全局接收设置已关闭 |
| `REPLAY_DETECTED` | 409 | nonce 已在 5 分钟保留期内使用过 |
| `DATA_SLOT_NOT_FOUND` | 404 | 数据槽不存在或未启用 |
| `FILE_NOT_FOUND` | 404 | 文件不属于该软件槽、不是 ready 或不存在 |
| `PAYLOAD_TOO_LARGE` | 413 | 报告超过全局/数据槽单条限制或报告上限 |
| `QUOTA_24H_EXCEEDED` | 413 | 超过数据槽滚动 24 小时字节配额 |
| `QUOTA_PERMANENT_EXCEEDED` | 413 | 超过数据槽永久字节配额 |
| `RECORD_LIMIT_EXCEEDED` | 413 | 超过数据槽记录数配额 |
| `INVALID_OFFSET` | 400 | file chunk 的 offset/length 非法或 offset 已到文件末尾 |
| `STORAGE_LIMIT` | 507 | 服务端文件存储低于配置的空间/inode 水位 |
| `KEY_UNAVAILABLE` | 503 | 服务端无法读取可用的软件密钥 |

`INVALID_DATA_SLOT`（400）表示 `data_slot` 格式非法；`INVALID_PAYLOAD`（400）表示报告数据不能按当前实现序列化。部分文件路径错误可能表现为 `INVALID_PATH`（400）或通用 `INVALID_REQUEST`。

### 6.2 v1 错误

v1 当前运行时可返回：

| 错误码 | 状态 | 含义 |
| --- | ---: | --- |
| `INVALID_REQUEST` | 400 | 包、时间戳、nonce、op 或请求结构不符合要求 |
| `INVALID_CREDENTIALS` | 401 | 旧版许可证不存在或不是 active |
| `LICENSE_EXPIRED` | 401 | 旧版许可证已过期 |
| `DEVICE_NOT_VERIFIED` | 403 | device_id 尚未通过 v1 verify |
| `DEVICE_LIMIT` | 403 | 超过 v1 许可证的设备数上限 |
| `REPLAY_DETECTED` | 409 | nonce 重复 |
| `PAYLOAD_TOO_LARGE` | 413 | report 序列化数据超过接收限制 |
| `RATE_LIMITED` | 429 | 超过按 IP 客户端限流 |

### 6.3 管理接口常见错误

管理接口不使用客户端二进制加密，而是 JSON 和普通 HTTP 状态。常见错误包括：

| HTTP 状态 | 错误码 |
| ---: | --- |
| 401 | `UNAUTHENTICATED`、`INVALID_CREDENTIALS` |
| 403 | `ORIGIN_FORBIDDEN`、`CSRF_INVALID`、`FORBIDDEN` |
| 428 | `PASSWORD_CHANGE_REQUIRED` |
| 404 | `NOT_FOUND` |
| 409 | `SOFTWARE_EXISTS`、`RELEASE_EXISTS`、`KEY_EXISTS`、`DATA_SLOT_IN_USE`、`LEGACY_PROTECTED` |
| 413 | `VALUE_TOO_LARGE`、`FILE_TOO_LARGE` |
| 415 | `JSON_BASE64_REQUIRED` |
| 429 | `RATE_LIMITED` |
| 500 | `GENERATION_FAILED` |
| 503 | `KEY_UNAVAILABLE` |

参数校验还会返回 `INVALID_SOFTWARE`、`INVALID_PROTOCOL`、`INVALID_KEY`、`INVALID_VERSION`、`INVALID_DATE`、`INVALID_RATE_LIMIT`、`PASSWORD_TOO_WEAK`、`INVALID_FILE` 等 400 错误。

## 7. Dashboard 管理接口概要

### 7.1 身份验证与权限

管理接口预期通过 HTTPS 使用。登录成功后服务端设置：

- `jur10n_session`：HttpOnly、Secure、SameSite=Strict，会话有效期 7 天；
- `jur10n_csrf`：非 HttpOnly、Secure、SameSite=Strict，用于前端读取并发送 CSRF token。

请求的 `Origin` 为空时允许；存在时必须等于服务端 `DASHBOARD_ORIGIN`（默认 `https://dashboard.example.com`，TODO(需要补充)：以你在服务器 env 中设置的后台域名为准）。除 GET 外的写操作需要 `X-CSRF-Token`，且必须同时匹配 CSRF cookie 和服务端会话中的摘要。

角色等级为 `viewer < operator < owner`：

- `viewer`：可执行已认证读取；
- `operator`：可执行许可证、变量、接收设置、报告等日常写操作；
- `owner`：可管理软件槽、密钥、session、绑定和 release。

初始管理员如果标记为必须改密码，除 `/api/admin/me` 和 `/api/admin/password` 外的管理请求会返回 `428 PASSWORD_CHANGE_REQUIRED`。

### 7.2 登录与会话

```http
POST /api/admin/login
```

JSON 请求为 `{ "username": "owner", "password": "..." }`。成功返回：

```json
{
  "user": {
    "id": 1,
    "username": "owner",
    "role": "owner",
    "mustChangePassword": false
  },
  "csrfToken": "..."
}
```

当前实现按 IP 对登录尝试使用每分钟 10 次的硬限制。登录接口、密码修改和退出：

```http
GET  /api/admin/me
POST /api/admin/password       {"password":"..."}
POST /api/admin/logout
```

新密码长度必须为 14–256 个字符；登录/退出会写审计日志。

### 7.3 软件槽、密钥与安全策略（v2 管理）

规范化的资源路径为 `/api/admin/software`。源码还会把请求 URL 中的 `/api/admin/software-slots` 前缀重写为 `/api/admin/software`，因此旧前缀可作为兼容写法。资源集合和软件级资源均使用 canonical 路径：

```text
POST   /api/admin/software
GET    /api/admin/software/:software_slot
PATCH  /api/admin/software/:software_slot
DELETE /api/admin/software/:software_slot
```

创建/编辑可设置 `name`、`description`、`status`、`machineCheck`、`ipCheck`、`ipChangePolicy`、`heartbeatTimeout`、`sessionTtl`。当前代码将 heartbeat timeout 限制在 30–3600 秒，将 session TTL 限制在 60–2592000 秒。`legacy` 软件槽受保护，不能删除。

软件槽信息包含 `protocolVersion: "jur10n-client-v2"`、当前密钥版本及指纹、许可证/变量/数据槽/session/存储统计等字段。安全策略接口为：

```text
GET /api/admin/software/:software_slot/security
PUT /api/admin/software/:software_slot/security
```

PUT 可更新机器校验、IP 校验、IP policy、heartbeat timeout 和 session TTL；`protocolVersion` 如果提供，必须为 `jur10n-client-v2`。

密钥生命周期接口（owner）：

```text
GET  /api/admin/software/:software_slot/keys
POST /api/admin/software/:software_slot/keys/rotate
POST /api/admin/software/:software_slot/keys/:version/revoke
POST /api/admin/software/:software_slot/keys/:version/export
```

`rotate` 会撤销旧 active key、创建下一个版本并撤销该软件槽的现有 client sessions，响应为 `{key, exportRequired: true}`，原始密钥不再随 rotate 返回。`export` 只允许导出尚未导出的 active key，导出后通过数据库原子标记为已导出（并发重复导出会得到 `KEY_ALREADY_EXPORTED`）。

`/api/admin/software-slots` 前缀的请求会被统一重写为 canonical 的 `/api/admin/software` 路径，仅作为兼容写法保留。

软件槽位管理：

```text
GET    /api/admin/software
POST   /api/admin/software
GET    /api/admin/software/:software_slot
PATCH  /api/admin/software/:software_slot
DELETE /api/admin/software/:software_slot
GET    /api/admin/monitoring
```

`DELETE` 是真正的硬删除（`legacy` 槽位受保护返回 `LEGACY_PROTECTED`）：会级联删除该软件的卡密、绑定、会话、变量、数据槽、上报与文件资源，并清理磁盘文件，操作不可恢复。`GET /api/admin/monitoring` 返回全局监控快照（所有槽位的请求/会话/卡密统计、进程内存、CPU、磁盘与 SQLite 模式）。

### 7.4 v2 许可证、绑定和 session

```text
GET    /api/admin/software/:software_slot/licenses
POST   /api/admin/software/:software_slot/licenses
POST   /api/admin/software/:software_slot/licenses/batch
PATCH  /api/admin/software/:software_slot/licenses/:id
DELETE /api/admin/software/:software_slot/licenses/:id
POST   /api/admin/software/:software_slot/licenses/:id/reset-binding
GET    /api/admin/software/:software_slot/bindings
GET    /api/admin/software/:software_slot/sessions
POST   /api/admin/software/:software_slot/sessions/:id/revoke
```

生成许可证的 body 支持两种形式：

- 批量生成：`{count, prefix, expiresAt, maxDevices, note}`；
- 手动添加：`{codes: ["MY-CODE-1", ...], expiresAt, maxDevices, note}`，重复卡密会出现在响应的 `duplicates` 数组中，格式非法返回 `INVALID_LICENSE_CODE`。

列表支持 `search`（按卡密明文/公开 ID/机器哈希子串匹配）、`status`（active/revoked）、`page`、`limit`。每个条目包含 `code`（at-rest 解密后的明文卡密；仅对启用明文存储后新建的卡密可用，历史迁移卡密为 null）、`machineHash` 与 `boundAt`（当前机器绑定信息，未绑定为 null）。

批量操作 `POST .../licenses/batch` body 为 `{action, ids}`，`action` 支持 `ban`（封禁）、`activate`（启用）、`reset-binding`（删除绑定并撤销会话）、`delete`（硬删除卡密及其绑定/会话），返回 `{ok, changed}`。单个 `DELETE .../licenses/:id` 也是硬删除。

`reset-binding` 会删除 binding 并撤销该许可证的 v2 sessions。

### 7.5 v2 变量、数据槽、报告与文件资源

变量：

```text
GET    /api/admin/software/:software_slot/variables
POST   /api/admin/software/:software_slot/variables
PATCH  /api/admin/software/:software_slot/variables/:id
DELETE /api/admin/software/:software_slot/variables/:id
```

变量 body 使用 `key`、`value`、`enabled`；scoped 变量 key 必须符合服务端 key 格式，变量值上限为 128 KiB；编辑 value 会递增变量版本。GET 会返回后台解密后的值。

数据槽和用量：

```text
GET    /api/admin/software/:software_slot/data-slots
POST   /api/admin/software/:software_slot/data-slots
GET    /api/admin/software/:software_slot/data-slots/usage
PATCH  /api/admin/software/:software_slot/data-slots/:id
DELETE /api/admin/software/:software_slot/data-slots/:id
```

数据槽只承载 `slug`、`name`、`description`、`enabled`；**不提供任何可配置配额字段**。每个单码在每个数据槽的最终快照固定上限为 200 KiB，数据槽本身不限总量。创建 body 为 `{slug, name, description, enabled}`，slug 冲突返回 `DATA_SLOT_EXISTS`。`usage` 返回槽位整体的单码快照数量和最近更新时间。

数据槽内部数据：

```text
GET    /api/admin/software/:software_slot/data-store
GET    /api/admin/software/:software_slot/data/:licenseId/:slot
PUT    /api/admin/software/:software_slot/data/:licenseId/:slot
DELETE /api/admin/software/:software_slot/data-store/:id
DELETE /api/admin/software/:software_slot/data/:licenseId/:slot
DELETE /api/admin/software/:software_slot/data-slots/:slot/history
```

`PUT` body 为 `{mode: "overwrite" | "append", data}`；省略 `mode` 等同 `overwrite`。历史清空只删除该槽位的 `data_uploads` 历史，不删除 `data_store` 当前快照。

v2 报告历史管理：

```text
GET    /api/admin/software/:software_slot/reports
GET    /api/admin/software/:software_slot/reports/:id
DELETE /api/admin/software/:software_slot/reports/:id
```

列表返回分页的历史 upload 元数据；详情返回后台解密后的 `payload`。按数据槽清空历史使用 `DELETE /api/admin/software/:software_slot/data-slots/:slot/history`，该操作不会删除单码当前快照。

文件资源管理（替代旧版本发布）：

```text
GET    /api/admin/software/:software_slot/resources
POST   /api/admin/software/:software_slot/resources
DELETE /api/admin/software/:software_slot/resources/:id
```

上传 body 必须是 JSON（不支持 FormData）：

```json
{
  "originalName": "client.bin",
  "content": "标准 base64 文件内容",
  "mime": "application/octet-stream"
}
```

单个文件上限默认 64 MiB（受 `MAX_FILE_BYTES` 影响）。存储名随机生成、目录不由 Web server 直接暴露；上传即对客户端可见（manifest 实时反映），删除会移除数据库记录与磁盘文件。

### 7.6 全局/legacy 管理接口（主要服务 v1）

以下接口保留旧版全局资源管理：

```text
GET    /api/admin/overview
GET    /api/admin/licenses
POST   /api/admin/licenses
PATCH  /api/admin/licenses/:id
DELETE /api/admin/licenses/:id

GET    /api/admin/variables
POST   /api/admin/variables
PATCH  /api/admin/variables/:id
DELETE /api/admin/variables/:id

GET    /api/admin/receive-settings
PUT    /api/admin/receive-settings
GET    /api/admin/security/rate-limit
PUT    /api/admin/security/rate-limit

GET    /api/admin/reports
GET    /api/admin/reports/:id
DELETE /api/admin/reports/:id
POST   /api/admin/reports/purge
GET    /api/admin/audit
```

- `overview` 返回许可证、变量、报告和 active session 的统计；
- `receive-settings` 返回/修改 `{enabled,maxPayloadBytes}`，`maxPayloadBytes` 实际被限制在 1024–131072；
- `security/rate-limit` 返回/修改客户端每 IP 每分钟限额；
- reports 详情返回后台解密的旧版报告 payload，purge 使用 `{before}` 清理该时间之前的记录；
- `audit` 为分页审计日志；
- 全局接口与 scoped v2 接口的表和统计并非完全相同，不能据全局 reports 推断 v2 `data_uploads` 的用量。

此外，`GET/PUT /api/admin/security` 返回/修改更宽的安全摘要（客户端限额、登录限额、包/报告上限、磁盘低水位）。`loginPerMinute` 会实际作用于管理员登录限流；限流响应包含 `Retry-After`。客户端包上限仍是服务端固定协议上限，不应当作可动态调节值。

## 8. 服务端存储与客户端注意事项

- SQLite 使用 WAL；数据库路径由 `SQLITE_DATABASE_PATH` 指定。
- `MASTER_SECRET` 必须能解码为 32 字节；它用于 v1 传输、at-rest 密钥派生、许可证 code HMAC 和 IP 摘要。
- v2 软件 key 是每个软件槽独立的 32 字节随机 AES key；客户端配置中的 key 等同于长期凭据，应使用安全存储。
- 许可证 code、session token、机器证明、IP 明文都不会按原值持久化：服务端分别保存 HMAC/机器摘要/IP 摘要或加密数据。
- 传输包上限 256 KiB，v2 report 业务数据上限 128 KiB；密文包还要额外包含 12 字节 IV、16 字节 tag 和 JSON/加密开销，因此不要把 128 KiB 当作可直接放入传输包的精确上限。
- nonce 必须每次重新生成；重试请求时不要重放整个旧密文包。应生成新 nonce、更新时间戳并重新加密；v1/v2 的 nonce 重放窗口都是 5 分钟。
客户端接口（v2）使用 60 秒时间窗口；v1 兼容接口仍使用独立的 120 秒窗口。
- 客户端必须先认证 tag，再解析 JSON；不要信任外层 HTTP `200` 或明文中未经验证的字段。
- v2 每次请求都要使用与密钥版本一致的 AAD。密钥轮换会使旧 session 失效，客户端收到 `INVALID_REQUEST`、`KEY_REVOKED`、`SESSION_REVOKED` 或无法解密响应时，应重新取得新版本配置并重新 login，而不是无限重试旧包。
- `file_chunk.chunk` 是标准 base64；manifest 中的文件摘要是完整文件摘要，不能用单块摘要代替。
- v2 report 的 `data_slot`、单条限制、24 小时配额、永久配额和记录数限制都可能独立拒绝请求；客户端应把 413 错误视为不可通过立即重试解决的配额/大小问题。
- 管理端返回的许可证 code 和 v2 key 是敏感值。服务端日志、客户端日志、错误上报和前端构建产物都不应记录这些值。


## 当前协议补充（2026-08-29）

### 时间窗口

v2 客户端请求的 `timestamp` 必须是 Unix 毫秒安全整数，与服务器当前时间的绝对差默认不超过 **60 秒**（由 `CLIENT_TIMESTAMP_WINDOW_MS` 配置，服务端至少保留 1 秒下限）。v1 兼容接口仍使用独立的 120 秒窗口，两个协议不可混用。

### 登录 token 与心跳

`login` 成功后，解密响应 `data` 中返回 `sessionToken` 和 `sessionId`。服务器只保存 `sessionToken` 的 HMAC 摘要。除 `login`、`announcement` 外的每个 v2 操作都必须携带 `session_token`、`session_id`、机器证明（若软件启用机器校验）、新的 timestamp 和 nonce。服务器会验证 token 是否存在、未撤销、未过期且最近一次心跳不超过软件槽的 `heartbeatTimeout`。`heartbeat` 只刷新活跃时间，不延长绝对 session TTL；轮换密钥、重置绑定和管理员强制下线会撤销 token。

### 数据槽：每单码独立的当前值

数据槽本身不设置总容量。每个 `(software_slot, data_slot, license)` 组合只有一条加密当前值记录，最终 JSON 快照大小固定不得超过 **200 KiB（204800 字节）**。客户端 `report` 支持：

- `mode: "overwrite"`（默认）：用本次 `data` 替换当前值；不存在时自动创建。
- `mode: "append"`：对象做浅层合并（同名键由新值覆盖）、数组拼接、字符串连接；不存在时自动创建；类型不兼容返回 `INVALID_APPEND`。

服务端按最终合并后的 UTF-8 JSON 快照大小检查 200 KiB。每个数据槽可由管理端创建、启停和删除；有未删除上报记录时不能删除。管理端数据视图应按单码查看当前值、版本、大小和 SHA-256。

### 公告

每个软件槽位有独立公告。公开读取接口为：

```text
GET /api/public/software/:software_slot/announcement
```

该接口不需要管理员或客户端 session，但只返回公告元数据/文本，不返回卡密、变量、数据槽值或文件内容。客户端加密协议也支持 `op: "announcement"`：请求仍须使用正确软件密钥、key version、timestamp 和一次性 nonce，但不需要 `session_token`；响应为加密二进制包。空公告返回空字符串。公告编辑仅限管理员并写入审计。

### 卡密生成

默认自动生成卡密为 **32 个大写十六进制字符**；如果指定前缀，则格式为 `PREFIX-` 加 32 个大写十六进制字符。管理端支持按明文卡密、公开 ID、机器摘要搜索，批量封禁、启用、重置绑定和删除。

### Cloudflare 代理建议

`server.example.com` 和 `dashboard.example.com`（TODO(需要补充)：换成你自己的域名）的 DNS 记录均可切换为 Cloudflare **Proxied（橙云）**。切换前应确认源站 443 可用，并在 Cloudflare SSL/TLS 中使用 **Full (strict)**；源站当前由 Caddy 提供公开可信 HTTPS 证书，满足该模式。

建议规则：

- `/api/v2/client/*`、`/api/v1/client`、`/api/admin/*`：Cache Rule 设为不缓存，保留 `Cache-Control: no-store`；不要启用 Browser Integrity Check/JS Challenge/Bot Challenge，避免二进制客户端请求被挑战页替代。
- dashboard 的 HTML/API 不缓存；带 hash 的 `/assets/*` 和 `/fonts/*` 可缓存。
- 保持源站 UFW 仅开放 SSH/HTTP/HTTPS；切换橙云后可进一步限制源站 80/443 只接受 Cloudflare IP，但必须先部署并验证 Cloudflare IP allowlist，避免误锁站。
- Cloudflare 代理隐藏源站 IP 并提供边缘 DDoS/WAF/CDN 接入，但不会改变应用层 AES-GCM、token、timestamp、nonce 或数据槽配额。
- 不要对 API 开启自动缓存或 Challenge；POST 二进制请求通常不应缓存。

官方参考：

- https://developers.cloudflare.com/dns/proxy-status/
- https://developers.cloudflare.com/ssl/origin-configuration/ssl-modes/full-strict/
- https://developers.cloudflare.com/cache/how-to/cache-rules/
- https://developers.cloudflare.com/cloudflare-challenges/concepts/how-challenges-work/
