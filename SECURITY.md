# jur10n-server 安全机制与服务器设置参考

> 整理自 `jur10n-server` 项目（2026-10-03）。用途：给朋友自己的服务器做安全参考。
> 这份文档只讲**安全机制和系统设置**；完整部署步骤看 `DEPLOYMENT_GUIDE.md`，API 契约看 `server/API.md`。
> 文中不含任何真实密钥。所有 `<placeholder>` 都要换成你自己的值。

---

## 0. 架构总览（安全分层）

```text
客户端 / 浏览器
     │ HTTPS (TLS 1.2+)
     ▼
Cloudflare（可选橙云代理：WAF / 缓存规则 / Full strict）
     ▼
Caddy 2.x（唯一公网入口，80/443，自动 HTTPS + 安全响应头）
     ├─ server.example.com   → 反代 127.0.0.1:3000（API）
     │   └─ /vpn/*           → 本地静态订阅文件（token 即凭证）
     └─ dashboard.example.com
         ├─ /api/*           → 反代 127.0.0.1:3000
         └─ 其余             → 静态 React 构建产物
     ▼
Node.js 24 + Fastify（systemd 沙箱内，只监听 127.0.0.1:3000）
     ├─ SQLite WAL（at-rest AES-256-GCM 加密，仅服务进程可读写）
     ├─ /srv/jur10n/data/files（随机存储名，0600，不经 Web 暴露）
     └─ /etc/jur10n/jur10n.env（0600，root 属主，敏感配置）
另：sing-box（VLESS-Reality + Hysteria2，8443 tcp/udp，独立 VPN 模块）
```

核心原则：**公网只有 Caddy 一层入口，应用只听 loopback，数据库和文件不进任何静态目录，服务进程被 systemd 关进沙箱。**

---

## 1. 网络与端口：最小攻击面

UFW 策略（`deploy/ufw-setup.sh`）：

```bash
ufw allow <SSH_PORT>/tcp comment 'SSH'   # 自定义端口，不用 22
ufw allow 80/tcp comment 'HTTP'          # 只为 Caddy 签证书和跳转
ufw allow 443/tcp comment 'HTTPS'
ufw default deny incoming
ufw default allow outgoing
ufw --force enable
```

规则要点：

- 默认入站全拒；**3000 端口、SQLite 文件、`data/files` 都不对公网开放**。
- 先放行规则再 `enable`，并且操作前确认 VPS 供应商有**带外控制台**（VNC/serial），防止 UFW 配错把自己锁死。
- VPN 模块额外放行 `8443/tcp + 8443/udp`（Reality 和 Hysteria2 共端口）。
- 如果开了 Cloudflare 橙云，可以进一步把 80/443 限制为只接受 Cloudflare IP 段——但这是高风险变更，必须先验证证书续期和回源，再动。

---

## 2. 系统层加固

### 2.1 专用服务用户

```bash
useradd --system --home-dir /srv/jur10n --create-home \
  --shell /usr/sbin/nologin jur10n
```

- 应用跑在 `jur10n` 系统用户下，**shell 为 nologin，不能 SSH 登录**。
- 目录权限：`/srv/jur10n` 树 0750，属主 `jur10n:jur10n`；静态 Dashboard 归 `root:root`（Caddy 读，应用进程写不了自己发布的页面）。
- 敏感配置 `/etc/jur10n/jur10n.env`：`root:root` + **0600**。

### 2.2 systemd 沙箱（`deploy/starlight-api.service.template`）

这是整套防御里性价比最高的部分，模板全文可用：

```ini
[Service]
Type=exec
User=jur10n
Group=jur10n
WorkingDirectory=/srv/jur10n/api
EnvironmentFile=-/etc/jur10n/jur10n.env
Environment=NODE_ENV=production
Environment=HOST=127.0.0.1
Environment=PORT=3000
ExecStart=/usr/bin/node /srv/jur10n/api/src/server.js
Restart=on-failure
RestartSec=5s
UMask=0077
NoNewPrivileges=true
PrivateTmp=true
PrivateDevices=true
ProtectSystem=strict
ProtectHome=true
ReadWritePaths=/srv/jur10n/data /srv/jur10n/logs
RestrictAddressFamilies=AF_UNIX AF_INET AF_INET6
RestrictNamespaces=true
LockPersonality=true
SystemCallArchitectures=native
LimitNOFILE=65536
MemoryMax=768M
TasksMax=256
CPUQuota=200%
```

翻译成人话：

| 配置 | 效果 |
| --- | --- |
| `NoNewPrivileges` | 进程无法通过 setuid 提权 |
| `ProtectSystem=strict` + `ReadWritePaths` | 整个文件系统只读，**只有** data 和 logs 可写——即使应用被攻破，也改不了系统文件 |
| `PrivateDevices` / `PrivateTmp` | 看不到真实设备，tmp 独立 |
| `RestrictNamespaces` / `LockPersonality` / `SystemCallArchitectures=native` | 堵容器逃逸、个人化切换和异构架构利用路径 |
| `UMask=0077` | 应用新建的所有文件默认只有属主可读 |
| `MemoryMax` / `TasksMax` / `CPUQuota` | 应用被打爆（如超大上传）也不会拖死整机 |

`ExecStart` 必须写 node 的**绝对路径**，避免 systemd 环境下 PATH 不一致导致起不来或起错二进制。

---

## 3. SSH

- 使用**自定义端口**（本仓库脚本默认写 22022，按实际改），编辑 `deploy/ufw-setup.sh` 里的端口后再跑。
- 登录用 **ed25519 密钥**（`~/.ssh/authorized_keys`），一键配置写在 `/etc/ssh/sshd_config.d/50-jur10n-key.conf`。
- 当前实况提醒：**密码认证还开着**（云镜像 `ssh_pwauth: false` 被供应商初始配置覆盖过）。密钥验证稳定后应关掉：

```bash
# /etc/ssh/sshd_config.d/ 中确保：
PasswordAuthentication no
PermitRootLogin prohibit-password   # 或换成普通用户 + sudo
systemctl restart ssh
```

改 SSH 配置前先开第二个会话验证能登录，并保留供应商带外控制台。

---

## 4. Caddy：唯一公网入口（`deploy/Caddyfile`）

完整可抄，替换域名即可：

```caddyfile
(jur10n_headers) {
	header {
		X-Content-Type-Options "nosniff"
		X-Frame-Options "DENY"
		Referrer-Policy "no-referrer"
		Permissions-Policy "camera=(), microphone=(), geolocation=()"
		Strict-Transport-Security "max-age=31536000; includeSubDomains"
		-Server
	}
}

(jur10n_api_headers) {
	header {
		Cache-Control "no-store"
		Pragma "no-cache"
	}
}

server.example.com {
	import jur10n_headers
	import jur10n_api_headers
	handle_path /vpn/* {
		root * /srv/jur10n/vpn
		file_server
	}
	handle {
		request_body { max_size 16MB }
		reverse_proxy 127.0.0.1:3000
	}
}

dashboard.example.com {
	import jur10n_headers
	handle /api/* {
		import jur10n_api_headers
		request_body { max_size 86MB }
		reverse_proxy 127.0.0.1:3000
	}
	handle /assets/* {
		header Cache-Control "public, max-age=31536000, immutable"
		root * /srv/jur10n/dashboard/dist
		encode zstd gzip
		file_server
	}
	handle {
		header Cache-Control "no-cache, must-revalidate"
		root * /srv/jur10n/dashboard/dist
		encode zstd gzip
		try_files {path} /index.html
		file_server
	}
}
```

设计点：

1. **安全响应头统一注入**（HSTS 一年、nosniff、DENY iframe、禁用敏感 API、抹掉 `Server` 头）。
2. **API 域名与后台域名分离**：客户端打 `server.*`，管理员浏览器打 `dashboard.*`，前端用同源 `/api`，不存在 CORS 面。
3. **请求体限额分级**：API 域名 16MB（客户端二进制包本来就 ≤256KiB，限制再紧也够）；后台 `/api/*` 86MB（容纳 base64 整文件上传）。上限故意不放开——上传是整文件进内存 base64，盲目放大等于给攻击者一个 OOM 武器。
4. **缓存策略**：动态 API 一律 `no-store`；只有 `/assets/*` 指纹化文件长期缓存；HTML `no-cache`。
5. `/vpn/*` 订阅文件同样 `no-store`，token 文件名即凭证，绝不能进缓存或日志。
6. 改配置先 `caddy validate` 再 reload。

---

## 5. Cloudflare 边缘（可选）

- **SSL/TLS 模式必须是 Full (strict)**：源站 Caddy 持有效证书，端到端加密。禁止 Flexible（那会让 CF→源站裸奔 HTTP）。
- 缓存规则：`/api/*`、`/healthz` 全部不缓存；只缓存静态资源。
- **WAF/Challenge 红线**：`POST /api/v2/client/*` 是 AES-GCM 二进制协议，绝不能套 Browser/JS/Bot Challenge——挑战页会把客户端协议整个打断。需要 Skip 规则时只对明确的客户端 API 路径放行。
- DNS 上线顺序：先灰云直连验证源站证书和接口 → 再切橙云 → 复测 `/healthz`。
- 中国大陆用户为主时，延迟由“客户端→CF→源站”各段共同决定，用 `CF-Ray` colo + 分段计时实测，别拍脑袋。

---

## 6. 应用层：认证、会话、审计

实现位于 `server/src/server.js` / `db.js` / `crypto.js`：

| 机制 | 实现 |
| --- | --- |
| 管理员密码 | **argon2id**（memoryCost 19456, timeCost 2）哈希存储 |
| 首次密码 | 初始密码写 `INITIAL_ADMIN_PASSWORD_FILE`（0600），首次登录**强制改密**，改完 `shred -u` 删文件 |
| 会话 | 服务端 session + HttpOnly `Secure` cookie + **CSRF token**（`SameSite=Strict`，CSRF cookie 供前端回传） |
| 限流 | 客户端接口默认 **30 次/分钟**（存 SQLite settings，可在管理台调），超限返回加密的 `RATE_LIMITED` |
| 审计 | `audit_log` 表：动作、对象、**IP 哈希**（不存明文 IP）、request_id、reason、result |
| 角色权限 | RBAC + **角色感知脱敏**：低权角色看不到完整敏感字段 |
| 报表历史 | 分页 + 可**硬删除** payload（不留软删除残留） |

安全协议决策（升级时不要退回去）：

- **免登录的 free 机器主体存哈希**，不存明文标识；
- **机器绑定与传输密钥解耦**——轮换软件 key 不影响已绑定的机器（稳定 machine binding）；
- 吊销/过期的卡密**立即失效所有活跃 session**，客户端不能拿旧 token 无限重试；
- 密钥轮换是**事务性**的（新版本生效 + 旧版本判定原子完成）。

---

## 7. 客户端通信协议（v2）：防重放、防篡改、防跨软件

每个软件槽位有**独立的 AES-256-GCM 密钥 + 密钥版本号**，客户端与服务端共享：

```text
包格式：12 字节随机 IV || ciphertext || 16 字节 GCM tag
请求 AAD：jur10n:client:v2:{software_slot}:{key_version}:request
响应 AAD：jur10n:client:v2:{software_slot}:{key_version}:response
```

AAD 绑定意味着：**密文挪到别的软件槽位、别的 key 版本、请求响应互换，解密直接失败**。

每个请求还必须带：

- `protocol: jur10n-client-v2` + `key_version`；
- Unix 毫秒 `timestamp`，窗口 **±60 秒**（`CLIENT_TIMESTAMP_WINDOW_MS`），超窗拒绝 → 防重放；
- 每次全新的随机 `nonce`；
- 登录后的操作附带 `session_token` / `session_id` / 机器证明（启用机器校验时）。

会话与绑定策略（每软件可配）：单码登录、**机器数上限**（`max_devices`）、IP 策略、heartbeat 超时（默认 300s）、session TTL。密钥轮换、重置绑定、心跳超时都会使旧 session 立即失效。

> v1 协议是遗留兼容（用 MASTER_SECRET 派生密钥，无槽位隔离），**新客户端一律走 v2**。

---

## 8. 数据与文件安全

- **at-rest 加密**：敏感字段用 `MASTER_SECRET` 派生的密钥做 AES-256-GCM 加密落库；数据库文件本身还有 SQLite WAL。
- 卡密只存 `code_hash`（HMAC 派生），不存明文。
- `ingest` 上报事件**幂等**（重复提交去重），结构化 header/content。
- 资源上传走**分块会话**（chunked upload sessions），避免大包整段进内存。
- 文件资源：**随机存储名**，磁盘上 0600，数据库只存元数据和相对路径；下载时做**路径校验**防目录穿越；客户端拿 manifest → 64 KiB 分片 → **SHA-256 校验**。
- 体积红线（全部硬编码上限，超了直接 413/507）：
  - 客户端单包 256 KiB；单次上报 128 KiB；每 `(软件, 数据槽, 单码)` 快照 200 KiB；文件单文件 64 MiB；
  - 磁盘低水位：剩余 <256 MiB 或 inode 不足时拒绝写入（`STORAGE_LIMIT` 507），防止把盘写满拖死系统。

---

## 9. 秘密管理

| 秘密 | 存放 | 规则 |
| --- | --- | --- |
| `MASTER_SECRET` | `/etc/jur10n/jur10n.env`（0600, root） | 32 字节 base64url，`node -e "console.log(require('node:crypto').randomBytes(32).toString('base64url'))"` 生成；**每台服务器独立生成**；丢失 = 加密数据不可恢复 |
| 管理员密码 | 数据库（argon2id） | 初始密码只在首次登录用，改完删除初始密码文件 |
| 软件密钥 | 导出一次 | 只走管理端导出流程；不进 Git、不进 `dashboard/dist`、不打日志 |
| 订阅 token | 文件名本身 | `/srv/jur10n/vpn/<token>.yaml`，轮换时清旧文件 |
| `.gitignore` | — | 忽略 `backups/`、`*.sqlite3*`、`initial-admin-password`、env 文件；打包迁移前人工复查一遍压缩包 |

纪律：任何秘密不进聊天记录、不进日志、不进备份以外的拷贝；历史备份、SQLite WAL/SHM、debug 产物视为**潜在泄露物**，处理时按已暴露对待（轮换相关凭证）。

---

## 10. VPN 模块（sing-box，可选）

- **协议**：VLESS + Reality（TCP 8443，伪装握手 `www.microsoft.com`）+ Hysteria2（UDP 8443，自签证书）。Reality 不需要真证书，抗主动探测。
- 配置 `/etc/sing-box/config.json` 权限 600 root；systemd 服务 `sing-box`。
- **订阅分发**：Caddy 静态发 `/srv/jur10n/vpn/<token>.yaml`，URL 里的 token 就是唯一凭证，`no-store`。
- **这台服务器的坑（重要）**：系统 DNS 上游被污染（google 系域名曾解析到错误 IP）。sing-box 配置里强制 **DoH（1.1.1.1 / 8.8.8.8 over TCP 443）+ `ipv4_only`**。**不要删 `dns` 段**，否则代理目标域名会静默超时。
- 内核调优 `/etc/sysctl.d/99-jur10n-vpn.conf`：BBR + fq + 16MB UDP 缓冲。
- 轮换：`node vpn/generate.mjs --rotate && bash vpn/deploy.sh`（幂等脚本：装 sing-box、调内核、UFW 放行、上传、重载）。
- 每次改配置：`sing-box check` → restart → 用**被墙域名**端到端测（只 ping 1.1.1.1 测不出 DNS 污染）。

---

## 11. 备份与发布回滚

`deploy/backup-jur10n.sh`（装到 `/usr/local/bin/jur10n-backup.sh`，cron 在 `deploy/starlight-sqlite-backup.cron`）：

- 用 **SQLite backup API** 在线一致性快照（不是 cp 数据库文件），之后 `PRAGMA quick_check` 验证；
- 一并打包 `data/files`；
- 备份目录 **0700**，备份文件 **0600**，`flock` 防并发，按保留天数清理（默认 14 天），**不上传任何外部服务**。

发布流程（`DEPLOYMENT_GUIDE.md` §15）：

1. 本地测试构建 → 服务器**先备份**（含 env、systemd、Caddyfile）；
2. 新代码传 staging，`node --check` + 权限检查；
3. 停服 → 原子 `mv` 换目录 → 起服 → 等 `/healthz` 200 → reload Caddy → 公网验证；
4. 旧目录保留（`api.previous-<时间戳>`）；
5. 起不来就反向 `mv` 回滚。**注意：迁移已执行时不能只回滚代码**，schema 不会自动降级——破坏性恢复必须用验证过 `quick_check` 的备份在停机窗口做。

---

## 12. 当前实况清单（2026-10-04 复核）

| 项 | 状态 |
| --- | --- |
| Ubuntu 22.04 / 2C / 3.8G / 60G | ✅ |
| Node 24 + Fastify，监听 127.0.0.1:3000 | ✅ |
| `jur10n-api.service` systemd 沙箱 | ✅ |
| Caddy 双域名 HTTPS（自动证书） | ✅ |
| HTTP→HTTPS 强制 | ✅ 80 端口 308/301 全跳转 + HSTS 一年（实测） |
| UFW active：22, 80, 443（+8443 tcp/udp VPN） | ✅ |
| SSH 密钥登录 | ✅ |
| SSH 密码认证 | ✅ 已关闭（`PasswordAuthentication no`，实测密码被拒） |
| v1 遗留协议 | ✅ 默认关闭（410），需 `ENABLE_V1_PROTOCOL=1` 显式开启 |
| Cloudflare 橙云 + Full (strict) | ✅ |
| 一致性备份 cron | ✅ |
| sing-box VPN 模块（含 DoH 段） | ✅ |

---

## 13. 已知弱点 / 处置状态（2026-10-04 复核）

1. ~~SSH 密码认证未关~~ **已解决**：`/etc/ssh/sshd_config.d/50-jur10n-key.conf` 改为 `PasswordAuthentication no` + `PermitRootLogin prohibit-password`，实测密钥登录正常、纯密码尝试被拒（`Permission denied (publickey)`）。
2. ~~v1 遗留协议常开~~ **已解决**：v1 默认关闭——`POST /api/v1/client` 一律返回 `410 V1_PROTOCOL_DISABLED`；确需兼容旧客户端时，在 `/etc/jur10n/jur10n.env` 设 `ENABLE_V1_PROTOCOL=1` 并重启 `jur10n-api`。v1 绑定 `MASTER_SECRET` 且无槽位隔离，能不用就不用。
3. ~~管理端整文件 base64 上传进内存~~ **已解决**：Dashboard 已迁移到分片上传会话（init → 4 MiB PUT 分片 → complete，服务端校验偏移与 SHA-256，单请求体 ≤8 MiB）；旧的 base64 路由仅作遗留兼容，前端不再调用。
4. 服务器 DNS 上游污染 → **持续缓解**：sing-box `dns` 段强制 DoH（1.1.1.1 / 8.8.8.8 over TCP 443）+ `ipv4_only`，已核实配置在位；不要删。
5. Windows 中文路径 npm/工具链 shim 问题 → **已缓解**：dashboard 的 `npm run build` 改为直接 `node node_modules/typescript/bin/tsc` + `node node_modules/vite/bin/vite.js`，绕开 PATH 中 `&` 截断；部署类脚本仍建议在服务器上跑。

---

## 14. 朋友复刻清单（最小动作集）

按顺序做，每步验证后再下一步：

```text
[ ] 1. VPS + 域名 + 带外控制台确认可用
[ ] 2. SSH：换自定义端口、上 ed25519 密钥、关密码认证
[ ] 3. apt 更新；装 Node 24 / Caddy / ufw / sqlite3
[ ] 4. 建 nologin 服务用户；/srv 目录树 0750
[ ] 5. 上传代码（不含 node_modules、不含任何秘密文件）
[ ] 6. 新生成 MASTER_SECRET → /etc/jur10n/jur10n.env（0600 root）
[ ] 7. 装 systemd 模板（沙箱配置照抄第 2.2 节），127.0.0.1:3000 healthz 200
[ ] 8. 装 Caddyfile（安全头 + body 限额 + no-store），HTTPS 证书自动签发
[ ] 9. UFW：default deny incoming，只放行 SSH/80/443
[ ] 10. 首次登录改密 → 删初始密码文件
[ ] 11. 建软件槽位 → 导出密钥（一次性）→ 生成卡密
[ ] 12. 客户端实测：登录/心跳/变量/上报/文件下载 SHA-256
[ ] 13. 备份脚本 + cron 装好，手动跑一次验证 quick_check ok
[ ] 14. 验证完再切 Cloudflare 橙云（Full strict + 缓存规则 + Challenge 白名单）
[ ] 15. （可选）VPN 模块：generate → deploy → 被墙域名端到端测试
```

安全底线（长期遵守）：应用只听 loopback；数据库和用户文件不进静态目录；秘密不进 Git/日志/聊天；发布前备份、保留回滚路径；UFW 变更前确认带外控制台；任何删除/恢复操作先确认目标。

---

*来源：`DEPLOYMENT_GUIDE.md`、`deploy/*`（Caddyfile / systemd / ufw / backup）、`server/src/*`（crypto / db / server）、`vpn/README.md`。细节冲突时以仓库内文件为准。*
