# jur10n VPS 控制平面：从零部署与迁移手册

> 本文用于把当前项目迁移到任意合规的 Linux VPS。它不依赖特定供应商（原文提到的供应商名已抹去；TODO(需要补充)：自行选择并填入）。朋友拿到项目后，应先通读本文，再按自己的域名、服务器 IP、SSH 端口和 Cloudflare Zone 替换占位符。
>
> 本手册只描述 `jur10n-server` 这个目录里的 VPS 后台。`ssjj-cookies` Cloudflare Worker 在同级的 `cfkv`，公开站在同级的 `webpage`。两边都不要跟着这次部署去改。

## 0. 先看结论

最终架构如下：

```text
客户端 / 浏览器
        │ HTTPS
        ▼
Cloudflare DNS / Proxied（可选）
        │
        ▼
Caddy（公网 80/443，自动 HTTPS）
        ├── dashboard.example.com/      → /srv/jur10n/dashboard/dist
        ├── dashboard.example.com/api/* → 127.0.0.1:3000
        └── server.example.com/*        → 127.0.0.1:3000
                    │
                    ▼
Node.js 24 + Fastify
        ├── SQLite WAL 数据库
        ├── /srv/jur10n/data/files 文件资源
        └── /etc/jur10n/jur10n.env 敏感配置
```

服务器端口原则：

- SSH：自定义端口，例如 `22022`；不要继续使用默认 `22` 暴露在公网。
- HTTP：`80/tcp`，供 Caddy 证书签发和 HTTP → HTTPS 跳转使用。
- HTTPS：`443/tcp`。
- Node/Fastify：只监听 `127.0.0.1:3000`，不直接暴露到公网。
- SQLite 和文件目录：不由 Caddy 直接暴露。

当前应用能力：

- 软件槽位隔离；
- 每软件独立 AES-256-GCM 客户端密钥和密钥版本；
- 单码登录、机器绑定、IP 策略、并行 session；
- heartbeat 活跃检查；
- 远程变量；
- `overwrite` / `append` 数据上报；
- 每个单码、每个数据槽固定 200 KiB 当前快照上限；
- 文件资源 manifest、64 KiB 下载分片和 SHA-256 校验；
- 软件公告；
- 管理 Dashboard；
- SQLite WAL、备份、审计、限流和 CSRF。

## 1. 占位符和迁移前准备

本文使用以下变量。不要把真实值提交到仓库或发到聊天记录中。

| 占位符 | 含义 | 示例（仅示例） |
| --- | --- | --- |
| `PROJECT_DIR` | 本地项目目录 | 本目录，即 `jur10n-server` |
| `APP_ROOT` | VPS 应用根目录 | `/srv/jur10n` |
| `SERVICE_USER` | 运行 Node 的非 root 用户 | `jur10n` |
| `API_DOMAIN` | 客户端 API 域名 | `server.example.com` |
| `DASHBOARD_DOMAIN` | 管理后台域名 | `dashboard.example.com` |
| `ORIGIN_IP` | VPS 公网 IPv4 | `203.0.113.10` |
| `SSH_PORT` | SSH 端口 | `22022` |
| `SSH_USER` | 初始 SSH 管理用户 | `root` 或供应商提供的管理员用户 |
| `ZONE_ID` | Cloudflare Zone ID | 在 Cloudflare 控制台或 API 中查询 |

建议朋友第一次迁移时仍使用固定目录 `/srv/jur10n`，这样可以直接复用：

- `deploy/starlight-api.service.template`；
- `deploy/Caddyfile`；
- `deploy/backup-jur10n.sh`；
- `deploy/starlight-sqlite-backup.cron`。

如果要改变 `APP_ROOT`，必须同步修改 systemd、Caddy、环境文件、备份脚本和本文中的命令。

### 1.1 不要复制的内容

以下内容不应从旧机器复制到朋友的环境，除非这是一次有计划的数据迁移：

- `node_modules/`、`dashboard/node_modules/`；
- `.venv/`；
- `examples/__pycache__/`；
- `server/v2-smoke.sqlite3*`；
- `server/initial-admin-password`；
- `.env`、`.dev.vars`、`.client.env`、`examples/.env`；
- `MASTER_SECRET`、管理员密码、软件密钥、卡密、session token；
- 旧服务器的 SSH 私钥；
- 含真实密钥的备份文件。

本目录的 `.gitignore` 已忽略本地凭据、SQLite 和 `backups/`。迁移前仍应人工检查压缩包，确认没有把 `backups/` 或 `server/initial-admin-password` 打进去。

## 2. 本地项目结构

```text
jur10n-server/
├── server/                         # VPS 后端 Node.js + Fastify
│   ├── src/server.js               # HTTP 路由、鉴权、v1/v2 协议
│   ├── src/db.js                   # SQLite schema 和迁移
│   ├── src/crypto.js               # AES-GCM、at-rest 加密、HMAC
│   ├── test/                       # Node 测试
│   ├── API.md                      # v1/v2 API 完整契约
│   ├── package.json
│   └── package-lock.json
├── dashboard/                      # React + TypeScript + Vite 管理台
│   ├── src/App.tsx
│   ├── src/api.ts
│   ├── src/styles.css
│   ├── public/fonts/
│   ├── package.json
│   └── package-lock.json
├── examples/                       # PyQt6 v2 客户端测试 GUI
│   ├── pyqt_client.py
│   └── requirements.txt
├── deploy/                         # VPS 部署模板和备份脚本
│   ├── .env.example
│   ├── Caddyfile
│   ├── starlight-api.service.template
│   ├── backup-jur10n.sh
│   ├── backup-sqlite.sh
│   ├── starlight-sqlite-backup.cron
│   ├── migrate-jur10n.sh
│   └── ufw-setup.sh
├── backups/                        # 迁移前的 VPS 快照，含密钥，不提交
├── README.md
└── DEPLOYMENT_GUIDE.md             # 本文
```

### 2.1 VPS 部署时各目录的对应关系

```text
/srv/jur10n/
├── api/                            # server/ 内容 + server/node_modules
│   ├── src/server.js
│   ├── src/db.js
│   ├── src/crypto.js
│   ├── package.json
│   └── node_modules/
├── dashboard/
│   └── dist/                       # dashboard npm run build 的产物
├── data/
│   ├── app.sqlite3                 # SQLite 主文件
│   ├── app.sqlite3-wal             # WAL 文件，运行中可能存在
│   ├── app.sqlite3-shm             # SQLite 共享内存文件
│   ├── files/
│   │   └── resources/<software_id>/# 随机存储名文件
│   └── initial-admin-password      # 首次初始化密码，权限 0600
├── backups/                        # 本地备份，不由 Web 访问
└── logs/                           # 服务日志或预留目录
```

系统级配置：

```text
/etc/jur10n/jur10n.env              # 0600，root:jur10n 或 root:root
/etc/systemd/system/jur10n-api.service
/etc/caddy/Caddyfile
/usr/local/bin/jur10n-backup.sh     # 可选，来自 deploy/backup-jur10n.sh
/etc/cron.d/starlight-sqlite-backup # 可选
```

## 3. 选择服务器和域名

### 3.1 VPS 最低建议

当前项目可在 1 vCPU / 2 GiB RAM 的小型 VPS 上运行，但生产建议至少：

- Ubuntu 24.04 LTS x86_64；
- 1–2 vCPU；
- 2 GiB RAM 起步；
- 25 GiB SSD/NVMe 起步；
- 有快照或外部备份能力；
- 可自定义 SSH 端口；
- 可开放 80/443；
- 数据中心位置符合用户访问和当地法律要求。

如果主要用户在中国大陆，应优先比较香港、日本、新加坡以及中国大陆合规服务器的实际运营商线路。地理位置不是唯一因素；同一城市不同供应商的跨境和运营商线路可能差异很大。

如果服务器在中国大陆：

- 先确认供应商、域名和网站/API 业务是否需要备案或其他许可；
- 确认供应商允许该类客户端/API 服务；
- 不要因为 Cloudflare 能解析就认为可以跳过当地监管要求；
- 生产上线前从中国电信、联通、移动和不同地区实测延迟、丢包和 HTTPS 建连。

### 3.2 DNS 初始状态

先在 DNS 服务商或 Cloudflare 创建：

```text
server.example.com       A       ORIGIN_IP
 dashboard.example.com  A       ORIGIN_IP
```

第一次部署建议先设置为 DNS-only（灰云），这样便于确认 Caddy 能够直接签发证书和排查源站。源站验证完成后再开启 Proxied（橙云）。

不要把 `api.旧worker域名` 指向新 VPS，也不要修改旧 Worker 的自定义域名、KV 或 Durable Object。

## 4. 初始化 Ubuntu VPS

以下命令以管理员账号执行。把 `SSH_PORT` 替换成朋友实际配置的端口。第一次操作必须保留供应商的带外控制台，避免 UFW 配错导致失联。

### 4.1 基础软件

```bash
apt update
apt full-upgrade -y
apt install -y \
  ca-certificates curl unzip rsync git tar gzip \
  python3 python3-venv sqlite3 ufw
```

安装 Node.js 24。推荐使用供应商认可的 Node.js 24 安装方式，并确认最终路径与 systemd 模板一致：

```bash
node --version
npm --version
command -v node
```

必须满足：

```text
Node.js >= 24
```

服务端使用 Node 24 的内置 `node:sqlite`。Node 18/20/22 不能假定完全兼容；如果 `node --check` 或启动时出现 sqlite 模块错误，先升级 Node，不要修改业务代码绕过。

### 4.2 创建服务用户和目录

```bash
id jur10n >/dev/null 2>&1 || \
  useradd --system --home-dir /srv/jur10n --create-home \
  --shell /usr/sbin/nologin jur10n

install -d -o jur10n -g jur10n -m 0750 /srv/jur10n
install -d -o jur10n -g jur10n -m 0750 \
  /srv/jur10n/api \
  /srv/jur10n/dashboard \
  /srv/jur10n/data \
  /srv/jur10n/data/files \
  /srv/jur10n/backups \
  /srv/jur10n/logs
install -d -o root -g root -m 0750 /etc/jur10n
```

服务用户不应拥有 SSH 登录权限。SSH 管理使用个人账号或供应商提供的 root/管理员账号；应用进程使用 `jur10n`。

## 5. 上传和安装项目

可以使用 Git、rsync、SFTP 或一次性压缩包。不要上传本地 `node_modules` 和秘密文件。

### 5.1 推荐的本地准备

在本地项目根目录：

```bash
npm --prefix server ci
npm --prefix dashboard ci
npm --prefix server test
npm --prefix dashboard run build
node --check server/src/server.js
node --check server/src/db.js
```

如果本地是 Windows PowerShell，可用：

```powershell
npm --prefix server ci
npm --prefix dashboard ci
npm --prefix server test
npm --prefix dashboard run build
node --check server/src/server.js
node --check server/src/db.js
```

上传时至少需要：

```text
server/src/
server/package.json
server/package-lock.json
dashboard/dist/
```

如果在服务器上构建 Dashboard，也上传 `dashboard/src/`、`dashboard/package.json` 和 lockfile，在服务器执行 `npm ci` 和 `npm run build`。

### 5.2 复制到 VPS

示例：

```bash
rsync -az --delete \
  --exclude node_modules \
  --exclude .venv \
  --exclude .git \
  --exclude '*.sqlite3*' \
  --exclude '.env' \
  --exclude '.dev.vars' \
  --exclude 'examples/.env' \
  server/ SSH_USER@ORIGIN_IP:/srv/jur10n/api/

rsync -az --delete dashboard/dist/ \
  SSH_USER@ORIGIN_IP:/srv/jur10n/dashboard/dist/
```

第一次复制后修正权限：

```bash
chown -R jur10n:jur10n /srv/jur10n/api /srv/jur10n/data /srv/jur10n/logs
chown -R root:root /srv/jur10n/dashboard
find /srv/jur10n/dashboard -type d -exec chmod 755 {} +
find /srv/jur10n/dashboard -type f -exec chmod 644 {} +
```

如果在 VPS 上安装生产依赖：

```bash
cd /srv/jur10n/api
npm ci --omit=dev
```

Dashboard 构建依赖只在构建阶段需要；生产环境最终由 Caddy读取 `dashboard/dist`，不需要让 Caddy 读取 `dashboard/src`。

## 6. 配置敏感环境变量

复制模板：

```bash
install -o root -g root -m 0600 /dev/null /etc/jur10n/jur10n.env
nano /etc/jur10n/jur10n.env
```

推荐的通用配置：

```env
NODE_ENV=production
HOST=127.0.0.1
PORT=3000

# 32 字节原始密钥的无填充 base64url 表示；每台独立环境重新生成
MASTER_SECRET=<GENERATE-A-NEW-32-BYTE-BASE64URL-SECRET>

ADMIN_USERNAME=owner
# 可选。首次启动时使用；登录并改密后从 env 中删除或注释。
ADMIN_INITIAL_PASSWORD=<ONE-TIME-INITIAL-PASSWORD>
INITIAL_ADMIN_PASSWORD_FILE=/srv/jur10n/data/initial-admin-password

SQLITE_DATABASE_PATH=/srv/jur10n/data/app.sqlite3
FILES_ROOT=/srv/jur10n/data/files

DASHBOARD_ORIGIN=https://dashboard.example.com

MIN_FREE_BYTES=268435456
MIN_FREE_INODES=128
MAX_FILE_BYTES=67108864
CLIENT_TIMESTAMP_WINDOW_MS=60000
CLIENT_HEARTBEAT_TIMEOUT_SECONDS=300
```

生成 `MASTER_SECRET`：

```bash
node -e "console.log(require('node:crypto').randomBytes(32).toString('base64url'))"
```

注意：

- `MASTER_SECRET` 是数据库 at-rest 加密、v1 兼容协议和部分 HMAC 的根密钥；丢失后数据库密文无法恢复。
- 不要把它写进 Git、前端、客户端示例、工单或日志。
- 新环境不要复用旧环境的 `MASTER_SECRET`，除非这是有意迁移同一套数据库。
- `ADMIN_INITIAL_PASSWORD` 只用于第一次创建管理员。代码会把初始密码写到 `INITIAL_ADMIN_PASSWORD_FILE`，并要求首次登录修改。
- 当前服务端实际读取的变量名是 `INITIAL_ADMIN_PASSWORD_FILE`，不是旧模板中的 `INITIAL_PASSWORD_FILE`。旧字段不会改变密码文件路径。
- `PUBLIC_API_ORIGIN`、`DASHBOARD_STATIC_DIR` 和 `CLIENT_RATE_LIMIT_PER_MINUTE` 不是当前核心启动路径所需的环境变量；客户端限流默认值会写入 SQLite settings，并可在管理台修改。

创建环境文件后：

```bash
chown root:root /etc/jur10n/jur10n.env
chmod 0600 /etc/jur10n/jur10n.env
```

初始密码读取方式：

```bash
cat /srv/jur10n/data/initial-admin-password
```

只在可信的服务器终端读取，不要通过公开聊天发送。完成第一次登录并修改密码后，可删除该文件：

```bash
shred -u /srv/jur10n/data/initial-admin-password
```

如果系统没有 `shred`，至少：

```bash
rm -f /srv/jur10n/data/initial-admin-password
```

## 7. systemd 服务

复制并检查模板：

```bash
install -o root -g root -m 0644 \
  deploy/starlight-api.service.template \
  /etc/systemd/system/jur10n-api.service
```

模板的关键约束：

```ini
User=jur10n
Group=jur10n
WorkingDirectory=/srv/jur10n/api
EnvironmentFile=-/etc/jur10n/jur10n.env
Environment=HOST=127.0.0.1
Environment=PORT=3000
ExecStart=/usr/bin/node /srv/jur10n/api/src/server.js
ReadWritePaths=/srv/jur10n/data /srv/jur10n/logs
```

如果 `command -v node` 不是 `/usr/bin/node`，把 `ExecStart` 改为实际绝对路径。不要在 systemd 中写 `node` 相对命令，以免 PATH 不同导致服务启动失败。

启动：

```bash
systemctl daemon-reload
systemctl enable --now jur10n-api.service
systemctl status jur10n-api.service --no-pager
curl --fail http://127.0.0.1:3000/healthz
```

预期：

```json
{"ok":true,"service":"jur10n-server","time":"..."}
```

日志：

```bash
journalctl -u jur10n-api.service -n 100 --no-pager
journalctl -u jur10n-api.service -f
```

### 7.1 数据库迁移

服务启动时会自动执行 `server/src/db.js` 中的幂等迁移。第一次启动会创建 SQLite 数据库、schema_migrations 和默认 `legacy` 软件槽位。

检查：

```bash
sqlite3 /srv/jur10n/data/app.sqlite3 \
  'PRAGMA quick_check; SELECT version,name FROM schema_migrations ORDER BY version;'
```

`PRAGMA quick_check` 应返回 `ok`。不要手工复制旧数据库到新环境后再盲目删除 migration 表；如果是正式数据迁移，应先备份并保留完整 schema 版本。

## 8. Caddy 反向代理和静态 Dashboard

安装 Caddy 后复制模板：

```bash
install -o root -g root -m 0644 \
  deploy/Caddyfile /etc/caddy/Caddyfile
```

把模板中的域名替换成朋友自己的域名。通用配置逻辑如下：

```caddyfile
(jur10n_headers) {
    header {
        X-Content-Type-Options "nosniff"
        X-Frame-Options "DENY"
        Referrer-Policy "no-referrer"
        Permissions-Policy "camera=(), microphone=(), geolocation=()"
        -Server
    }
}

server.example.com {
    import jur10n_headers
    request_body {
        max_size 16MB
    }
    reverse_proxy 127.0.0.1:3000
}

dashboard.example.com {
    import jur10n_headers
    handle /api/* {
        request_body {
            max_size 86MB
        }
        reverse_proxy 127.0.0.1:3000
    }
    handle {
        root * /srv/jur10n/dashboard/dist
        encode zstd gzip
        try_files {path} /index.html
        file_server
    }
}
```

为什么有两个域名：

- `server.example.com` 是给客户端使用的 API 入口；
- `dashboard.example.com` 是管理员浏览器入口，同时把 `/api/*` 反代到后端；
- Dashboard 使用同源 `/api/...`，因此浏览器不需要跨域；
- Caddy 只暴露 HTTP/HTTPS，Fastify 仍然只在 localhost 监听。

检查和加载：

```bash
caddy validate --config /etc/caddy/Caddyfile
systemctl enable --now caddy
systemctl reload caddy
curl --fail https://server.example.com/healthz
curl --fail -I https://dashboard.example.com/
```

### 8.1 文件大小说明

> 2026-10-04 更新：Dashboard 管理端上传已迁移到**分片上传会话**（init → 4 MiB PUT 分片 → complete，服务端校验偏移和 SHA-256），单分片请求体只有 4 MiB。旧的"完整文件 base64 + JSON"路由仍保留作遗留兼容，但前端不再使用。

当前代码的文件限制要区分三个概念：

1. 客户端 `file_chunk` 单次下载块：**64 KiB**；
2. 服务端应用层单文件名义上限：**64 MiB**；
3. Dashboard 上传使用“完整文件 base64 + JSON”，经过 Caddy 的 `86MB` 请求体限制后，实际可上传的原始文件会略低于 64 MiB，约 61 MiB 量级。

因此：

- 64KB 不是总文件大小；客户端会循环请求多个分片；
- 当前 64MiB 对多数客户端分发文件已够用；
- 大文件上传应使用 `dashboard.example.com` 的管理页面，不要用 `server.example.com` 上传，因为当前 server host 的 Caddy 请求体上限是 16MB；
- 不要为了“无限文件”简单删除 body limit；当前上传会把整文件放入内存并 base64，盲目放大容易耗尽 Node 内存和磁盘。

## 9. UFW 和 SSH 安全

确认当前 SSH 已能使用新端口后，再配置防火墙：

```bash
ufw allow SSH_PORT/tcp comment 'SSH'
ufw allow 80/tcp comment 'HTTP'
ufw allow 443/tcp comment 'HTTPS'
ufw default deny incoming
ufw default allow outgoing
ufw --force enable
ufw status verbose
```

仓库中的 `deploy/ufw-setup.sh` 当前默认写的是 `22022`，迁移到其他 SSH 端口时必须先编辑脚本中的端口，或按上面的命令手工执行。不要在没有带外控制台、没有确认端口的情况下直接启用 UFW。

最终不应开放：

```text
3000/tcp
SQLite 文件路径
/srv/jur10n/data/files 的 Web 目录访问
```

如果启用 Cloudflare 橙云并确认 Cloudflare IP allowlist 已正确部署，可以进一步限制 80/443 只接受 Cloudflare IP。但这属于高风险变更，必须先测试 IPv4/IPv6、证书续期、回源和故障回滚；SSH 端口仍需保留管理来源。

## 10. Cloudflare 配置

### 10.1 DNS

在目标 Zone 中创建两个 A 记录：

```text
server.example.com       A       ORIGIN_IP
 dashboard.example.com  A       ORIGIN_IP
```

第一次部署：

1. DNS-only；
2. 直接访问源站 HTTPS；
3. 确认 Caddy 证书、API、Dashboard、文件权限都正确；
4. 再把两个记录切到 Proxied。

不要改动旧 Worker 的：

- Worker script；
- `wrangler.jsonc` 中的 KV namespace；
- Durable Object；
- 旧 Worker 自定义域名；
- 旧 Worker 的 DNS 记录。

### 10.2 SSL/TLS

Cloudflare → SSL/TLS：

```text
Encryption mode: Full (strict)
```

Full (strict) 要求源站 443 提供有效可信证书。Caddy 使用公开域名时会自动申请证书；如果源站证书是自签名，应改用 Cloudflare Origin Certificate，并正确安装到 Caddy，而不是退回 Flexible。

不要使用 Flexible，因为它会让 Cloudflare 到源站这一段变成 HTTP，失去端到端 HTTPS 的意义。

### 10.3 Cache Rules

动态接口全部不缓存：

```text
/api/v2/client/*
/api/v1/client
/api/admin/*
/healthz
```

保留源站：

```http
Cache-Control: no-store
```

可缓存的静态内容：

```text
/assets/*
/fonts/*
```

Dashboard HTML 和 API 不应设置成强缓存。客户端二进制接口是 POST + `application/octet-stream`，不要对它启用自动缓存。

### 10.4 WAF、Bot 和 Challenge

不要给这些客户端接口开启 Browser Challenge、JS Challenge 或 Bot Challenge：

```text
POST /api/v2/client/*
POST /api/v1/client
```

这些接口返回 AES-GCM 二进制密文，不是浏览器页面；Challenge 页面会破坏客户端协议。可以对 Dashboard 管理页面设置更严格的访问策略，但要避免把 `/api/v2/client/*` 误套上浏览器挑战。

建议：

- Dashboard 登录由应用自己的 session cookie + CSRF 保护；
- Cloudflare WAF 用于通用恶意流量拦截；
- 需要跳过 Challenge 时，仅为明确的客户端 API 路径创建 Skip 规则；
- 不要为了测试直接关闭整个 Zone 的安全防护。

### 10.5 中国大陆访问和“指定中国节点”

普通 Cloudflare Proxied 使用全球 Anycast。用户不能在普通 DNS 或橙云设置里手工选择“北京、上海、广州、中国节点”。实际接入点由 BGP、运营商路径、网络可达性和 Cloudflare 调度决定。

Cloudflare 的中国大陆方案是独立商业能力，通常涉及：

- Cloudflare China Network；
- 中国大陆合作伙伴和合规流程；
- ICP 或相关备案/资质；
- 面向动态 API 的 CDN Global Acceleration（旧称 China Express）等能力。

它不是普通橙云里的免费地区开关。即使开通中国网络，如果动态 API 的源站在新加坡，回源仍可能跨境，延迟不会自动消失。

中国大陆为主要用户时，建议按优先级测试：

1. 香港源站；
2. 日本东京源站；
3. 新加坡源站；
4. 中国大陆合规服务器；
5. Cloudflare China Network / CDN Global Acceleration 商业方案。

测试时记录：

- DNS 解析时间；
- TCP 建连时间；
- TLS 握手时间；
- TTFB；
- 总耗时；
- `CF-Ray` 末尾的 colo；
- HTTP 失败率和丢包；
- 直连源站与橙云的差异。

不要只根据 `Anycast` 字样判断慢点在哪里。慢可能来自客户端到 Cloudflare、Cloudflare 到源站、源站处理或 TLS 建连中的任一段。

## 11. 首次启动和后台初始化

### 11.1 验证服务

```bash
systemctl is-active jur10n-api.service
systemctl is-active caddy
curl -fsS https://server.example.com/healthz
curl -fsSI https://dashboard.example.com/
```

### 11.2 第一次登录

打开：

```text
https://dashboard.example.com
```

使用：

- 用户名：`ADMIN_USERNAME`；
- 初始密码：`/srv/jur10n/data/initial-admin-password` 中的内容。

第一次登录后必须立即修改密码。然后删除初始密码文件，并从 `/etc/jur10n/jur10n.env` 移除 `ADMIN_INITIAL_PASSWORD`（如果配置过）。

### 11.3 创建软件槽位

在 Dashboard：

1. 进入总览；
2. 新建软件槽位；
3. 填写唯一小写 slug，例如 `demo-app`；
4. 保持默认机器校验，除非业务明确不需要；
5. 设置 heartbeat timeout、session TTL 和 IP 策略；
6. 保存。

每个软件槽位会拥有独立：

- 软件密钥；
- 密钥版本；
- 卡密；
- 变量；
- 数据槽；
- 文件资源；
- 公告；
- 会话、绑定和安全策略。

`legacy` 是自动创建的兼容槽位，不要随意删除。API 文档是通用协议文档，不需要在文档页面切换软件；真正使用哪个槽位，由客户端 URL 中的 `{software_slot}` 决定。

### 11.4 导出软件密钥

软件密钥只在管理端设计的导出流程中获取一次。拿到后：

- 立即写入受控的客户端配置系统；
- 不要放进公开 Dashboard 静态资源；
- 不要提交到 Git；
- 不要打印完整密钥到日志；
- 如果丢失，只能按密钥生命周期重新生成/轮换，并重新下发给客户端。

## 12. 客户端和本地 PyQt 测试 GUI

### 12.1 安装 Python 环境

Windows 推荐 Python 3.12 或更新版本：

```powershell
py -3.12 -m venv .venv
.\.venv\Scripts\python.exe -m pip install -r examples\requirements.txt
```

运行：

```powershell
.\.venv\Scripts\python.exe examples\pyqt_client.py
```

也可以双击：

```text
run-pyqt-client.bat
```

该 bat 会调用项目根目录的 `.venv\Scripts\python.exe`。如果提示路径不存在，先按上面的命令创建虚拟环境。

Linux/macOS 示例：

```bash
python3.12 -m venv .venv
. .venv/bin/activate
python -m pip install -r examples/requirements.txt
python examples/pyqt_client.py
```

依赖：

```text
PyQt6
cryptography
requests
```

### 12.2 GUI 中填写的配置

在“会话”页填写：

```text
Base URL:       https://server.example.com
Software slot:  demo-app
Key version:    1
软件密钥:       管理端一次性导出的 32 字节 key 的 base64url
卡密:           该软件槽位生成的卡密
机器证明:       启用机器校验时填写，长度和字符集必须符合协议
```

GUI 默认值是本地开发值：

```text
http://127.0.0.1:3000
legacy
1
```

默认密钥为空，这是有意设计；示例程序不携带生产密钥，也不会自动知道朋友新服务器的密钥。

### 12.3 测试顺序

建议按以下顺序：

1. 点击“登录”；
2. 点击“心跳”；
3. 在“变量”页拉取变量；
4. 在“上报”页选择数据槽，测试 `overwrite`；
5. 再测试 `append`；
6. 在 Dashboard 查看接收历史和单码当前数据；
7. 在“文件”页获取 manifest；
8. 读取公开公告；
9. 填写文件 ID 和本地保存路径；
10. 下载并校验 SHA-256。

如果看到 `SESSION_INACTIVE`，先点击心跳或重新登录。密钥轮换、重置绑定和管理员撤销 session 后，客户端必须重新登录，不能无限重试旧 token。

## 13. v1 / v2 API 使用边界

完整契约见 `server/API.md`。核心区别：

### v1

```text
POST /api/v1/client
Content-Type: application/octet-stream
```

- 旧版全局资源/旧客户端；
- 使用 `MASTER_SECRET` 派生的旧协议密钥；
- 保留 `verify`、`pull_variables`、`report`；
- 与 v2 session、软件槽位隔离不互通；
- 不要把 v1 当作新客户端协议。

### v2

```text
POST /api/v2/client/{software_slot}
Content-Type: application/octet-stream
```

AES-256-GCM 包布局：

```text
12 字节随机 IV || ciphertext || 16 字节 GCM tag
```

请求 AAD：

```text
jur10n:client:v2:{software_slot}:{key_version}:request
```

响应 AAD：

```text
jur10n:client:v2:{software_slot}:{key_version}:response
```

每个 v2 请求都需要：

- `protocol: jur10n-client-v2`；
- `key_version`；
- Unix 毫秒 `timestamp`；
- 新的随机 `nonce`；
- `op`。

默认时间窗口：60 秒。登录成功后，除 `announcement` 外的操作需要：

- `session_token`；
- `session_id`；
- 机器证明（启用机器校验时）；
- 新 timestamp；
- 新 nonce。

错误也在加密响应中返回。客户端不要只看 HTTP 200；必须解密并检查响应中的 `ok`、`status` 和 `error`。

## 14. 数据槽和文件资源语义

### 14.1 数据槽

每个 `(software, data_slot, license)` 只有一条当前快照：

- `overwrite`：覆盖快照；
- `append`：对象浅层合并、数组拼接、字符串连接；
- 类型不兼容：`INVALID_APPEND`；
- 最终 UTF-8 JSON 快照超过 200 KiB：拒绝；
- 每次接收可在历史中留下记录；
- 清空接收历史不会删除单码当前快照。

### 14.2 文件资源

管理端上传任意文件资源后，客户端通过：

```text
manifest → file_chunk(offset, length) → SHA-256 校验
```

当前约束：

- 单次下载块最多 64 KiB；
- 一个文件名义上限 64 MiB；
- 文件内容不通过 Caddy 静态目录直接暴露；
- 存储名随机化；
- 数据库只保存元数据和相对存储路径；
- 删除资源会标记删除并清理磁盘文件；
- 实际资源总量仍受 VPS 磁盘、inode、备份空间和低水位限制。

## 15. 备份、升级和回滚

### 15.1 备份内容

至少备份：

- SQLite 数据库；
- SQLite WAL 一致性快照；
- `data/files` 文件资源；
- 当前 Caddyfile；
- systemd service 文件；
- `/etc/jur10n/jur10n.env`（必须加密保存，不能放公开仓库）；
- 代码和 Dashboard 构建产物的版本信息。

项目提供一致性备份脚本：

```bash
install -o root -g root -m 0700 \
  deploy/backup-jur10n.sh /usr/local/bin/jur10n-backup.sh

/usr/local/bin/jur10n-backup.sh
```

脚本会：

- 使用 SQLite backup API 生成一致性数据库副本；
- 执行 `PRAGMA quick_check`；
- 打包 `FILES_ROOT`；
- 以 0700/0600 权限保存；
- 按保留天数清理旧备份；
- 不上传外部服务；
- 不触碰 `/opt/starlight`。

安装定时任务前先检查 `deploy/starlight-sqlite-backup.cron` 中的路径和保留策略：

```bash
install -o root -g root -m 0644 \
  deploy/starlight-sqlite-backup.cron \
  /etc/cron.d/starlight-sqlite-backup
```

### 15.2 发布前备份

```bash
STAMP=$(date -u +%Y%m%dT%H%M%SZ)
mkdir -p /srv/jur10n/backups/pre-$STAMP
cp -a /etc/jur10n/jur10n.env /srv/jur10n/backups/pre-$STAMP/
cp -a /etc/systemd/system/jur10n-api.service /srv/jur10n/backups/pre-$STAMP/
cp -a /etc/caddy/Caddyfile /srv/jur10n/backups/pre-$STAMP/
/usr/local/bin/jur10n-backup.sh
```

复制新版本到 staging 目录，先做 `node --check`、依赖检查和 Dashboard 静态文件检查，再切换：

```bash
systemctl stop jur10n-api.service
mv /srv/jur10n/api /srv/jur10n/api.previous-$STAMP
mv /srv/jur10n/api-staging-$STAMP /srv/jur10n/api
chown -R jur10n:jur10n /srv/jur10n/api
systemctl start jur10n-api.service
curl --fail http://127.0.0.1:3000/healthz
systemctl reload caddy
```

更稳妥的线上发布顺序是：

1. 本地测试和构建；
2. 服务器备份；
3. 上传 staging；
4. 远端语法/权限/文件检查；
5. 原子替换 API；
6. 等待 `/healthz`；
7. 切换 Dashboard `dist`；
8. reload Caddy；
9. 验证公网；
10. 保留旧目录一段时间再清理。

### 15.3 回滚

如果新 API 无法健康启动：

```bash
systemctl stop jur10n-api.service
rm -rf /srv/jur10n/api.failed-$STAMP
mv /srv/jur10n/api.previous-$STAMP /srv/jur10n/api
chown -R jur10n:jur10n /srv/jur10n/api
systemctl start jur10n-api.service
curl --fail http://127.0.0.1:3000/healthz
```

如果数据库迁移已经执行，不能只回滚代码而假设 schema 自动回滚。必须先确认新代码是否只执行了向前兼容迁移；破坏性数据库恢复应从经过 `quick_check` 的备份恢复，并在停机窗口内操作。

## 15.4 VPN 模块（sing-box 订阅）

`vpn/` 目录是独立于 API 的可选模块：把 VPS 变成私人代理出口，并通过面板「VPN 订阅」页发放 Clash 订阅。协议为 VLESS+Reality（TCP 8443）和 Hysteria2（UDP 8443），服务端为 sing-box。

```bash
# 首次或重新生成/部署（在项目根目录运行）
node vpn/generate.mjs            # 首次生成 vpn/values.json 凭证
bash vpn/deploy.sh               # 幂等：装 sing-box、调内核、放行 8443、上传订阅、重载 Caddy

# 轮换全部凭证（所有客户端需重新导入）
node vpn/generate.mjs --rotate && bash vpn/deploy.sh
```

服务器侧落点：`/etc/sing-box/config.json`（600）、`/srv/jur10n/vpn/<token>.yaml`（订阅，token 即凭证）、`/srv/jur10n/data/vpn/meta.json`（面板 API 读取）、`/etc/sysctl.d/99-jur10n-vpn.conf`（BBR）。Caddyfile 中 `server.example.com` 的 `handle_path /vpn/*` 块由 `deploy.sh` 从 `deploy/Caddyfile` 同步。

排障：`systemctl status sing-box`、`journalctl -u sing-box -n 50`、`sing-box check -c /etc/sing-box/config.json`。注意这台服务器的系统 DNS 上游存在投毒（google 系域名曾被解析到错误 IP），sing-box 配置里已强制走 DoH（1.1.1.1 / 8.8.8.8 over TCP 443）并 `ipv4_only`，不要删掉 `dns` 段。

细节见 `vpn/README.md`。

## 16. 监控和排障

### API

```bash
systemctl status jur10n-api.service --no-pager
journalctl -u jur10n-api.service -n 200 --no-pager
curl -i http://127.0.0.1:3000/healthz
curl -i https://server.example.com/healthz
```

### Caddy

```bash
systemctl status caddy --no-pager
journalctl -u caddy -n 200 --no-pager
caddy validate --config /etc/caddy/Caddyfile
```

### 磁盘和 SQLite

```bash
df -h /srv/jur10n
df -i /srv/jur10n
sqlite3 /srv/jur10n/data/app.sqlite3 'PRAGMA quick_check;'
ls -la /srv/jur10n/data
```

### 常见问题

#### `Connection closed` 或 SSH 被拒绝

检查：

- VPN 是否改变了公网路径；
- SSH 端口是否正确；
- VPS 防火墙和 UFW 是否已放行该端口；
- 供应商是否要求使用 root 或指定管理员账号；
- `/run/sshd` 是否存在且权限为 0755；
- 服务器是否需要 `systemctl restart ssh.socket`。

不要在没有带外控制台的情况下反复修改 UFW。

#### `curl 127.0.0.1:3000` 失败

```bash
systemctl status jur10n-api.service --no-pager
journalctl -u jur10n-api.service -n 100 --no-pager
node --version
node --check /srv/jur10n/api/src/server.js
```

重点排查：

- Node 版本低于 24；
- `/etc/jur10n/jur10n.env` 不存在或权限错误；
- `MASTER_SECRET` 不是恰好 32 字节 base64url；
- `ExecStart` 路径不对；
- `jur10n` 无法写 `/srv/jur10n/data`；
- 数据库被错误恢复或 migration 失败。

#### Dashboard 返回 403 或空白

```bash
namei -l /srv/jur10n/dashboard/dist/index.html
find /srv/jur10n/dashboard/dist -maxdepth 2 -type f -ls
caddy validate --config /etc/caddy/Caddyfile
```

Caddy 必须能穿过 `/srv/jur10n/dashboard` 和 `dist` 目录：目录通常需要 0755，文件通常需要 0644。不要给静态目录设置 0700，否则 Caddy 无法读取。

#### Dashboard 加载失败、`/api/admin/software` 404

检查前端请求和服务端路由是否来自同一版本：

- 当前前端使用 canonical `/api/admin/software`；
- 服务端必须包含该集合路由；
- Caddy 的 `dashboard.example.com/api/*` 必须反代到 127.0.0.1:3000；
- 未登录时正确结果应为 401，而不是 `Route GET ... not found`。

#### PyQt 客户端无法登录

检查：

- Base URL 是否为 `https://server.example.com`，不要重复填写 `/api/v2/client`；
- Software slot 是否和 Dashboard 中的 slug 完全一致；
- key version 是否和导出的版本一致；
- 软件密钥是否是正确的 32 字节 base64url；
- 卡密是否属于同一个软件槽位；
- 机器证明是否符合格式；
- 客户端和服务器时间差是否超过 60 秒；
- Cloudflare 是否返回了 Challenge HTML 而不是二进制密文；
- 旧 session 是否因密钥轮换、重置绑定或 heartbeat 超时而失效。

#### Cloudflare 后变慢或返回 Challenge

先分别检查：

```bash
curl -fsSI https://dashboard.example.com/
curl -fsSI https://server.example.com/healthz
```

观察：

- `Server: cloudflare`；
- `CF-Ray`；
- `CF-Cache-Status`；
- HTTP 状态；
- TLS 和 TTFB。

动态 API 应保持 `DYNAMIC`/`no-store`。如果客户端遇到 Challenge，先检查 WAF/安全规则是否误套浏览器挑战，不要修改 AES 协议来适配挑战页。

#### 文件上传超过限制

当前管理上传是完整 base64 JSON：

- 64 MiB 是应用层名义单文件上限；
- Dashboard Caddy 的 86MB body limit 会让实际原始文件上限略低；
- `server.example.com` 全站 16MB body limit 更小；
- 单次下载分片 64KiB 与总文件大小无关。

优先使用 Dashboard 域名上传；不要直接把 Caddy/Fastify body limit 改成无限，除非同时重构成流式/分片上传并增加磁盘、并发和超时保护。

## 17. 安全底线

必须长期遵守：

1. 不修改现有 `ssjj-cookies` Worker，除非单独安排 Worker 变更；
2. 不把 `MASTER_SECRET`、软件 key、卡密、session token 写入日志；
3. 不把生产软件密钥写进 `dashboard/dist` 或客户端源码；
4. 不把数据库、文件资源或 `/srv/jur10n/data` 放进 Caddy 静态根目录；
5. Node 只监听 `127.0.0.1`；
6. 管理员使用 HTTPS、强密码和 CSRF；
7. 文件资源保留随机存储名、权限 0600 和路径校验；
8. 保留 SQLite + 文件的一致性备份；
9. 发布前保留旧版本和回滚路径；
10. Cloudflare Challenge 不得覆盖客户端二进制 API；
11. 服务器在中国大陆时，先处理备案、供应商和业务合规问题；
12. 任何删除数据库、删除文件、修改 UFW、切换 DNS 或恢复备份的操作，都要先确认目标和备份。

## 18. 新服务器交付验收清单

### 源站

- [ ] Ubuntu 版本和 CPU 架构正确；
- [ ] Node.js >= 24；
- [ ] `jur10n` 服务用户存在；
- [ ] `/srv/jur10n/api/src/server.js` 存在；
- [ ] `/etc/jur10n/jur10n.env` 权限 0600；
- [ ] `MASTER_SECRET` 是新生成且已安全备份的 32 字节密钥；
- [ ] `jur10n-api.service` active；
- [ ] `curl http://127.0.0.1:3000/healthz` 返回 200；
- [ ] Caddy active；
- [ ] Caddy 配置 validate 通过；
- [ ] SQLite `quick_check` 返回 ok；
- [ ] `/srv/jur10n/data/files` 可由服务用户写入；
- [ ] 备份脚本成功运行；
- [ ] UFW 只开放 SSH/80/443。

### Cloudflare

- [ ] `server.example.com` A 记录指向新源站；
- [ ] `dashboard.example.com` A 记录指向新源站；
- [ ] 初始 DNS-only 验证完成；
- [ ] SSL/TLS 为 Full (strict)；
- [ ] 两个记录切换橙云后 `/healthz` 仍为 200；
- [ ] API、管理 API、Dashboard HTML 不缓存；
- [ ] 客户端 API 不被 Browser/JS/Bot Challenge 拦截；
- [ ] 没有改动旧 Worker、KV、Durable Object 或旧 Worker 域名；
- [ ] 已从目标用户地区测量 DNS、TLS、TTFB、CF-Ray 和失败率；
- [ ] 中国大陆场景已单独评估 ICP、源站位置和 Cloudflare China Network 条件。

### 客户端

- [ ] 创建软件槽位；
- [ ] 导出并安全保存软件 key；
- [ ] 生成测试卡密；
- [ ] PyQt GUI 登录成功；
- [ ] heartbeat 成功；
- [ ] 变量读取成功；
- [ ] overwrite 和 append 成功；
- [ ] 公告读取成功；
- [ ] manifest 成功；
- [ ] 文件下载后 SHA-256 一致；
- [ ] 错误响应可以解密；
- [ ] 重复 nonce 被拒绝；
- [ ] 错误机器被拒绝；
- [ ] 管理端 reset binding 后旧 session 失效。

---

## 附录 A：与当前项目文件的对应关系

| 任务 | 文件 |
| --- | --- |
| 服务端启动 | `server/src/server.js` |
| SQLite 迁移 | `server/src/db.js` |
| 加密和 HMAC | `server/src/crypto.js` |
| API 契约 | `server/API.md` |
| Dashboard 路由和页面 | `dashboard/src/App.tsx` |
| Dashboard API 客户端 | `dashboard/src/api.ts` |
| Dashboard 样式 | `dashboard/src/styles.css` |
| PyQt v2 GUI | `examples/pyqt_client.py` |
| Python 依赖 | `examples/requirements.txt` |
| systemd | `deploy/starlight-api.service.template` |
| Caddy | `deploy/Caddyfile` |
| 环境模板 | `deploy/.env.example` |
| SQLite/文件备份 | `deploy/backup-jur10n.sh` |
| SQLite 备份 cron | `deploy/starlight-sqlite-backup.cron` |
| UFW | `deploy/ufw-setup.sh` |
| 旧 Worker | 同级目录 `../cfkv/`，不要在部署 VPS 时修改 |

## 附录 B：朋友拿到项目后的最短执行顺序

```text
1. 准备 Ubuntu 24.04 VPS、域名和 SSH key
2. 设置 DNS-only 的 server.example.com / dashboard.example.com
3. 安装 Node 24、Caddy、UFW、Python3、SQLite 工具
4. 创建 jur10n 用户和 /srv/jur10n 目录
5. 上传 server/ 和 dashboard/dist/
6. 生成新的 MASTER_SECRET
7. 写 /etc/jur10n/jur10n.env，确认变量名正确
8. 安装并启动 systemd
9. 确认 127.0.0.1:3000/healthz
10. 安装 Caddyfile，确认 HTTPS 和静态 Dashboard
11. 配置 UFW，只放行 SSH/80/443
12. Dashboard 首次登录并改密码
13. 创建软件槽位、导出 key、生成卡密
14. 本地安装 PyQt demo，填写新 URL/key/slot/code
15. 测试登录、heartbeat、变量、上报、公告、文件
16. 配置备份和 cron
17. 验收完成后再把 DNS 切到 Cloudflare Proxied
18. 配置 no-cache API 和跳过客户端 Challenge
19. 从目标用户地区做真实延迟测试
```
