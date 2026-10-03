# jur10n VPS 控制平面

独立 Linux VPS 上的后台。不是同级 `cfkv` 里的 `ssjj-cookies` Worker，也不是同级 `webpage` 里的公开站。

```text
客户端 / 浏览器
        │ HTTPS
        ▼
Caddy（公网 80/443）
        ├── dashboard 域名 /      → dashboard/dist
        ├── dashboard 域名 /api/* → 127.0.0.1:3000
        └── server 域名 /*        → 127.0.0.1:3000
                    │
                    ▼
Node.js 24 + Fastify + SQLite
```

Node 只监听 `127.0.0.1:3000`。`MASTER_SECRET`、管理员密码、软件密钥和卡密放在服务器的 `/etc/jur10n/jur10n.env`，不要写进这个目录。

## 目录

```text
jur10n-server/
├── server/                 # Fastify API，v1 / v2 客户端协议
│   ├── src/server.js
│   ├── src/db.js
│   ├── src/crypto.js
│   ├── test/
│   └── API.md              # 协议契约
├── dashboard/              # React + Vite 管理台
├── examples/               # PyQt6 v2 客户端
├── deploy/                 # Caddy、systemd、备份、UFW 模板
├── backups/                # 本地 VPS 快照，含密钥，不提交
├── run-pyqt-client.ps1
└── DEPLOYMENT_GUIDE.md     # 从零部署和迁移
```

## 本地

服务端：

```bash
cd server
npm install
npm test
npm run dev
```

管理台：

```bash
cd dashboard
npm install
npm run dev
```

PyQt 客户端：`run-pyqt-client.ps1`，或先 `pip install -r examples/requirements.txt` 再运行 `examples/pyqt_client.py`。虚拟环境在 `.venv/`。

换机器、换域名或换供应商时，按 [DEPLOYMENT_GUIDE.md](DEPLOYMENT_GUIDE.md) 做。日常改代码、加功能、对接 app、发布与回滚的流程见 [WORKFLOW.md](WORKFLOW.md)（一键发布：`bash deploy/release.sh api|web|all`）。协议细节在 [server/API.md](server/API.md)。

## 公开仓库说明：需要补充的占位符

真实 IP、域名、供应商、凭证已全部抹去（git 历史重写过，提交邮箱换成 GitHub noreply）。部署前把代码和配置里的 `TODO(需要补充)` 占位符全部换成你自己的值：

| 位置 | 要填的内容 |
| --- | --- |
| `vpn/generate.mjs` 顶部 | `SERVER_IP`、`API_DOMAIN` 占位符（推荐写进 gitignored 的 `vpn/values.json` 的 `serverIp`/`apiDomain` 字段） |
| `vpn/deploy.sh` | 创建 gitignored 的 `vpn/deploy.env`：`VPS_IP` / `API_ORIGIN` / `SSH_KEY` |
| `deploy/Caddyfile` | 两个站点域名（本机真实配置放 gitignored 的 `deploy/Caddyfile.local`，`deploy.sh` 会优先使用） |
| `server/src/server.js` | `DASHBOARD_ORIGIN`（建议在服务器 env 里覆盖为你的后台域名） |
| `dashboard/src/App.tsx` | 界面上展示的 API 域名 |
| `server/debug-e2e.mjs` | 用 `BASE_URL` 指向你的 API 域名 |

凭证类（`vpn/values.json`、`vpn/out/`、`server/initial-admin-password`、SQLite 文件、`backups/`）被 `.gitignore` 挡住，永远不入库。
