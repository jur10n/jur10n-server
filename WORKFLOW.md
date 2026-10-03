# jur10n-server 变更与发布工作流

> 给"经常对接 app、改后台、加功能"的日常开发用。安全底线见 [SECURITY.md](SECURITY.md)，完整迁移见 [DEPLOYMENT_GUIDE.md](DEPLOYMENT_GUIDE.md)。

## 0. 一张图

```text
改代码 → 本地测试 → git push（CI 自动测试+构建）
                    ↓
        bash deploy/release.sh api|web|all
                    ↓
   上传 staging → lockfile 判定依赖 → node --check
                    ↓
        停服 → 原子切换 → 起服 → healthz 门闸
                    ↓
        通过：清理旧版本（保留 3 份）      失败：自动回滚 + 旧版本恢复健康
```

回滚永远可用：`bash deploy/release.sh rollback`（后端）/ `rollback x web`（前端）。`bash deploy/release.sh status` 随时看当前版本和可回滚列表。

## 1. 日常小修（改逻辑、改文案、修 bug）

```bash
# 1. 改 server/src/... 或 dashboard/src/...
# 2. 本地验证
cd server && node --test          # 后端必须 8/8（数量会随用例增长）
cd ../dashboard && npm run build  # 前端必须零 TS 错误
# 3. git commit + push（CI 再跑一遍，绿了才算数）
# 4. 发布
bash deploy/release.sh api        # 只改后端
bash deploy/release.sh web        # 只改前端
bash deploy/release.sh all        # 都改了
# 5. 验证
curl -fsS https://<API域名>/healthz
```

单人项目直接在 `main` 上干没问题；大改动先开分支，CI 绿了再合。

## 2. 新增后端功能 checklist（按顺序，缺一步发布后就得多跑一轮）

1. **协议先行**：新增的是客户端 v2 `op` 还是管理端 `/api/admin/...`？先把请求/响应字段写进 `server/API.md`（含错误码）。
2. **数据库**：`server/src/db.js` 加**幂等迁移**（`CREATE TABLE IF NOT EXISTS` / `hasColumn` 判定）。只增不改，迁移执行过的库上必须能重复跑。
3. **路由**：`server/src/server.js`
   - 管理端路由挂 `{ preHandler: requireAdmin }` 或 `requireOwnerMutation`（写操作一律 owner）；
   - 客户端 v2 新 op：加进 `ALLOWED_OPS`，走既有解密封包流程，响应必须加密返回；
   - 体积上限：能设 `bodyLimit` 就设，别吃全局默认；
   - 关键动作埋 `audit(db, {...})`。
4. **测试**：`server/test/` 加用例。**鉴权必须覆盖**：未登录/低权角色访问新路由要断言 401/403。
5. **前端**（如涉及）：`dashboard/src/api.ts` 加 client 方法（走 `request`，二进制体直接传 Blob），`App.tsx` 加页面/入口。
6. **文档**：API.md 同步；动了安全机制（鉴权、加密、限流、上传）就更新 `SECURITY.md` 对应段落。
7. **发布**：`bash deploy/release.sh api`（脚本会强制先跑本地测试）。
8. **线上冒烟**：healthz + 新接口手工打一发（管理接口用 dashboard 点一遍）。

## 3. 对接一个新 app（v2 客户端）

1. Dashboard → 总览 → 新建软件槽位（唯一小写 slug），按需设置机器校验/IP 策略/heartbeat/session TTL；
2. **导出软件密钥**（只在导出流程出现一次，当场存进客户端配置系统，别进 Git/日志）；
3. 生成测试卡密；
4. 客户端实现走 v2 协议：AES-256-GCM、AAD `jur10n:client:v2:{slot}:{key_version}:{direction}`、每次新 timestamp（±60s）+ nonce、登录后带 session token——拿 `examples/pyqt_client.py` 当参考实现；
5. 测试顺序：login → heartbeat → pull_variables → report(overwrite/append) → announcement → manifest → file_chunk+SHA-256 校验；
6. 确认密钥轮换/重置绑定后旧 session 立即失效（Dashboard 操作一遍）。

> v1 协议默认已禁用（410）。老 app 只会说 v1 时，临时在服务器 `/etc/jur10n/jur10n.env` 加 `ENABLE_V1_PROTOCOL=1` 重启，同时尽快迁移。

## 4. 出问题怎么办

```bash
bash deploy/release.sh status              # 看当前版本 + 可回滚列表
bash deploy/release.sh rollback            # 后端回到上一个版本
bash deploy/release.sh rollback <stamp> web # dashboard 回到指定版本
journalctl -u jur10n-api -n 100 --no-pager # 服务日志
```

数据库迁移是**只向前**的：回滚代码不会回滚 schema。破坏性恢复必须用 `jur10n-backup.sh` 的备份在停机窗口做。

## 5. CI

`.github/workflows/ci.yml`：push/PR 自动跑服务端测试 + dashboard 构建。**CI 红了不要发布**；CI 绿 ≠ 可以发布（CI 不含部署，发布永远走 `release.sh`，密钥不上 GitHub）。

## 6. 什么时候值得上"多智能体 workflow"

ZCode 里还有一种动态 workflow（编排多个子 agent 并行拆任务）。它适合**一次性的大工程**，比如：

- "重构上传协议为流式 + 全量回归 + API.md/SECURITY.md 同步更新"这种横跨多文件、可并行的改造；
- 大规模代码审计/批量迁移（每轮升级协议、批量加测试）。

日常发版和小功能**不要**用——脚本 + CI 更快、更稳、零 token 成本。大活要跑的时候，直接说"用 workflow 干 XX"即可。
