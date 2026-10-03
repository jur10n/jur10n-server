# jur10n VPN 模块

把你自己的 VPS（TODO(需要补充)：填入公网 IP）变成私人代理出口，并通过面板「VPN 订阅」页发放 Clash 订阅链接。

- 协议：`香港服务器` = VLESS + Reality（TCP 8443，伪装 TLS 到 www.microsoft.com）；`香港服务器-HY2` = Hysteria2（UDP 8443，自签证书 + skip-cert-verify）。同一台服务器、同一个出口 IP。
- 服务端：sing-box（`/etc/sing-box/config.json`），systemd 服务 `sing-box`。
- 订阅分发：Caddy 在 `server.example.com`（TODO(需要补充)：你的 API 域名）上把 `/vpn/*` 映射到 `/srv/jur10n/vpn/`（token 文件名即凭证，`Cache-Control: no-store`）。
- 面板：Fastify `GET /api/admin/vpn`（requireAdmin）读取 `/srv/jur10n/data/vpn/meta.json`；Dashboard `/vpn` 页展示订阅链接、二维码和导入步骤。

## 文件

| 文件 | 说明 |
| --- | --- |
| `generate.mjs` | 生成凭证（首次写 `values.json`）+ sing-box 配置 + Clash 订阅 YAML + 面板元数据，输出到 `out/` |
| `values.json` | 凭证（UUID / Reality 密钥对 / short-id / HY2 密码 / 订阅 token）+ 本机 `serverIp`/`apiDomain` 覆盖，已 gitignore |
| `deploy.env` | 本机部署参数（`VPS_IP` / `API_ORIGIN` / `SSH_KEY`），需要自己创建，已 gitignore |
| `deploy.sh` | 幂等部署：安装 sing-box、BBR/UDP 调优、UFW 放行 8443、上传配置与订阅、重载 Caddy、重启 sing-box |
| `out/` | 生成产物（含秘密，已 gitignore） |

## 日常操作

> TODO(需要补充)：首次部署前先创建 `vpn/deploy.env`，并在 `vpn/values.json` 里补上 `serverIp` / `apiDomain` 字段（两个文件都已 gitignore，不入库）。

```bash
# 重新生成并部署（改节点名/端口/规则后）
node vpn/generate.mjs && bash vpn/deploy.sh

# 轮换全部凭证（所有客户端需重新导入订阅）
node vpn/generate.mjs --rotate && bash vpn/deploy.sh
```

## 服务器侧位置

- sing-box 配置：`/etc/sing-box/config.json`（600，root），证书 `/etc/sing-box/{cert,key}.pem`
- 订阅文件：`/srv/jur10n/vpn/<token>.yaml`（部署时会清掉旧 token 文件）
- 面板元数据：`/srv/jur10n/data/vpn/meta.json`（jur10n 属主）
- 内核调优：`/etc/sysctl.d/99-jur10n-vpn.conf`（BBR + fq + 16MB UDP 缓冲）

## 注意

- 改了订阅内容只跑 `deploy.sh` 里的上传步骤也行，但保持整脚本幂等直接全跑即可。
- 订阅 YAML 的分流规则在 `generate.mjs` 的 `renderSubscriptionYaml` 里维护（国内直连清单 + GEOSITE/GEOIP 兜底 + MATCH 走节点选择）。
- 客户端至少需要 mihomo 内核（FlClash / Clash Verge Rev 均满足）：用到了 `vless.reality-opts`、`hysteria2`、`GEOSITE`。
