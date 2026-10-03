#!/usr/bin/env bash
# jur10n VPN 部署：把生成的 sing-box 配置、Clash 订阅、面板元数据推到 VPS。
# 幂等：可重复运行。首次运行会安装 sing-box、调优内核参数、放行端口。
# 用法：bash vpn/deploy.sh
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# TODO(需要补充)：首次使用请创建 vpn/deploy.env（已 gitignore）：
#   VPS_IP=你的VPS公网IP
#   API_ORIGIN=https://你的API域名
#   SSH_KEY=你的SSH私钥路径
if [ -f "$HERE/deploy.env" ]; then . "$HERE/deploy.env"; fi
KEY="${SSH_KEY:-$HOME/.ssh/id_ed25519}"
IP="${VPS_IP:?需要补充：先在 vpn/deploy.env 或环境变量中设置 VPS_IP=你的VPS公网IP}"
API_ORIGIN="${API_ORIGIN:-https://server.example.com}" # TODO(需要补充)：你的 API 域名（与 generate.mjs 的 apiDomain 一致）
SSH="ssh -i $KEY -o StrictHostKeyChecking=accept-new root@$IP"
SCP="scp -i $KEY -o StrictHostKeyChecking=accept-new"
OUT="$HERE/out"
# 本机私有覆盖：gitignored 的 deploy/Caddyfile.local（含真实域名）优先于入库模板
CADDYFILE="$HERE/../deploy/Caddyfile"
if [ -f "$HERE/../deploy/Caddyfile.local" ]; then CADDYFILE="$HERE/../deploy/Caddyfile.local"; fi

[ -f "$OUT/sing-box.config.json" ] || { echo "缺少 $OUT/sing-box.config.json，先运行: node vpn/generate.mjs"; exit 1; }
SUBFILE="$(ls "$OUT"/*.yaml | head -1)"
SUBNAME="$(basename "$SUBFILE")"

echo "==> 1/7 VPS 引导（sing-box / 内核参数 / 防火墙）"
$SSH 'bash -s' <<'BOOTSTRAP'
set -euo pipefail
if ! command -v sing-box >/dev/null 2>&1; then
  TMP="$(mktemp -d)"
  curl -fsSL --max-time 20 -o "$TMP/release.json" https://api.github.com/repos/SagerNet/sing-box/releases/latest
  VER="$(grep -m1 '"tag_name"' "$TMP/release.json" | cut -d'"' -f4)"
  echo "安装 sing-box ${VER} ..."
  curl -fsSL --max-time 120 -o "$TMP/sb.tar.gz" "https://github.com/SagerNet/sing-box/releases/download/${VER}/sing-box-${VER#v}-linux-amd64.tar.gz"
  tar -xzf "$TMP/sb.tar.gz" -C "$TMP"
  install -m 0755 "$TMP"/sing-box-*/sing-box /usr/local/bin/sing-box
  rm -rf "$TMP"
fi
sing-box version

if [ ! -f /etc/systemd/system/sing-box.service ]; then
  cat > /etc/systemd/system/sing-box.service <<'UNIT'
[Unit]
Description=sing-box service
Documentation=https://sing-box.sagernet.org
After=network.target nss-lookup.target

[Service]
CapabilityBoundingSet=CAP_NET_ADMIN CAP_NET_BIND_SERVICE
AmbientCapabilities=CAP_NET_ADMIN CAP_NET_BIND_SERVICE
NoNewPrivileges=true
ExecStart=/usr/local/bin/sing-box run -c /etc/sing-box/config.json
Restart=on-failure
RestartSec=10
LimitNOFILE=infinity

[Install]
WantedBy=multi-user.target
UNIT
  systemctl daemon-reload
  systemctl enable sing-box >/dev/null
fi

if [ ! -f /etc/sysctl.d/99-jur10n-vpn.conf ]; then
  cat > /etc/sysctl.d/99-jur10n-vpn.conf <<'SYSCTL'
net.core.default_qdisc = fq
net.ipv4.tcp_congestion_control = bbr
net.core.rmem_max = 16777216
net.core.wmem_max = 16777216
SYSCTL
fi
sysctl -q --system
sysctl -n net.ipv4.tcp_congestion_control

ufw allow 8443/tcp comment 'vless-reality' >/dev/null 2>&1 || true
ufw allow 8443/udp comment 'hysteria2' >/dev/null 2>&1 || true
mkdir -p /etc/sing-box /srv/jur10n/vpn /srv/jur10n/data/vpn
echo BOOTSTRAP_OK
BOOTSTRAP

echo "==> 2/7 上传 sing-box 配置 / 订阅 / 元数据"
$SSH "mkdir -p /etc/sing-box /srv/jur10n/vpn /srv/jur10n/data/vpn"
(cd "$OUT" && $SCP sing-box.config.json "root@$IP:/etc/sing-box/config.json")
(cd "$OUT" && $SCP "$SUBNAME" "root@$IP:/srv/jur10n/vpn/$SUBNAME")
(cd "$OUT" && $SCP meta.json "root@$IP:/srv/jur10n/data/vpn/meta.json")

echo "==> 3/7 自签证书与权限"
$SSH "bash -s -- '$SUBNAME' '$API_DOMAIN'" <<'PERMS'
set -euo pipefail
SUBNAME="$1"
API_DOMAIN="$2" # TODO(需要补充)：来自 API_ORIGIN 的域名，与 generate.mjs 的 HY2_SNI 保持一致
if [ ! -f /etc/sing-box/cert.pem ]; then
  openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 \
    -keyout /etc/sing-box/key.pem -out /etc/sing-box/cert.pem \
    -days 3650 -nodes -subj "/CN=${API_DOMAIN}" \
    -addext "subjectAltName=DNS:${API_DOMAIN}"
fi
chmod 600 /etc/sing-box/config.json /etc/sing-box/key.pem
chmod 644 /etc/sing-box/cert.pem
find /srv/jur10n/vpn -maxdepth 1 -name '*.yaml' ! -name "$SUBNAME" -delete
chmod 755 /srv/jur10n/vpn
chmod 644 "/srv/jur10n/vpn/$SUBNAME"
chown -R jur10n:jur10n /srv/jur10n/data/vpn
chmod 644 /srv/jur10n/data/vpn/meta.json
echo PERMS_OK
PERMS

echo "==> 4/7 同步 Caddyfile 并重载"
if [ -f "$CADDYFILE" ]; then
  $SCP "$CADDYFILE" "root@$IP:/etc/caddy/Caddyfile"
fi
$SSH 'caddy validate --config /etc/caddy/Caddyfile --adapter caddyfile >/dev/null && systemctl reload caddy && echo CADDY_OK'

echo "==> 5/7 sing-box 校验并重启"
$SSH 'sing-box check -c /etc/sing-box/config.json && systemctl restart sing-box && sleep 1 && systemctl is-active sing-box && ss -tulnp | grep -E "8443" || true'

echo "==> 6/7 本机自检（出口 IP 对比）"
$SSH 'curl -s --max-time 8 https://api.ipify.org; echo " <- VPS 出口"; ip -4 addr show scope global | grep -oP "inet \K[\d.]+"' || true

echo "==> 7/7 订阅可达性"
curl -fsS --max-time 15 -o /tmp/jur10n-sub-check.yaml "$API_ORIGIN/vpn/$SUBNAME" && sed -n '1,5p' /tmp/jur10n-sub-check.yaml
echo
echo "完成。订阅链接: $API_ORIGIN/vpn/$SUBNAME"
