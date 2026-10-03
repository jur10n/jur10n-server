#!/usr/bin/env node
// jur10n VPN：生成 sing-box 服务端配置、Clash 订阅 YAML 和面板元数据。
// 首次运行会生成凭证写入 vpn/values.json（已 gitignore），之后重复运行复用凭证。
// 用法：node vpn/generate.mjs          （复用/创建凭证）
//       node vpn/generate.mjs --rotate （重新生成全部凭证）

import { existsSync, mkdirSync, readFileSync, writeFileSync, readdirSync, unlinkSync } from 'node:fs'
import { generateKeyPairSync, randomBytes, randomUUID } from 'node:crypto'
import { dirname, join } from 'node:path'
import { fileURLToPath } from 'node:url'

const HERE = dirname(fileURLToPath(import.meta.url))
const VALUES_PATH = join(HERE, 'values.json')
const OUT_DIR = join(HERE, 'out')

// ==== 可调参数 ====
// TODO(需要补充)：SERVER_IP / API_DOMAIN 必须换成你自己的值才能生成可用产物。
// 本机私有做法：在 gitignored 的 vpn/values.json 里加 "serverIp" / "apiDomain" 字段，会优先于占位符。
const SERVER_IP_PLACEHOLDER = '<TODO:你的VPS公网IP>'
const API_DOMAIN_PLACEHOLDER = '<TODO:你的API域名>' // 例如 server.example.com
const NODE_NAME = '香港服务器'
const NODE_NAME_HY2 = `${NODE_NAME}-HY2`
const REALITY_PORT = 8443
const HY2_PORT = 8443
const REALITY_SNI = 'www.microsoft.com' // Reality 伪装域名（握手目标），需 TLS1.3 + HTTP/2
// =================

const b64url = (buf) => buf.toString('base64').replaceAll('+', '-').replaceAll('/', '_').replace(/=+$/, '')

function createValues() {
  const { privateKey, publicKey } = generateKeyPairSync('x25519')
  // PKCS8 / SPKI DER 的末 32 字节即裸密钥
  const privateRaw = privateKey.export({ type: 'pkcs8', format: 'der' }).subarray(-32)
  const publicRaw = publicKey.export({ type: 'spki', format: 'der' }).subarray(-32)
  return {
    uuid: randomUUID(),
    realityPrivateKey: b64url(privateRaw),
    realityPublicKey: b64url(publicRaw),
    shortId: randomBytes(8).toString('hex'),
    hy2Password: randomBytes(24).toString('base64url'),
    subToken: randomBytes(16).toString('hex'),
    createdAt: new Date().toISOString(),
  }
}

function loadValues(rotate) {
  if (!rotate && existsSync(VALUES_PATH)) {
    const values = JSON.parse(readFileSync(VALUES_PATH, 'utf8'))
    if (values.uuid && values.realityPrivateKey && values.realityPublicKey && values.shortId && values.hy2Password && values.subToken) {
      return values
    }
    console.warn('[vpn] values.json 不完整，重新生成凭证')
  }
  const values = createValues()
  writeFileSync(VALUES_PATH, `${JSON.stringify(values, null, 2)}\n`)
  console.log(`[vpn] 凭证已写入 ${VALUES_PATH}`)
  return values
}

function renderSingBoxConfig(values) {
  return {
    log: { level: 'warn', timestamp: true },
    // 服务端自带的 DoH 解析：这台 VPS 的系统 DNS 上游被投毒（google 曾被解析到 Facebook IP），
    // 走 TCP/443 的 DoH 绕开投毒，且强制 IPv4（VPS 无公网 IPv6）。
    dns: {
      servers: [
        { type: 'https', tag: 'doh-cloudflare', server: '1.1.1.1', server_port: 443, path: '/dns-query', tls: { server_name: 'cloudflare-dns.com' } },
        { type: 'https', tag: 'doh-google', server: '8.8.8.8', server_port: 443, path: '/dns-query', tls: { server_name: 'dns.google' } },
      ],
      final: 'doh-cloudflare',
      strategy: 'ipv4_only',
    },
    inbounds: [
      {
        type: 'vless',
        tag: 'vless-reality',
        listen: '::',
        listen_port: REALITY_PORT,
        users: [{ uuid: values.uuid, flow: 'xtls-rprx-vision' }],
        tls: {
          enabled: true,
          server_name: REALITY_SNI,
          reality: {
            enabled: true,
            handshake: { server: REALITY_SNI, server_port: 443 },
            private_key: values.realityPrivateKey,
            short_id: [values.shortId],
          },
        },
      },
      {
        type: 'hysteria2',
        tag: 'hysteria2',
        listen: '::',
        listen_port: HY2_PORT,
        masquerade: 'https://www.bing.com',
        ignore_client_bandwidth: true,
        users: [{ password: values.hy2Password }],
        tls: {
          enabled: true,
          alpn: ['h3'],
          certificate_path: '/etc/sing-box/cert.pem',
          key_path: '/etc/sing-box/key.pem',
        },
      },
    ],
    outbounds: [{ type: 'direct', tag: 'direct' }],
    route: { default_domain_resolver: { server: 'doh-cloudflare' } },
  }
}

// 国内直连域名（借鉴商业订阅的显式清单，配合 GEOSITE/GEOIP 兜底）
const CN_DIRECT = [
  '126.com', '126.net', '127.net', '163.com', '360buyimg.com', '36kr.com', 'acfun.tv', 'aicdn.com',
  'aliyun.com', 'alibaba.com', '1688.com', 'alipay.com', 'alicdn.com', 'amap.com', 'autonavi.com',
  'baidu.com', 'bdimg.com', 'bdstatic.com', 'bilibili.com', 'bilivideo.com', 'bytedance.com', 'bytednsdoc.com',
  'caiyunapp.com', 'cnbeta.com', 'cnblogs.com', 'csdn.net', 'ctrip.com', 'dianping.com', 'dingtalk.com',
  'douban.com', 'doubanio.com', 'douyin.com', 'duokan.com', 'ele.me', 'feishu.cn', 'gitee.com', 'gtimg.com',
  'hdslb.com', 'hupu.com', 'ifeng.com', 'iqiyi.com', 'ixigua.com', 'jd.com', 'jianshu.com', 'juejin.cn',
  'kuaishou.com', 'kugou.com', 'kuwo.cn', 'le.com', 'lianjia.com', 'lvmama.com', 'meituan.com', 'meizu.com',
  'mi.com', 'migu.cn', 'miguvideo.com', 'netease.com', 'nuomi.com', 'oppo.com', 'oschina.net', 'panda.tv',
  'qcloud.com', 'qidian.com', 'qq.com', 'qunar.com', 'sina.com.cn', 'sina.cn', 'sinaimg.cn', 'smzdm.com',
  'sogou.com', 'sohu.com', 'taobao.com', 'tencent.com', 'tencent-cloud.net', 'tmall.com', 'toutiao.com',
  'umeng.com', 'unionpay.com', 'vivo.com', 'wandoujia.com', 'weibo.com', 'xiaohongshu.com', 'xiaomi.com',
  'ximalaya.com', 'xinhuanet.com', 'xunlei.com', 'yeah.net', 'youku.com', 'zhihu.com', 'zhimg.com',
]

function renderSubscriptionYaml(values, generatedAt) {
  const proxyReality = `  - { name: '${NODE_NAME}', type: vless, server: ${SERVER_IP}, port: ${REALITY_PORT}, uuid: ${values.uuid}, udp: true, flow: xtls-rprx-vision, tls: true, skip-cert-verify: false, client-fingerprint: chrome, servername: ${REALITY_SNI}, reality-opts: { public-key: ${values.realityPublicKey}, short-id: ${values.shortId} } }`
  const proxyHy2 = `  - { name: '${NODE_NAME_HY2}', type: hysteria2, server: ${SERVER_IP}, port: ${HY2_PORT}, password: ${values.hy2Password}, udp: true, sni: ${HY2_SNI}, skip-cert-verify: true }`

  const rules = []
  rules.push(`  - 'DOMAIN-SUFFIX,local,DIRECT'`)
  ;[
    '127.0.0.0/8', '10.0.0.0/8', '172.16.0.0/12', '192.168.0.0/16', '100.64.0.0/10',
    '169.254.0.0/16', '224.0.0.0/4', '255.255.255.255/32', '119.29.29.29/32', '223.5.5.5/32',
  ].forEach((cidr) => rules.push(`  - 'IP-CIDR,${cidr},DIRECT,no-resolve'`))
  // 面板 / 本机 VPS 直连
  rules.push(`  - 'DOMAIN-SUFFIX,${API_DOMAIN},DIRECT'`)
  rules.push(`  - 'IP-CIDR,${SERVER_IP}/32,DIRECT,no-resolve'`)
  // Windows 连通性探测走直连
  rules.push(`  - 'DOMAIN-SUFFIX,msftconnecttest.com,DIRECT'`)
  rules.push(`  - 'DOMAIN-SUFFIX,msftncsi.com,DIRECT'`)
  // Google Play 国内特供域名必须走代理
  rules.push(`  - 'DOMAIN-SUFFIX,services.googleapis.cn,🚀 节点选择'`)
  rules.push(`  - 'DOMAIN-SUFFIX,xn--ngstr-lra8j.com,🚀 节点选择'`)
  // Apple：App Store / 系统服务走代理，其余直连
  ;[
    'developer.apple.com', 'ocsp.apple.com', 'doh.dns.apple.com', 'digicert.com', 'ocsp.sectigo.com',
    'ocsp.comodoca.com', 'ocsp.usertrust.com', 'ocsp.verisign.net', 'apple-dns.net', 'testflight.apple.com',
    'sandbox.itunes.apple.com', 'itunes.apple.com', 'apps.apple.com', 'blobstore.apple.com', 'cvws.icloud-content.com',
  ].forEach((domain) => rules.push(`  - 'DOMAIN-SUFFIX,${domain},🚀 节点选择'`))
  ;[
    'mzstatic.com', 'icloud.com', 'icloud-content.com', 'me.com', 'aaplimg.com', 'cdn-apple.com',
    'apple.com', 'apple-cloudkit.com', 'apple-mapkit.com',
  ].forEach((domain) => rules.push(`  - 'DOMAIN-SUFFIX,${domain},DIRECT'`))
  // 国内常见域名直连
  CN_DIRECT.forEach((domain) => rules.push(`  - 'DOMAIN-SUFFIX,${domain},DIRECT'`))
  rules.push(`  - 'GEOSITE,cn,DIRECT'`)
  rules.push(`  - 'GEOIP,CN,DIRECT'`)
  rules.push(`  - 'MATCH,🚀 节点选择'`)

  return `# jur10n 私人节点订阅 · ${NODE_NAME}
# 生成时间: ${generatedAt}
# 节点: ${NODE_NAME}（VLESS+Reality/TCP ${REALITY_PORT}）· ${NODE_NAME_HY2}（Hysteria2/UDP ${HY2_PORT}）
# 服务端: ${SERVER_IP} · 仅限本人设备使用，泄露请到面板重新生成
mixed-port: 7890
allow-lan: false
mode: rule
log-level: info
ipv6: false
unified-delay: true
tcp-concurrent: true
profile:
  store-selected: true
  store-fake-ip: true
dns:
  enable: true
  ipv6: false
  enhanced-mode: fake-ip
  fake-ip-range: 198.18.0.1/16
  use-hosts: true
  respect-rules: true
  fake-ip-filter: ['*.lan', '*.local', '*.arpa', 'time.*.com', 'ntp.*.com', '+.market.xiaomi.com', 'localhost.ptlogin2.qq.com']
  default-nameserver: [223.5.5.5, 119.29.29.29, 114.114.114.114]
  proxy-server-nameserver: [223.5.5.5, 119.29.29.29, 114.114.114.114]
  nameserver: [223.5.5.5, 119.29.29.29, 114.114.114.114]
  fallback: ['https://doh.dns.apple.com/dns-query', 'tls://8.8.8.8:853', 'tls://1.1.1.1:853', 'https://dns.google/dns-query']
  fallback-filter: { geoip: true, geoip-code: CN, ipcidr: [240.0.0.0/4], domain: ['+.google.com', '+.googleapis.com', '+.googlevideo.com', '+.youtube.com', '+.openai.com', '+.anthropic.com', '+.claude.ai', '+.twitter.com', '+.x.com', '+.instagram.com', '+.facebook.com', '+.telegram.org', '+.t.me', '+.wikipedia.org', '+.github.com', '+.githubusercontent.com'] }
proxies:
${proxyReality}
${proxyHy2}
proxy-groups:
  - { name: 🚀 节点选择, type: select, proxies: [${NODE_NAME}, ${NODE_NAME_HY2}, ♻️ 自动选择, DIRECT] }
  - { name: ♻️ 自动选择, type: url-test, url: 'http://www.gstatic.com/generate_204', interval: 300, tolerance: 80, proxies: [${NODE_NAME}, ${NODE_NAME_HY2}] }
rules:
${rules.join('\n')}
`
}

function renderMeta(values, generatedAt) {
  return {
    enabled: true,
    name: NODE_NAME,
    server: SERVER_IP,
    subscriptionUrl: `${SUB_ORIGIN}/vpn/${values.subToken}.yaml`,
    updatedAt: generatedAt,
    nodes: [
      { name: NODE_NAME, protocol: 'VLESS + Reality', transport: 'TCP', address: SERVER_IP, port: REALITY_PORT, camouflage: REALITY_SNI },
      { name: NODE_NAME_HY2, protocol: 'Hysteria2', transport: 'UDP', address: SERVER_IP, port: HY2_PORT, camouflage: HY2_SNI },
    ],
  }
}

const rotate = process.argv.includes('--rotate')
const values = loadValues(rotate)

// TODO(需要补充)：优先读 values.json 的 serverIp / apiDomain（本机私有，gitignored），否则保持占位符
const SERVER_IP = values.serverIp || SERVER_IP_PLACEHOLDER
const API_DOMAIN = values.apiDomain || API_DOMAIN_PLACEHOLDER
const SUB_ORIGIN = `https://${API_DOMAIN}` // Caddy 上 API 域名的 /vpn/* 静态目录
const HY2_SNI = API_DOMAIN // HY2 自签证书主机名（客户端 skip-cert-verify），需与 deploy.sh 的证书 CN 一致
if (SERVER_IP === SERVER_IP_PLACEHOLDER || API_DOMAIN === API_DOMAIN_PLACEHOLDER) {
  console.warn('[vpn] 警告：SERVER_IP / API_DOMAIN 仍是占位符（TODO），生成产物不可用于部署')
}

const generatedAt = new Date().toISOString()

mkdirSync(OUT_DIR, { recursive: true })
// 清掉旧 token 订阅，避免残留
for (const file of readdirSync(OUT_DIR)) {
  if (file.endsWith('.yaml') && file !== `${values.subToken}.yaml`) {
    unlinkSync(join(OUT_DIR, file))
  }
}

writeFileSync(join(OUT_DIR, 'sing-box.config.json'), `${JSON.stringify(renderSingBoxConfig(values), null, 2)}\n`)
writeFileSync(join(OUT_DIR, `${values.subToken}.yaml`), renderSubscriptionYaml(values, generatedAt))
writeFileSync(join(OUT_DIR, 'meta.json'), `${JSON.stringify(renderMeta(values, generatedAt), null, 2)}\n`)

console.log(`[vpn] sing-box 配置 : out/sing-box.config.json`)
console.log(`[vpn] 订阅文件     : out/${values.subToken}.yaml`)
console.log(`[vpn] 面板元数据   : out/meta.json`)
console.log(`[vpn] 订阅链接     : ${SUB_ORIGIN}/vpn/${values.subToken}.yaml`)
