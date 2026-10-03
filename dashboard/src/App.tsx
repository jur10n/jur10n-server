import { FormEvent, ReactNode, createContext, useContext, useEffect, useMemo, useState } from 'react'
import {
  Activity, AlertTriangle, ArrowDownToLine, ArrowLeft, ArrowUpRight, BookOpen,
  CheckCircle2, ChevronRight, Clipboard, Copy, Database, Download, Eye,
  EyeOff, FileKey2, FileText, Gauge, Globe, KeyRound, LayoutDashboard, LockKeyhole, LogOut,
  Menu, Moon, MoreHorizontal, Package, Plus, QrCode, RefreshCw, RotateCw, Save, Search,
  ServerCog, Settings2, ShieldCheck, Sun, Trash2, Upload, UserCircle2, Variable,
  Wifi, X, XCircle,
} from 'lucide-react'
import {
  api, ApiError, asList, asRecord, type AuditEntry, type ClientSession,
  type DataSlot, type DataUsage, type DataStoreRecord, type Announcement, type License, type MonitoringSnapshot, type ReceiveSettings,
  type RemoteVariable, type Report, type ResourceFile, type SecuritySettings,
  type SoftwareKey, type SoftwareSlot, type SoftwareSlotForm, type User, type VpnInfo,
} from './api'
import { toDataURL } from 'qrcode'
import './styles.css'

type Theme = 'dark' | 'light'
type SlotPage = 'overview' | 'variables' | 'licenses' | 'data' | 'files' | 'security'
type Route = { scope: 'slots' | 'slot' | 'docs' | 'monitoring' | 'security' | 'audit' | 'custom' | 'vpn'; slug?: string; page?: SlotPage }
type Toast = { type: 'success' | 'error' | 'info'; message: string }
type AdminRole = 'owner' | 'operator' | 'viewer'
type RoleCapabilities = { role: AdminRole; canOperate: boolean; canOwn: boolean }

const RoleContext = createContext<RoleCapabilities>({ role: 'viewer', canOperate: false, canOwn: false })
const useRole = () => useContext(RoleContext)
function capabilitiesFor(role?: string): RoleCapabilities {
  const normalized: AdminRole = role === 'owner' || role === 'operator' ? role : 'viewer'
  return { role: normalized, canOperate: normalized !== 'viewer', canOwn: normalized === 'owner' }
}

type ConfirmRequest = { kind: 'confirm'; title: string; message: string; confirmLabel?: string; danger?: boolean; resolve: (ok: boolean) => void }
type PromptField = { key: string; label: string; placeholder?: string; type?: string; required?: boolean; initial?: string; hint?: string }
type PromptRequest = { kind: 'prompt'; title: string; message?: string; fields: PromptField[]; confirmLabel?: string; resolve: (values: Record<string, string> | null) => void }
type DialogRequest = ConfirmRequest | PromptRequest

const DialogsContext = createContext<{
  confirm: (options: { title: string; message: string; confirmLabel?: string; danger?: boolean }) => Promise<boolean>
  prompt: (options: { title: string; message?: string; fields: PromptField[]; confirmLabel?: string }) => Promise<Record<string, string> | null>
}>({ confirm: async () => false, prompt: async () => null })

const useDialogs = () => useContext(DialogsContext)

const slotNavigation: Array<{ id: SlotPage; label: string; icon: typeof LayoutDashboard; hint: string }> = [
  { id: 'overview', label: '软件概览', icon: LayoutDashboard, hint: '状态与密钥' },
  { id: 'variables', label: '内部变量', icon: Variable, hint: '运行时配置' },
  { id: 'licenses', label: '卡密管理', icon: FileKey2, hint: '生成、绑定与会话' },
  { id: 'data', label: '数据槽', icon: Database, hint: '上报与用量' },
  { id: 'files', label: '文件资源', icon: Package, hint: '任意文件分发' },
  { id: 'security', label: '软件安全', icon: ShieldCheck, hint: '机器与 IP 策略' },
]

function parseLocation(): Route {
  const parts = window.location.pathname.split('/').filter(Boolean)
  if (parts[0] === 'security') return { scope: 'security' }
  if (parts[0] === 'audit') return { scope: 'audit' }
  if (parts[0] === 'custom') return { scope: 'custom' }
  if (parts[0] === 'vpn') return { scope: 'vpn' }
  if (parts[0] === 'docs') return { scope: 'docs' }
  if (parts[0] === 'monitoring') return { scope: 'monitoring' }
  if (parts[0] === 'software' && parts[1]) return { scope: 'slot', slug: decodeURIComponent(parts[1]), page: (parts[2] as SlotPage) || 'overview' }
  return { scope: 'slots' }
}

function App() {
  const [route, setRoute] = useState<Route>(() => parseLocation())
  const [theme, setTheme] = useState<Theme>(() => {
    try {
      const saved = window.localStorage.getItem('jur10n.dashboard.theme')
      if (saved === 'dark' || saved === 'light') return saved
    } catch { /* use system preference */ }
    return window.matchMedia?.('(prefers-color-scheme: dark)').matches ? 'dark' : 'light'
  })
  const [user, setUser] = useState<User | null>(null)
  const [checkingSession, setCheckingSession] = useState(true)
  const [toast, setToast] = useState<Toast | null>(null)
  const [mobileNavOpen, setMobileNavOpen] = useState(false)
  const [refreshKey, setRefreshKey] = useState(0)
  const [slots, setSlots] = useState<SoftwareSlot[]>([])
  const [slotsLoading, setSlotsLoading] = useState(true)
  const [slotError, setSlotError] = useState('')
  const [slotModal, setSlotModal] = useState<SoftwareSlot | 'new' | null>(null)
  const [expandedSlots, setExpandedSlots] = useState<Set<string>>(() => new Set())
  const [dialog, setDialog] = useState<DialogRequest | null>(null)

  useEffect(() => {
    const onPopState = () => setRoute(parseLocation())
    window.addEventListener('popstate', onPopState)
    return () => window.removeEventListener('popstate', onPopState)
  }, [])
  useEffect(() => {
    document.documentElement.dataset.theme = theme
    try { window.localStorage.setItem('jur10n.dashboard.theme', theme) } catch { /* ignore storage errors */ }
  }, [theme])
  useEffect(() => {
    api.me().then((payload) => setUser(payload.user)).catch(() => setUser(null)).finally(() => setCheckingSession(false))
  }, [])
  useEffect(() => {
    if (!toast) return
    const timer = window.setTimeout(() => setToast(null), 4200)
    return () => window.clearTimeout(timer)
  }, [toast])
  useEffect(() => {
    if (!user) return
    let alive = true
    setSlotsLoading(true)
    setSlotError('')
    api.softwareSlots().then((payload) => {
      if (alive) setSlots(asList<SoftwareSlot>(payload, ['slots', 'softwareSlots']))
    }).catch((error) => {
      if (alive) {
        setSlots([])
        setSlotError(getErrorMessage(error, '软件槽位加载失败'))
      }
    }).finally(() => { if (alive) setSlotsLoading(false) })
    return () => { alive = false }
  }, [user, refreshKey])

  const navigate = (path: string) => {
    window.history.pushState({}, '', path)
    setRoute(parseLocation())
    setMobileNavOpen(false)
  }
  const notify = (next: Toast) => setToast(next)

  const dialogApi = useMemo(() => ({
    confirm: (options: { title: string; message: string; confirmLabel?: string; danger?: boolean }) => new Promise<boolean>((resolve) => {
      setDialog({ kind: 'confirm', ...options, resolve })
    }),
    prompt: (options: { title: string; message?: string; fields: PromptField[]; confirmLabel?: string }) => new Promise<Record<string, string> | null>((resolve) => {
      setDialog({ kind: 'prompt', ...options, resolve })
    }),
  }), [])
  const closeDialog = (payload: unknown) => {
    if (!dialog) return
    if (dialog.kind === 'confirm') (dialog.resolve as (value: unknown) => void)(payload === true)
    else (dialog.resolve as (value: unknown) => void)(payload)
    setDialog(null)
  }

  if (checkingSession) return <div className="loading-screen"><span className="loading-spinner" />正在连接控制台…</div>

  if (!user) return <LoginScreen onLogin={async (username, password) => { const payload = await api.login(username, password); setUser(payload.user) }} />

  if (user.mustChangePassword) {
    return <ChangePasswordScreen user={user} onLogout={async () => { await api.logout(); setUser(null) }} onComplete={() => setUser({ ...user, mustChangePassword: false })} onError={notify} />
  }

  const currentSlot = route.slug ? slots.find((slot) => slot.slug === route.slug) : undefined
  const title = route.scope === 'slots' ? '软件槽位'
    : route.scope === 'slot' ? slotNavigation.find((item) => item.id === route.page)?.label || '软件概览'
    : route.scope === 'docs' ? 'API 文档'
    : route.scope === 'monitoring' ? '软件监控'
    : route.scope === 'security' ? '全局安全'
    : route.scope === 'custom' ? '自定义区域'
    : route.scope === 'vpn' ? 'VPN 订阅'
    : '审计日志'

  const capabilities = capabilitiesFor(user.role)

  return (
    <RoleContext.Provider value={capabilities}>
      <DialogsContext.Provider value={dialogApi}>
        <div className="app-shell">
        <nav className={`sidebar ${mobileNavOpen ? 'sidebar-open' : ''}`}>
          <div className="brand"><div className="brand-mark"><span>j</span></div><div className="brand-copy"><strong>jur10n 控制台</strong><small>control plane</small></div><button className="icon-button sidebar-close" onClick={() => setMobileNavOpen(false)} aria-label="关闭导航"><X size={16} /></button></div>
          <p className="workspace-label">工作台</p>
          <div className="main-nav">
            <button className={`nav-item root-nav ${route.scope === 'slots' ? 'active' : ''}`} onClick={() => navigate('/')}><LayoutDashboard size={16} />总览</button>
          </div>
          {slots.length > 0 && <p className="workspace-label">软件槽位</p>}
          <div className="slot-tree">
            {slots.map((slot) => {
              const selected = route.scope === 'slot' && route.slug === slot.slug
              const expanded = expandedSlots.has(slot.slug)
              return <div className="slot-tree-item" key={slot.slug}>
                <div className={`slot-switcher ${selected ? 'selected' : ''}`}>
                  <button className="slot-main" onClick={() => navigate(`/software/${encodeURIComponent(slot.slug)}/overview`)}>
                    <span className="slot-avatar">{slot.name.slice(0, 1).toUpperCase()}</span>
                    <span className="slot-switcher-copy"><strong>{slot.name}</strong><small>{slot.slug}</small></span>
                  </button>
                  <button className="slot-expander" aria-label={expanded ? '折叠槽位' : '展开槽位'} aria-expanded={expanded} onClick={() => setExpandedSlots((current) => { const next = new Set(current); if (next.has(slot.slug)) next.delete(slot.slug); else next.add(slot.slug); return next })}>
                    <ChevronRight size={13} style={{ transform: expanded ? 'rotate(90deg)' : 'none', transition: 'transform .16s ease' }} />
                  </button>
                </div>
                {expanded ? <div className="slot-subnav">
                  {slotNavigation.map((item) => <button key={item.id} className={route.page === item.id ? 'active' : ''} onClick={() => navigate(`/software/${encodeURIComponent(slot.slug)}/${item.id}`)}>{item.label}</button>)}
                </div> : null}
              </div>
            })}
            <button className="nav-item add-slot" onClick={() => setSlotModal('new')}><Plus size={15} />新建软件槽位</button>
          </div>
          <div className="sidebar-divider" />
          <div className="secondary-nav">
            <button className={`nav-item ${route.scope === 'docs' ? 'active' : ''}`} onClick={() => navigate('/docs')}><BookOpen size={16} />API 文档</button>
            <button className={`nav-item ${route.scope === 'monitoring' ? 'active' : ''}`} onClick={() => navigate('/monitoring')}><Activity size={16} />软件监控</button>
            <button className={`nav-item ${route.scope === 'security' ? 'active' : ''}`} onClick={() => navigate('/security')}><ShieldCheck size={16} />全局安全</button>
            <button className={`nav-item ${route.scope === 'audit' ? 'active' : ''}`} onClick={() => navigate('/audit')}><FileText size={16} />审计日志</button>
            <button className={`nav-item ${route.scope === 'custom' ? 'active' : ''}`} onClick={() => navigate('/custom')}><Settings2 size={16} />自定义区域</button>
            <button className={`nav-item ${route.scope === 'vpn' ? 'active' : ''}`} onClick={() => navigate('/vpn')}><Globe size={16} />VPN 订阅</button>
          </div>
          <div className="sidebar-spacer" />
          {/* TODO(需要补充)：API 域名占位符，替换成你的域名 */}
          <div className="connection-status"><span className="status-pulse" /><span><strong>API 在线</strong><small>server.example.com</small></span><Wifi size={15} /></div>
          <div className="sidebar-footer"><span className="secure-label"><LockKeyhole size={12} />HTTPS · AES-GCM</span><span>v2</span></div>
        </nav>
        {mobileNavOpen && <button className="nav-overlay" onClick={() => setMobileNavOpen(false)} aria-label="关闭导航" />}
        <main className="main-content">
          <header className="topbar">
            <div className="breadcrumb">
              <button className="menu-button icon-button" onClick={() => setMobileNavOpen(true)} aria-label="打开导航"><Menu size={17} /></button>
              {route.scope === 'slot' && <><button className="breadcrumb-link" onClick={() => navigate('/')}>总览</button><ChevronRight size={13} /><strong>{currentSlot?.name || route.slug}</strong></>}
              {route.scope !== 'slot' && <strong>{title}</strong>}
            </div>
            <div className="topbar-actions">
              <button className="icon-button" onClick={() => setRefreshKey((key) => key + 1)} title="刷新数据"><RefreshCw size={15} /></button>
              <button className="theme-toggle" onClick={() => setTheme(theme === 'dark' ? 'light' : 'dark')} title="切换主题">{theme === 'dark' ? <Sun size={15} /> : <Moon size={15} />}</button>
              <div className="user-menu">
                <span className="avatar"><UserCircle2 size={17} /></span>
                <span className="user-copy"><strong>{user.username}</strong><small>{user.role === 'owner' ? '所有者' : user.role === 'operator' ? '操作员' : '观察者'}</small></span>
                <button className="icon-button" title="退出登录" onClick={() => void (async () => { if (await dialogApi.confirm({ title: '退出登录', message: '确定要退出当前管理员会话吗？', confirmLabel: '退出', danger: true })) { try { await api.logout() } catch { /* session already gone */ } setUser(null) } })()}><LogOut size={15} /></button>
              </div>
            </div>
          </header>
          <div className="page-body">
            {route.scope === 'slots' && <SlotsOverview slots={slots} slotError={slotError} loading={slotsLoading} onNavigate={navigate} onCreate={() => setSlotModal('new')} onEdit={(slot) => setSlotModal(slot)} refresh={() => setRefreshKey((key) => key + 1)} notify={notify} />}
            {route.scope === 'slot' && route.slug && (currentSlot
              ? <SlotWorkspace slot={currentSlot} page={route.page || 'overview'} refreshKey={refreshKey} onNavigate={navigate} onEdit={() => setSlotModal(currentSlot)} onDeleted={() => { setSlotModal(null); notify({ type: 'success', message: '软件槽位已删除' }); navigate('/') }} refresh={() => setRefreshKey((key) => key + 1)} notify={notify} />
              : <NotFoundSlot onBack={() => navigate('/')} />)}
            {route.scope === 'docs' && <DocsPage />}
            {route.scope === 'monitoring' && <MonitoringPage refreshKey={refreshKey} />}
            {route.scope === 'security' && <GlobalSecurityPage refreshKey={refreshKey} notify={notify} />}
            {route.scope === 'audit' && <AuditPage refreshKey={refreshKey} />}
            {route.scope === 'custom' && <CustomAreaPage />}
            {route.scope === 'vpn' && <VpnPage refreshKey={refreshKey} notify={notify} />}
          </div>
        </main>
      </div>
      {slotModal && <SlotModal slot={slotModal === 'new' ? null : slotModal} onClose={() => setSlotModal(null)} onSaved={(saved) => {
        setSlotModal(null)
        if (saved?.slug && slotModal === 'new') {
          setSlots((current) => current.some((item) => item.slug === saved.slug) ? current.map((item) => item.slug === saved.slug ? { ...item, ...saved } : item) : [saved, ...current])
          navigate(`/software/${encodeURIComponent(saved.slug)}/overview`)
        } else setRefreshKey((key) => key + 1)
      }} notify={notify} />}
      {toast && <ToastMessage toast={toast} onClose={() => setToast(null)} />}
      {dialog && (dialog.kind === 'confirm'
        ? <Modal eyebrow={dialog.danger ? 'CONFIRM / DANGER' : 'CONFIRM'} title={dialog.title} onClose={() => closeDialog(false)}>
            <p className="modal-body">{dialog.message}</p>
            <div className="modal-actions stick">
              <button className="button secondary" onClick={() => closeDialog(false)}>取消</button>
              <button className={`button ${dialog.danger ? 'danger' : 'primary'}`} onClick={() => closeDialog(true)}>{dialog.confirmLabel || '确认'}</button>
            </div>
          </Modal>
        : <PromptModal request={dialog} onClose={closeDialog} />)}
      </DialogsContext.Provider>
    </RoleContext.Provider>
  )
}

function PromptModal({ request, onClose }: { request: PromptRequest; onClose: (values: Record<string, string> | null) => void }) {
  const [values, setValues] = useState<Record<string, string>>(() => Object.fromEntries(request.fields.map((field) => [field.key, field.initial || ''])))
  const submit = (event: FormEvent) => {
    event.preventDefault()
    for (const field of request.fields) if (field.required && !values[field.key]?.trim()) return
    onClose(values)
  }
  return <Modal eyebrow="INPUT" title={request.title} onClose={() => onClose(null)}>
    {request.message && <p className="modal-body">{request.message}</p>}
    <form className="modal-form" onSubmit={submit}>
      {request.fields.map((field) => <label key={field.key}>{field.label}
        {field.type === 'textarea'
          ? <textarea rows={3} value={values[field.key] || ''} placeholder={field.placeholder} onChange={(event) => setValues({ ...values, [field.key]: event.target.value })} />
          : <input type={field.type || 'text'} value={values[field.key] || ''} placeholder={field.placeholder} onChange={(event) => setValues({ ...values, [field.key]: event.target.value })} autoFocus={request.fields[0]?.key === field.key} />}
        {field.hint && <small className="muted">{field.hint}</small>}
      </label>)}
      <div className="modal-actions stick">
        <button type="button" className="button secondary" onClick={() => onClose(null)}>取消</button>
        <button className="button primary">{request.confirmLabel || '确定'}</button>
      </div>
    </form>
  </Modal>
}

function LoginScreen({ onLogin }: { onLogin: (username: string, password: string) => Promise<void> }) {
  const [username, setUsername] = useState('')
  const [password, setPassword] = useState('')
  const [visible, setVisible] = useState(false)
  const [error, setError] = useState('')
  const [working, setWorking] = useState(false)
  const submit = async (event: FormEvent) => { event.preventDefault(); setWorking(true); setError(''); try { await onLogin(username, password) } catch (error) { setError(getErrorMessage(error, '登录失败，请检查用户名和密码')) } finally { setWorking(false) } }
  return <div className="login-shell"><div className="login-grid" /><div className="login-card">
    <div className="login-brand"><div className="brand-mark"><span>j</span></div>jur10n 控制台 <i>control plane</i></div>
    <div className="login-heading"><p className="eyebrow"><span className="eyebrow-dot" />SECURE ADMIN</p><h1>登录管理后台</h1><p>仅限所有者与操作员访问。所有写操作均记录审计。</p></div>
    <form className="login-form" onSubmit={submit}>
      <label>用户名<input value={username} onChange={(event) => setUsername(event.target.value)} placeholder="owner" autoFocus /></label>
      <label>密码<span className="input-with-action"><input type={visible ? 'text' : 'password'} value={password} onChange={(event) => setPassword(event.target.value)} placeholder="管理员密码" /><button type="button" onClick={() => setVisible(!visible)} aria-label={visible ? '隐藏密码' : '显示密码'}>{visible ? <EyeOff size={15} /> : <Eye size={15} />}</button></span></label>
      {error && <p className="inline-error" style={{ margin: 0 }}><AlertTriangle size={15} />{error}</p>}
      <button className="button primary login-button" disabled={working || !username || !password}>{working ? <span className="button-spinner" /> : '登录'}</button>
    </form>
    <p className="login-hint"><LockKeyhole size={12} />HTTPS · AES-256-GCM 客户端协议 · 审计留痕</p>
  </div><p className="login-footer">jur10n control plane · server.example.com</p></div>
}

function ChangePasswordScreen({ user, onLogout, onComplete, onError }: { user: User; onLogout: () => Promise<void>; onComplete: () => void; onError: (toast: Toast) => void }) {
  const [password, setPassword] = useState('')
  const [confirm, setConfirm] = useState('')
  const [saving, setSaving] = useState(false)
  const submit = async (event: FormEvent) => { event.preventDefault(); if (password.length < 14) return onError({ type: 'error', message: '新密码至少需要 14 个字符' }); if (password !== confirm) return onError({ type: 'error', message: '两次输入的密码不一致' }); setSaving(true); try { await api.changePassword(password); onComplete() } catch (error) { onError({ type: 'error', message: getErrorMessage(error, '密码修改失败') }) } finally { setSaving(false) } }
  return <div className="login-shell"><div className="login-grid" /><div className="login-card"><div className="login-brand"><div className="brand-mark"><span>j</span></div>jur10n 控制台 <i>first login</i></div><div className="login-heading"><p className="eyebrow"><span className="eyebrow-dot" />FIRST LOGIN</p><h1>更新管理员密码</h1><p>账号 {user.username} 的初始密码只能使用一次。</p></div><form onSubmit={submit} className="login-form"><label>新密码<input type="password" autoComplete="new-password" value={password} onChange={(event) => setPassword(event.target.value)} placeholder="至少 14 个字符" autoFocus /></label><label>确认新密码<input type="password" autoComplete="new-password" value={confirm} onChange={(event) => setConfirm(event.target.value)} placeholder="再次输入新密码" /></label><button className="button primary login-button" disabled={saving}>{saving ? '保存中…' : '保存新密码'}</button></form><button className="button secondary login-button" onClick={() => void onLogout()}>退出登录</button></div></div>
}

function SlotsOverview({ slots, slotError, loading, onNavigate, onCreate, onEdit, refresh, notify }: { slots: SoftwareSlot[]; slotError: string; loading: boolean; onNavigate: (path: string) => void; onCreate: () => void; onEdit: (slot: SoftwareSlot) => void; refresh: () => void; notify: (toast: Toast) => void }) {
  const { confirm } = useDialogs()
  const remove = async (slot: SoftwareSlot) => {
    if (!await confirm({ title: `删除 ${slot.name}`, message: `将永久删除软件槽位 ${slot.slug} 及其全部卡密、变量、数据槽、文件与会话。该操作不可恢复。`, confirmLabel: '永久删除', danger: true })) return
    try { await api.deleteSoftwareSlot(slot.slug); notify({ type: 'success', message: `${slot.name} 已删除` }); refresh() } catch (error) { notify({ type: 'error', message: getErrorMessage(error, '删除失败') }) }
  }
  return <>
    <div className="overview-banner"><div><p className="eyebrow"><span className="eyebrow-dot" />SOFTWARE INVENTORY</p><h2>以槽位隔离每个客户端产品</h2><p>密钥、卡密、变量、数据槽和文件均按软件边界管理。</p></div><button className="button primary" onClick={onCreate}><Plus size={15} />新建软件</button></div>
    {slotError && <InlineError message={slotError} />}
    <div className="section-toolbar"><span className="count-label">{loading ? '同步中…' : `${slots.length} 个软件槽位`}</span><span className="toolbar-note"><ShieldCheck size={13} /> 所有变更写入审计</span></div>
    {loading ? <div className="slot-card-grid"><SlotSkeleton /><SlotSkeleton /><SlotSkeleton /></div>
      : slots.length === 0 ? <section className="panel"><EmptyState icon={ServerCog} title="还没有软件槽位" description="创建第一个槽位，开始隔离客户端资源。" action={<button className="button primary small" onClick={onCreate}><Plus size={14} />创建槽位</button>} /></section>
      : <div className="slot-card-grid">{slots.map((slot) => <SoftwareCard slot={slot} key={slot.slug} onOpen={() => onNavigate(`/software/${encodeURIComponent(slot.slug)}/overview`)} onEdit={() => onEdit(slot)} onDelete={() => void remove(slot)} />)}</div>}
  </>
}

function SoftwareCard({ slot, onOpen, onEdit, onDelete }: { slot: SoftwareSlot; onOpen: () => void; onEdit: () => void; onDelete: () => void }) {
  const [menuOpen, setMenuOpen] = useState(false)
  const enabled = slot.enabled !== false && slot.status !== 'disabled'
  return <article className={`software-card ${!enabled ? 'disabled' : ''}`}>
    <div className="software-card-top"><div className="slot-avatar large">{slot.name.slice(0, 1).toUpperCase()}</div>
      <div className="software-card-title"><div><h2>{slot.name}</h2><code>{slot.slug}</code></div>
        <div style={{ display: 'flex', alignItems: 'center', gap: 6 }}>
          <StatusBadge status={enabled ? 'active' : 'disabled'} />
          <div style={{ position: 'relative' }}>
            <button className="icon-button" onClick={() => setMenuOpen(!menuOpen)} title="更多操作"><MoreHorizontal size={17} /></button>
            {menuOpen && <div style={{ position: 'absolute', right: 0, top: 32, zIndex: 5, display: 'grid', minWidth: 132, padding: 6, gap: 2, border: '1px solid var(--line)', borderRadius: 10, background: 'var(--panel-strong)', boxShadow: 'var(--shadow)' }}>
              <button className="button ghost small" onClick={() => { setMenuOpen(false); onEdit() }}><Settings2 size={13} />编辑设置</button>
              <button className="button ghost small" style={{ color: 'var(--red)' }} onClick={() => { setMenuOpen(false); onDelete() }}><Trash2 size={13} />删除槽位</button>
            </div>}
          </div>
        </div>
      </div>
    </div>
    <p className="software-description">{slot.description || '暂无描述'}</p>
    <div className="software-card-metrics"><Metric label="卡密" value={slot.licenseCount} /><Metric label="变量" value={slot.variableCount} /><Metric label="数据槽" value={slot.dataSlotCount} /><Metric label="会话" value={slot.activeSessions} /></div>
    <div className="software-card-bottom"><span className="fingerprint"><KeyRound size={12} /> {slot.keyFingerprint ? truncate(slot.keyFingerprint, 16) : '密钥待配置'}</span>
      <div><button className="button secondary small" onClick={onOpen}>打开 <ArrowUpRight size={13} /></button></div>
    </div>
  </article>
}
function SlotSkeleton() { return <div className="software-card skeleton-card"><span className="skeleton" /><span className="skeleton" /><span className="skeleton" /><span className="skeleton" /></div> }

function SlotModal({ slot, onClose, onSaved, notify }: { slot: SoftwareSlot | null; onClose: () => void; onSaved: (slot?: SoftwareSlot) => void; notify: (toast: Toast) => void }) {
  const [form, setForm] = useState<SoftwareSlotForm>({ slug: slot?.slug || '', name: slot?.name || '', description: slot?.description || '', enabled: slot?.enabled !== false, machineCheck: slot?.machineCheck !== false, ipCheck: Boolean(slot?.ipCheck), ipChangePolicy: slot?.ipChangePolicy || 'allow', heartbeatTimeout: slot?.heartbeatTimeout || 300, sessionTtl: slot?.sessionTtl || 86400, freeSoftware: Boolean(slot?.freeSoftware) })
  const [saving, setSaving] = useState(false)
  const update = (key: keyof SoftwareSlotForm, value: unknown) => setForm((current) => ({ ...current, [key]: value }))
  const submit = async (event: FormEvent) => {
    event.preventDefault(); setSaving(true)
    try { const saved = slot ? await api.updateSoftwareSlot(slot.slug, form) : await api.createSoftwareSlot(form as SoftwareSlotForm); onSaved(asRecord<SoftwareSlot>(saved)) }
    catch (error) { notify({ type: 'error', message: getErrorMessage(error, '槽位保存失败') }) } finally { setSaving(false) }
  }
  return <Modal eyebrow={slot ? 'SLOT / EDIT' : 'SLOT / CREATE'} title={slot ? '编辑软件槽位' : '新建软件槽位'} onClose={onClose}>
    <form className="modal-form" onSubmit={submit}>
      <div className="form-row"><label>公开 slug<input required pattern="[a-z0-9][a-z0-9-]{1,63}" disabled={Boolean(slot)} value={form.slug} onChange={(event) => update('slug', event.target.value)} placeholder="my-product" /></label><label>显示名称<input required value={form.name || ''} onChange={(event) => update('name', event.target.value)} placeholder="我的软件" /></label></div>
      <label>描述<textarea rows={2} value={form.description || ''} onChange={(event) => update('description', event.target.value)} placeholder="用于识别此客户端产品" /></label>
      <div className="form-row"><label>心跳超时（秒）<input type="number" min="30" value={form.heartbeatTimeout} onChange={(event) => update('heartbeatTimeout', Number(event.target.value))} /></label><label>会话 TTL（秒）<input type="number" min="300" value={form.sessionTtl} onChange={(event) => update('sessionTtl', Number(event.target.value))} /></label></div>
      <div className="check-grid"><label className="checkbox-label"><input type="checkbox" checked={Boolean(form.enabled)} onChange={(event) => update('enabled', event.target.checked)} />启用槽位</label><label className="checkbox-label"><input type="checkbox" checked={Boolean(form.machineCheck)} onChange={(event) => update('machineCheck', event.target.checked)} />校验机器指纹</label><label className="checkbox-label"><input type="checkbox" checked={Boolean(form.ipCheck)} onChange={(event) => update('ipCheck', event.target.checked)} />校验客户端 IP</label>{!slot && <label className="checkbox-label"><input type="checkbox" checked={Boolean(form.freeSoftware)} onChange={(event) => update('freeSoftware', event.target.checked)} />免费软件（仅创建时可设置，机器码登录）</label>}{slot && <span className="status-badge">{form.freeSoftware ? '免费软件' : '卡密软件'}</span>}</div>
      <div className="modal-actions"><button type="button" className="button secondary" onClick={onClose}>取消</button><button className="button primary" disabled={saving}>{saving ? '保存中…' : <><Save size={15} />保存槽位</>}</button></div>
    </form>
  </Modal>
}

function CustomAreaPage() {
  return <section className="panel panel-pad">
    <p className="eyebrow"><span className="eyebrow-dot" />CUSTOM AREA</p>
    <h2>定制 API 区域</h2>
    <p className="lede">这里独立于软件槽位。当前只保留入口，后续通过 SSH 在服务端 `src/custom` 增加明确的路由模块。</p>
    <p className="muted">健康检查：<code>/api/custom/healthz</code> · VPN 模块已上线：<a href="/vpn" onClick={(event) => { event.preventDefault(); window.history.pushState({}, '', '/vpn'); window.dispatchEvent(new PopStateEvent('popstate')) }}>打开 VPN 订阅</a></p>
  </section>
}

function VpnPage({ refreshKey, notify }: { refreshKey: number; notify: (toast: Toast) => void }) {
  const [vpn, setVpn] = useState<VpnInfo | null>(null)
  const [loading, setLoading] = useState(true)
  const [qr, setQr] = useState('')
  const [copied, setCopied] = useState(false)

  useEffect(() => {
    let alive = true
    setLoading(true)
    api.vpn()
      .then((info) => { if (alive) setVpn(info) })
      .catch((error) => { if (alive) setVpn({ enabled: false, message: getErrorMessage(error, 'VPN 信息加载失败') }) })
      .finally(() => { if (alive) setLoading(false) })
    return () => { alive = false }
  }, [refreshKey])

  const subscriptionUrl = vpn?.subscriptionUrl || ''
  useEffect(() => {
    if (!subscriptionUrl) { setQr(''); return }
    let alive = true
    toDataURL(subscriptionUrl, { width: 240, margin: 1, errorCorrectionLevel: 'M', color: { dark: '#141210', light: '#ffffff' } })
      .then((dataUrl) => { if (alive) setQr(dataUrl) })
      .catch(() => { if (alive) setQr('') })
    return () => { alive = false }
  }, [subscriptionUrl])

  if (loading) return <section className="panel panel-pad">
    <p className="eyebrow"><span className="eyebrow-dot" />VPN SUBSCRIPTION</p>
    <h2>VPN 订阅</h2>
    <VariableLoading />
  </section>

  if (!vpn?.enabled) return <section className="panel">
    <EmptyState icon={Globe} title="VPN 模块未就绪" description={vpn?.message || '服务端尚未生成订阅文件：在项目目录运行 node vpn/generate.mjs 后执行 bash vpn/deploy.sh。'} />
  </section>

  const copySubscription = async () => {
    try {
      await copyText(subscriptionUrl)
      setCopied(true)
      notify({ type: 'success', message: '订阅链接已复制' })
      window.setTimeout(() => setCopied(false), 2200)
    } catch (error) {
      notify({ type: 'error', message: getErrorMessage(error, '复制失败') })
    }
  }

  return <div className="vpn-layout">
    <section className="panel panel-pad vpn-main">
      <div className="section-heading">
        <div>
          <p className="eyebrow"><span className="eyebrow-dot" />VPN SUBSCRIPTION</p>
          <h2>{vpn.name || '香港服务器'}</h2>
          <p className="section-description">私有出口节点 <code>{vpn.server}</code>，导入订阅即可使用。Reality 走 TCP 稳定，HY2 走 UDP 适合移动网络。</p>
        </div>
        <ShieldCheck size={18} className="green-icon" />
      </div>
      <div className="vpn-link-row">
        <code className="vpn-link">{subscriptionUrl}</code>
        <button className="button primary small" onClick={() => void copySubscription()}>{copied ? <CheckCircle2 size={14} /> : <Copy size={14} />}{copied ? '已复制' : '复制链接'}</button>
      </div>
      <div className="vpn-actions">
        <button className="button secondary small" onClick={() => window.open(subscriptionUrl, '_blank', 'noopener')}><ArrowUpRight size={14} />打开订阅文件</button>
        <span className="toolbar-note"><LockKeyhole size={13} />链接即凭证，泄露后在服务端重新生成</span>
      </div>
      <div className="vpn-nodes">
        {(vpn.nodes || []).map((node) => <div className="vpn-node" key={String(node.name)}>
          <div className="vpn-node-head">
            <strong>{node.name}</strong>
            <span className="status-badge active"><span />{node.transport || 'TCP'}</span>
          </div>
          <span className="vpn-node-meta">{node.protocol} · {node.address}:{node.port}</span>
          {node.camouflage ? <span className="vpn-node-meta">TLS 伪装 · {node.camouflage}</span> : null}
        </div>)}
      </div>
    </section>
    <section className="panel panel-pad vpn-side">
      <div className="section-heading">
        <div>
          <p className="eyebrow"><span className="eyebrow-dot" />QUICK IMPORT</p>
          <h2>扫码导入</h2>
        </div>
        <QrCode size={17} className="muted-icon" />
      </div>
      {qr ? <div className="vpn-qr"><img src={qr} alt="VPN 订阅二维码" width={220} height={220} /></div> : <p className="muted">二维码生成中…</p>}
      <ol className="vpn-steps">
        <li>手机 FlClash：「配置」→ 右下角「+」→「导入 URL」</li>
        <li>粘贴订阅链接或扫描二维码，保存后选中 <strong>{vpn.name || '香港服务器'}</strong></li>
        <li>桌面 Clash Verge：「订阅」→ 粘贴链接导入</li>
      </ol>
      <div className="check-list">
        <CheckItem title="协议入口" detail={`${(vpn.nodes || []).length} 个（同一出口 IP）`} />
        <CheckItem title="订阅更新时间" detail={formatDate(vpn.updatedAt)} />
      </div>
    </section>
  </div>
}

function SlotWorkspace({ slot, page, refreshKey, onNavigate, onEdit, onDeleted, refresh, notify }: { slot: SoftwareSlot; page: SlotPage; refreshKey: number; onNavigate: (path: string) => void; onEdit: () => void; onDeleted: () => void; refresh: () => void; notify: (toast: Toast) => void }) {
  const { confirm } = useDialogs()
  const remove = async () => {
    if (!await confirm({ title: `删除 ${slot.name}`, message: `将永久删除 ${slot.slug} 及其全部卡密、变量、数据槽、文件与会话。该操作不可恢复。`, confirmLabel: '永久删除', danger: true })) return
    try { await api.deleteSoftwareSlot(slot.slug); onDeleted() } catch (error) { notify({ type: 'error', message: getErrorMessage(error, '删除失败') }) }
  }
  return <>
    {page === 'overview' && <SlotOverviewPage slot={slot} refreshKey={refreshKey} onNavigate={onNavigate} onEdit={onEdit} onDelete={() => void remove()} notify={notify} />}
    {page === 'variables' && <VariablesPage slug={slot.slug} refreshKey={refreshKey} notify={notify} />}
    {page === 'licenses' && <LicensesPage slug={slot.slug} refreshKey={refreshKey} notify={notify} />}
    {page === 'data' && <DataPage slug={slot.slug} refreshKey={refreshKey} notify={notify} />}
    {page === 'files' && <FilesPage slug={slot.slug} refreshKey={refreshKey} notify={notify} />}
    {page === 'security' && <SoftwareSecurityPage slug={slot.slug} refreshKey={refreshKey} notify={notify} />}
  </>
}

function SlotOverviewPage({ slot, refreshKey, onNavigate, onEdit, onDelete, notify }: { slot: SoftwareSlot; refreshKey: number; onNavigate: (path: string) => void; onEdit: () => void; onDelete: () => void; notify: (toast: Toast) => void }) {
  const [keys, setKeys] = useState<SoftwareKey[]>([])
  const [detail, setDetail] = useState<SoftwareSlot>(slot)
  const [announcement, setAnnouncement] = useState('')
  const [announcementUpdatedAt, setAnnouncementUpdatedAt] = useState<string | null>(null)
  const [loading, setLoading] = useState(true)
  const [working, setWorking] = useState(false)
  const { confirm, prompt } = useDialogs()
  useEffect(() => {
    let alive = true; setLoading(true)
    Promise.all([api.softwareSlot(slot.slug), api.softwareKeys(slot.slug), api.getAnnouncement(slot.slug)]).then(([slotPayload, keyPayload, announcementPayload]) => {
      if (!alive) return; setDetail({ ...slot, ...asRecord<SoftwareSlot>(slotPayload) }); setKeys(asList<SoftwareKey>(keyPayload, ['keys', 'items'])); const nextAnnouncement = asRecord<Announcement>(announcementPayload); setAnnouncement(String(nextAnnouncement.announcement || '')); setAnnouncementUpdatedAt(nextAnnouncement.updatedAt || null)
    }).catch(() => { if (alive) setKeys([]) }).finally(() => { if (alive) setLoading(false) })
    return () => { alive = false }
  }, [slot.slug, refreshKey])
  const rotate = async () => {
    if (!await confirm({ title: '轮换软件密钥', message: '轮换会生成新版本密钥并撤销所有现有客户端会话，旧客户端将必须重新导入配置。继续？', confirmLabel: '轮换' })) return
    setWorking(true)
    try { await api.rotateSoftwareKey(slot.slug); window.location.reload() } catch (error) { alert2(notify, error, '密钥轮换失败'); setWorking(false) }
  }
  const exportConfig = async () => {
    setWorking(true)
    try {
      const version = keys.find((key) => key.status === 'active')?.version
      if (version === undefined) throw new Error('没有可导出的有效密钥')
      const payload = await api.exportSoftwareConfig(slot.slug, version)
      const text = formatPayload(payload)
      await copyText(text)
      notify({ type: 'success', message: '客户端配置已复制（密钥只能导出一次）' })
    } catch (error) { alert2(notify, error, '配置导出失败') } finally { setWorking(false) }
  }
  const rename = async () => {
    const values = await prompt({ title: '编辑显示信息', fields: [{ key: 'name', label: '显示名称', initial: detail.name, required: true }, { key: 'description', label: '描述', initial: detail.description || '' }], confirmLabel: '保存' })
    if (!values) return
    try { const updated = await api.updateSoftwareSlot(slot.slug, { name: values.name, description: values.description }); setDetail({ ...detail, ...asRecord<SoftwareSlot>(updated) }); notify({ type: 'success', message: '已保存' }) } catch (error) { alert2(notify, error, '保存失败') }
  }
  const saveAnnouncement = async () => {
    setWorking(true)
    try { const result = await api.updateAnnouncement(slot.slug, announcement); setAnnouncementUpdatedAt(result.updatedAt || new Date().toISOString()); notify({ type: 'success', message: '公告已保存，客户端无需登录即可读取' }) }
    catch (error) { alert2(notify, error, '公告保存失败') } finally { setWorking(false) }
  }
  return <>
    <section className="panel panel-pad announcement-panel">
      <div className="section-heading"><div><p className="eyebrow"><span className="eyebrow-dot" />PUBLIC ANNOUNCEMENT</p><h2>软件公告</h2><p className="desc">客户端可以在未登录状态下读取公告；内容仍通过软件密钥加密传输。</p></div><span className="count-label">{announcementUpdatedAt ? `更新于 ${formatDate(announcementUpdatedAt)}` : '尚未发布'}</span></div>
      <textarea className="announcement-input" rows={3} value={announcement} onChange={(event) => setAnnouncement(event.target.value)} placeholder="例如：当前版本正在维护，请稍后重试。" />
      <div className="announcement-actions"><span className="muted">公开公告不携带 session token，仅校验软件密钥、时间戳和 nonce。</span><button className="button primary small" onClick={() => void saveAnnouncement()} disabled={working}><Save size={13} />保存公告</button></div>
    </section>
    <div className="slot-hero">
      <div className="slot-hero-main"><div className="slot-avatar xlarge">{detail.name.slice(0, 1).toUpperCase()}</div>
        <div><div className="slot-title-line"><h2>{detail.name}</h2><StatusBadge status={detail.enabled === false ? 'disabled' : 'active'} /></div>
          <code className="mono muted" style={{ fontSize: 12 }}>/{detail.slug} · {detail.protocolVersion || 'jur10n-client-v2'}</code>
          <p>{detail.description || '该软件槽位的独立控制面板。'}</p></div>
      </div>
      <div className="slot-hero-actions"><button className="button secondary" onClick={onEdit}><Settings2 size={14} />编辑设置</button><button className="button ghost" onClick={() => void rename()}>重命名</button><button className="button ghost" style={{ color: 'var(--red)' }} onClick={onDelete}><Trash2 size={14} />删除</button><button className="button dark" onClick={() => onNavigate('/monitoring')}><Activity size={14} />监控</button></div>
    </div>
    <div className="stat-grid compact-stats">
      <StatCard icon={FileKey2} label="卡密" value={detail.licenseCount} hint="本软件范围" />
      <StatCard icon={Variable} label="变量" value={detail.variableCount} hint="运行时配置" />
      <StatCard icon={Database} label="数据槽" value={detail.dataSlotCount} hint="200KB/码固定配额" />
      <StatCard icon={Gauge} label="活跃会话" value={detail.activeSessions} hint="近一个心跳周期" />
    </div>
    <div className="two-column-grid">
      <section className="panel panel-pad">
        <div className="section-heading"><div><p className="eyebrow"><span className="eyebrow-dot" />KEY MATERIAL</p><h2>软件密钥</h2><p className="desc">仅显示指纹；原始密钥只能一次性导出。</p></div><span className="secure-badge"><LockKeyhole size={12} />仅指纹</span></div>
        {loading ? <VariableLoading /> : <>
          <div className="key-summary"><div><span>当前版本</span><strong>v{detail.currentKeyVersion ?? keys[0]?.version ?? '—'}</strong></div><div><span>指纹</span><code>{detail.keyFingerprint || keys[0]?.fingerprint || '—'}</code></div></div>
          <div className="key-list">{keys.length ? keys.map((key) => <div className="key-row" key={String(key.version)}><span className="version-chip">v{key.version}</span><code>{key.fingerprint || '—'}</code><StatusBadge status={key.status || 'active'} /><small>{key.createdAt ? formatDate(key.createdAt) : '—'}</small></div>) : <EmptyState compact icon={KeyRound} title="密钥信息不可用" description="请创建或读取软件密钥。" />}</div>
          <div className="panel-actions"><button className="button secondary small" onClick={rotate} disabled={working}><RotateCw size={13} />轮换密钥</button><button className="button ghost small" onClick={exportConfig} disabled={working}><Download size={13} />一次性导出配置</button></div>
        </>}
      </section>
      <section className="panel panel-pad">
        <div className="section-heading"><div><p className="eyebrow"><span className="eyebrow-dot" />WORKSPACE</p><h2>快速进入</h2></div><ArrowUpRight size={16} className="muted-icon" /></div>
        <div className="module-links">{slotNavigation.filter((item) => item.id !== 'overview').map((item) => { const Icon = item.icon; return <button key={item.id} onClick={() => onNavigate(`/software/${encodeURIComponent(slot.slug)}/${item.id}`)}><span className="module-icon"><Icon size={15} /></span><span><strong>{item.label}</strong><small>{item.hint}</small></span><ChevronRight size={14} /></button> })}</div>
      </section>
    </div>
  </>
}

function alert2(notify: (toast: Toast) => void, error: unknown, fallback: string) { notify({ type: 'error', message: getErrorMessage(error, fallback) }) }

function VariablesPage({ slug, refreshKey, notify }: { slug: string; refreshKey: number; notify: (toast: Toast) => void }) {
  const [items, setItems] = useState<RemoteVariable[]>([])
  const [draft, setDraft] = useState<Record<string, string>>({})
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState('')
  const { confirm, prompt } = useDialogs()
  const load = async () => { setLoading(true); setError(''); try { const payload = await api.variablesFor(slug); const next = asList<RemoteVariable>(payload, ['items']); setItems(next); setDraft(Object.fromEntries(next.map((item) => [item.key, typeof item.value === 'string' ? item.value : formatPayload(item.value)]))) } catch (error) { setError(getErrorMessage(error, '变量加载失败')) } finally { setLoading(false) } }
  useEffect(() => { void load() }, [slug, refreshKey])
  const save = async () => {
    try {
      const changed = items.filter((item) => item.id !== undefined && item.value !== draft[item.key])
      for (const item of changed) await api.updateVariableFor(slug, item.id!, { value: draft[item.key] })
      notify({ type: 'success', message: `已保存 ${changed.length} 个变量` }); void load()
    } catch (error) { alert2(notify, error, '变量保存失败') }
  }
  const add = async () => {
    const values = await prompt({ title: '添加内部变量', message: '客户端通过 pull_variables 增量拉取这些变量。', fields: [{ key: 'key', label: '变量名', placeholder: '例如 API_TIMEOUT', required: true }, { key: 'value', label: '初始值', placeholder: '变量值（留空为空字符串）' }], confirmLabel: '添加' })
    if (!values || !values.key?.trim()) return
    try { await api.createVariableFor(slug, { key: values.key.trim(), value: values.value ?? '', enabled: true }); notify({ type: 'success', message: '变量已添加' }); void load() } catch (error) { alert2(notify, error, '变量添加失败') }
  }
  const remove = async (item: RemoteVariable) => {
    if (item.id === undefined || !await confirm({ title: `删除变量 ${item.key}`, message: '删除后客户端将无法再拉取该变量。', confirmLabel: '删除', danger: true })) return
    try { await api.deleteVariableFor(slug, item.id); notify({ type: 'success', message: '变量已删除' }); void load() } catch (error) { alert2(notify, error, '变量删除失败') }
  }
  return <>
    <div className="content-intro"><div><p>变量按软件槽位隔离，修改后客户端通过 v2 会话增量拉取。</p><span className="inline-meta"><LockKeyhole size={12} />at-rest 加密 · 按变量版本号增量</span></div>
      <div className="intro-actions"><button className="button secondary" onClick={add}><Plus size={14} />添加变量</button><button className="button primary" onClick={save} disabled={loading}><Save size={14} />保存更改</button></div></div>
    {error && <InlineError message={error} />}
    <section className="panel variables-panel"><div className="table-heading no-padding"><div><p className="eyebrow"><span className="eyebrow-dot" />SOFTWARE VARIABLES</p><h2>内部变量</h2></div><span className="count-label">{items.length} keys</span></div>
      {loading ? <VariableLoading /> : items.length === 0 ? <EmptyState icon={Variable} title="暂无内部变量" description="添加第一个运行时变量。" action={<button className="button secondary small" onClick={add}><Plus size={13} />添加变量</button>} />
        : <div className="variable-list">{items.map((item) => <VariableRow key={item.key} variable={item} value={draft[item.key] ?? ''} onChange={(value) => setDraft((current) => ({ ...current, [item.key]: value }))} onRemove={() => void remove(item)} />)}</div>}
    </section>
  </>
}
function VariableRow({ variable, value, onChange, onRemove }: { variable: RemoteVariable; value: string; onChange: (value: string) => void; onRemove: () => void }) {
  const [visible, setVisible] = useState(true)
  return <div className="variable-row"><div className="variable-title"><div className="variable-icon"><Variable size={16} /></div><div><strong>{variable.key}</strong><small>v{variable.version || 1} · {formatDate(variable.updatedAt)}</small></div></div>
    <div className="variable-input"><textarea rows={3} value={visible ? value : '•'.repeat(Math.min(80, Math.max(8, value.length)))} readOnly={!visible} onChange={(event) => onChange(event.target.value)} placeholder="变量值（支持多行长文本）" /><button type="button" className="icon-button" onClick={() => setVisible(!visible)} aria-label={visible ? '隐藏' : '显示'}>{visible ? <EyeOff size={15} /> : <Eye size={15} />}</button></div>
    <StatusBadge status={variable.enabled === false ? 'disabled' : 'enabled'} /><button className="icon-button danger-button" onClick={onRemove} title="删除变量"><Trash2 size={15} /></button></div>
}

const LICENSE_TYPES = [
  { id: 'permanent', label: '永久卡', days: 0 },
  { id: 'd30', label: '30 天卡', days: 30 },
  { id: 'd90', label: '90 天卡', days: 90 },
  { id: 'd180', label: '180 天卡', days: 180 },
  { id: 'd365', label: '365 天卡', days: 365 },
  { id: 'custom', label: '自定义天数', days: -1 },
]

function LicensesPage({ slug, refreshKey, notify }: { slug: string; refreshKey: number; notify: (toast: Toast) => void }) {
  const [tab, setTab] = useState<'licenses' | 'sessions'>('licenses')
  const [items, setItems] = useState<License[]>([])
  const [sessions, setSessions] = useState<ClientSession[]>([])
  const [loading, setLoading] = useState(true)
  const [search, setSearch] = useState('')
  const [statusFilter, setStatusFilter] = useState('')
  const [selected, setSelected] = useState<Set<string>>(new Set())
  const [generated, setGenerated] = useState<string[]>([])
  const [type, setType] = useState('d30')
  const [days, setDays] = useState(30)
  const [count, setCount] = useState(10)
  const [prefix, setPrefix] = useState('')
  const [manualCode, setManualCode] = useState('')
  const [manualExpiry, setManualExpiry] = useState('')
  const [working, setWorking] = useState(false)
  const { confirm } = useDialogs()

  const load = async () => {
    setLoading(true)
    try {
      if (tab === 'licenses') { const payload = await api.licensesFor(slug, { search, status: statusFilter, limit: 500 }); setItems(asList<License>(payload, ['items'])); setSelected(new Set()) }
      else setSessions(asList<ClientSession>(await api.sessionsFor(slug), ['items']))
    } catch { if (tab === 'licenses') setItems([]); else setSessions([]) } finally { setLoading(false) }
  }
  useEffect(() => { void load() }, [slug, tab, refreshKey])

  const expiryFromType = () => {
    const definition = LICENSE_TYPES.find((item) => item.id === type)
    if (!definition || definition.days === 0) return ''
    const value = definition.days === -1 ? days : definition.days
    return new Date(Date.now() + value * 86400_000).toISOString()
  }
  const batchGenerate = async () => {
    setWorking(true)
    try {
      const payload = await api.createLicenseFor(slug, { count, prefix: prefix || undefined, expiresAt: expiryFromType() || undefined })
      setGenerated(payload.codes || [])
      notify({ type: 'success', message: `已生成 ${payload.count} 个卡密` }); void load()
    } catch (error) { alert2(notify, error, '批量生成失败') } finally { setWorking(false) }
  }
  const manualAdd = async () => {
    setWorking(true)
    try {
      const expiresAt = manualExpiry ? new Date(manualExpiry).toISOString() : undefined
      const payload = await api.createLicenseFor(slug, { codes: [manualCode.trim()], expiresAt })
      const duplicates = payload.duplicates || []
      notify({ type: duplicates.length ? 'error' : 'success', message: duplicates.length ? '该卡密已存在' : '卡密已添加' })
      if (!duplicates.length) setManualCode('')
      void load()
    } catch (error) { alert2(notify, error, '手动添加失败') } finally { setWorking(false) }
  }
  const batchAction = async (action: 'ban' | 'activate' | 'reset-binding' | 'delete') => {
    const ids = Array.from(selected)
    if (!ids.length) return notify({ type: 'info', message: '请先勾选要操作的卡密' })
    const labels: Record<string, string> = { ban: '封禁', activate: '启用', 'reset-binding': '重置机器绑定', delete: '删除' }
    if (!await confirm({ title: `批量${labels[action]}`, message: `将对选中的 ${ids.length} 个卡密执行「${labels[action]}」。${action === 'delete' ? '删除不可恢复。' : ''}`, confirmLabel: labels[action], danger: action === 'delete' })) return
    try { const payload = await api.batchLicenses(slug, { action, ids }); notify({ type: 'success', message: `已${labels[action]} ${payload.changed} 个卡密` }); void load() } catch (error) { alert2(notify, error, '批量操作失败') }
  }
  const rowAction = async (license: License, action: 'ban' | 'activate' | 'reset-binding' | 'delete') => {
    if (license.id === undefined) return
    const labels: Record<string, string> = { ban: '封禁', activate: '启用', 'reset-binding': '重置机器绑定', delete: '删除' }
    if (!await confirm({ title: `${labels[action]}卡密`, message: `${license.publicId} 将被${labels[action]}。${action === 'delete' ? '删除不可恢复。' : ''}`, confirmLabel: labels[action], danger: action === 'delete' })) return
    try {
      if (action === 'delete') await api.deleteLicenseFor(slug, license.id)
      else if (action === 'reset-binding') await api.resetBinding(slug, license.id)
      else await api.updateLicenseFor(slug, license.id, { status: action === 'ban' ? 'revoked' : 'active' })
      notify({ type: 'success', message: `已${labels[action]}` }); void load()
    } catch (error) { alert2(notify, error, '操作失败') }
  }
  const revokeSession = async (session: ClientSession) => {
    if (session.id === undefined || !await confirm({ title: '强制下线', message: '该客户端会话将被撤销，客户端需重新登录。', confirmLabel: '下线', danger: true })) return
    try { await api.revokeSession(slug, session.id); notify({ type: 'success', message: '会话已下线' }); void load() } catch (error) { alert2(notify, error, '下线失败') }
  }
  const exportCsv = () => {
    const rows = [['ID', '卡密', '机器码', '状态', '创建时间', '绑定时间', '过期时间', '备注']]
    for (const item of items) rows.push([String(item.id ?? ''), item.code || item.publicId, item.machineHash || '', item.status || '', item.createdAt || '', item.boundAt || '', item.expiresAt || '', item.note || ''])
    const csv = '\ufeff' + rows.map((row) => row.map((cell) => `"${String(cell).split('"').join('""')}"`).join(',')).join('\n')
    const url = URL.createObjectURL(new Blob([csv], { type: 'text/csv;charset=utf-8' }))
    const link = document.createElement('a')
    link.href = url
    link.download = `licenses-${slug}-${new Date().toISOString().slice(0, 10)}.csv`
    link.click()
    URL.revokeObjectURL(url)
  }
  const toggleAll = () => { setSelected(items.every((item) => selected.has(String(item.id))) ? new Set() : new Set(items.map((item) => String(item.id)))) }

  return <>
    <div className="toolbar">
      <div className="search-box"><Search size={14} /><input value={search} onChange={(event) => setSearch(event.target.value)} onKeyDown={(event) => event.key === 'Enter' && void load()} placeholder="搜索卡密公开 ID / 机器码…" /></div>
      <select value={statusFilter} onChange={(event) => { setStatusFilter(event.target.value); }} aria-label="状态筛选"><option value="">全部状态</option><option value="active">有效</option><option value="revoked">已封禁</option></select>
      <button className="button secondary small" onClick={() => void load()}><Search size={13} />搜索</button>
      <span style={{ flex: 1 }} />
      <button className="button secondary small" onClick={exportCsv}><Download size={13} />导出 CSV</button>
    </div>
    {tab === 'licenses' && <>
      <section className="panel panel-pad" style={{ marginBottom: 16 }}>
        <div className="section-heading"><div><p className="eyebrow"><span className="eyebrow-dot" />BATCH GENERATE</p><h2>批量生成卡密</h2><p className="desc">过期时间采用严格 24 小时制（精确到当前时刻 + 天数）。</p></div></div>
        <div className="toolbar" style={{ marginTop: 14, marginBottom: 0 }}>
          <select value={type} onChange={(event) => setType(event.target.value)} aria-label="卡密类型">{LICENSE_TYPES.map((item) => <option key={item.id} value={item.id}>{item.label}</option>)}</select>
          {type === 'custom' && <input className="form-input-inline" type="number" min="1" value={days} onChange={(event) => setDays(Number(event.target.value))} style={{ width: 96 }} aria-label="天数" placeholder="天数" />}
          <input className="form-input-inline" type="number" min="1" max="1000" value={count} onChange={(event) => setCount(Number(event.target.value))} style={{ width: 96 }} aria-label="数量" placeholder="数量" />
          <input className="form-input-inline" value={prefix} onChange={(event) => setPrefix(event.target.value)} style={{ width: 120 }} aria-label="前缀" placeholder="前缀（可选）" />
          <button className="button primary" onClick={batchGenerate} disabled={working}><KeyRound size={14} />批量生成</button>
        </div>
      </section>
      <section className="panel panel-pad" style={{ marginBottom: 16 }}>
        <div className="section-heading"><div><p className="eyebrow"><span className="eyebrow-dot" />MANUAL ADD</p><h2>手动添加卡密</h2><p className="desc">使用自定义卡密内容，8–128 位字母数字与 ._:- 组合。</p></div></div>
        <div className="toolbar" style={{ marginTop: 14, marginBottom: 0 }}>
          <input className="form-input-inline" value={manualCode} onChange={(event) => setManualCode(event.target.value)} style={{ flex: 1, minWidth: 200 }} placeholder="输入卡密" aria-label="卡密" />
          <input className="form-input-inline" type="datetime-local" value={manualExpiry} onChange={(event) => setManualExpiry(event.target.value)} aria-label="过期时间" />
          <button className="button primary" disabled={!manualCode.trim() || working} onClick={manualAdd}><Plus size={14} />手动添加</button>
        </div>
      </section>
    </>}
    <div className="tabs">
      <button className={tab === 'licenses' ? 'active' : ''} onClick={() => setTab('licenses')}><FileKey2 size={14} />卡密列表 <span>{items.length}</span></button>
      <button className={tab === 'sessions' ? 'active' : ''} onClick={() => setTab('sessions')}><Wifi size={14} />客户端会话 <span>{sessions.length}</span></button>
    </div>
    {tab === 'licenses' && <>
      {selected.size > 0 && <div className="batch-bar"><strong>已选 {selected.size} 项</strong>
        <button className="button secondary small" onClick={() => void batchAction('ban')}>封禁</button>
        <button className="button secondary small" onClick={() => void batchAction('activate')}>启用</button>
        <button className="button secondary small" onClick={() => void batchAction('reset-binding')}>重置绑定</button>
        <button className="button danger small" onClick={() => void batchAction('delete')}>删除</button>
        <button className="button ghost small" onClick={() => setSelected(new Set())}>取消选择</button>
      </div>}
      <section className="panel table-panel">
        <TableHeader eyebrow="LICENSE CODES" title="卡密列表" count={`${items.length} 条`} />
        <DataTable loading={loading} emptyIcon={FileKey2} emptyTitle="暂无卡密" emptyDescription="批量生成或手动添加后，客户端即可登录。"
          columns={['', 'ID', '卡密', '机器码', '状态', '创建时间', '绑定时间', '过期时间', '操作']}
          rows={items.map((item) => [
            <input type="checkbox" checked={selected.has(String(item.id))} onChange={() => setSelected((current) => { const next = new Set(current); if (next.has(String(item.id))) next.delete(String(item.id)); else next.add(String(item.id)); return next })} aria-label={`选择 ${item.publicId}`} />,
            <span className="mono muted">{item.id}</span>,
            <button className="code-button" onClick={() => void copyText(item.code || item.publicId)} title="点击复制"><span style={{ overflow: 'hidden', textOverflow: 'ellipsis' }}>{item.code || item.publicId}</span><Copy size={12} /></button>,
            item.machineHash ? <button className="code-button" onClick={() => void copyText(item.machineHash!)} title="点击复制"><span style={{ overflow: 'hidden', textOverflow: 'ellipsis', maxWidth: 150 }}>{truncate(item.machineHash, 18)}</span><Copy size={12} /></button> : <span className="muted">未绑定</span>,
            <StatusBadge status={normalizedStatus(item.status, item.expiresAt)} />,
            formatDate(item.createdAt), formatDate(item.boundAt || undefined), item.expiresAt ? formatDate(item.expiresAt, true) : <span className="muted">永久</span>,
            <div className="row-actions">
              {item.status === 'revoked'
                ? <button className="icon-button" title="启用" onClick={() => void rowAction(item, 'activate')}><CheckCircle2 size={14} /></button>
                : <button className="icon-button" title="封禁" onClick={() => void rowAction(item, 'ban')}><XCircle size={14} /></button>}
              <button className="icon-button" title="重置绑定" onClick={() => void rowAction(item, 'reset-binding')}><RotateCw size={14} /></button>
              <button className="icon-button danger-button" title="删除" onClick={() => void rowAction(item, 'delete')}><Trash2 size={14} /></button>
            </div>])} />
      </section>
    </>}
    {tab === 'sessions' && <section className="panel table-panel"><TableHeader eyebrow="CLIENT SESSIONS" title="客户端会话" count={`${sessions.length} 条`} />
      <DataTable loading={loading} emptyIcon={Wifi} emptyTitle="暂无活跃会话" emptyDescription="客户端登录后，会话和心跳状态会显示在这里。"
        columns={['单码', '机器摘要', '创建时间', '最后心跳', '过期时间', '状态', '']}
        rows={sessions.map((item) => [<code>{item.publicId || item.licenseId || '—'}</code>, <code>{truncate(item.machineHash || '—', 18)}</code>, formatDate(item.createdAt), formatDate(item.lastHeartbeatAt), formatDate(item.expiresAt), <StatusBadge status={item.revokedAt ? 'revoked' : item.active ? 'active' : 'expired'} />, <button className="button ghost small" onClick={() => void revokeSession(item)}>强制下线</button>])} />
    </section>}
    {generated.length > 0 && <Modal eyebrow="ONE-TIME OUTPUT" title="新生成的卡密" onClose={() => setGenerated([])}>
      <p className="modal-note">明文卡密只在此次响应中可见，请立即复制并安全保存。</p>
      <div className="codes-list">{generated.map((code) => <button className="generated-code" key={code} onClick={() => void copyText(code)}><span>{code}</span><Clipboard size={13} /></button>)}</div>
      <div className="modal-actions"><button className="button secondary" onClick={() => { setGenerated([]) }}>关闭</button><button className="button primary" onClick={() => void copyText(generated.join('\n'))}><Clipboard size={14} />复制全部</button></div>
    </Modal>}
  </>
}

function DataPage({ slug, refreshKey, notify }: { slug: string; refreshKey: number; notify: (toast: Toast) => void }) {
  const [tab, setTab] = useState<'slots' | 'reports' | 'store'>('slots')
  const [slots, setSlots] = useState<DataSlot[]>([])
  const [usage, setUsage] = useState<DataUsage[]>([])
  const [reports, setReports] = useState<Report[]>([])
  const [store, setStore] = useState<DataStoreRecord[]>([])
  const [storeQuery, setStoreQuery] = useState('')
  const [historyQuery, setHistoryQuery] = useState('')
  const [loading, setLoading] = useState(true)
  const [selected, setSelected] = useState<Report | null>(null)
  const [selectedSlot, setSelectedSlot] = useState<DataSlot | null>(null)
  const { confirm, prompt } = useDialogs()
  const load = async () => {
    setLoading(true)
    try {
      const [slotPayload, usagePayload] = await Promise.all([api.dataSlotsFor(slug), api.dataUsageFor(slug)])
      setSlots(asList<DataSlot>(slotPayload, ['items'])); setUsage(asList<DataUsage>(usagePayload, ['items']))
    } catch {
      setSlots([]); setUsage([])
    }
    try {
      if (tab === 'reports') setReports(asList<Report>(await api.reportsFor(slug), ['items']))
      if (tab === 'store') setStore(asList<DataStoreRecord>(await api.dataStoreFor(slug), ['items', 'records']))
    } catch {
      if (tab === 'reports') setReports([])
      if (tab === 'store') setStore([])
    } finally { setLoading(false) }
  }
  useEffect(() => { void load() }, [slug, refreshKey, tab])

  const create = async () => {
    const values = await prompt({ title: '新建数据槽', message: '数据槽本身不限总量；每个单码在每个数据槽的最终快照固定上限 200KB。', fields: [{ key: 'slug', label: 'slug', placeholder: 'events', required: true }, { key: 'name', label: '名称', placeholder: '事件数据', required: true }, { key: 'description', label: '描述', placeholder: '可选' }], confirmLabel: '创建' })
    if (!values) return
    try { await api.createDataSlot(slug, { slug: values.slug.trim(), name: values.name.trim(), description: values.description || '', enabled: true }); notify({ type: 'success', message: '数据槽已创建（槽本身不限总量，每个单码每槽最终快照固定 200KB）' }); void load() } catch (error) { alert2(notify, error, '数据槽创建失败') }
  }
  const toggleSlot = async (slot: DataSlot) => {
    if (slot.id === undefined) return
    try { await api.updateDataSlot(slug, slot.id, { enabled: slot.enabled === false }); void load() } catch (error) { alert2(notify, error, '状态更新失败') }
  }
  const removeSlot = async (slot: DataSlot) => {
    if (slot.id === undefined || !await confirm({ title: `删除数据槽 ${slot.name}`, message: '删除会同时清理该槽位的当前快照、历史记录和事件数据。操作不可恢复。', confirmLabel: '删除', danger: true })) return
    try { await api.deleteDataSlot(slug, slot.id, true); notify({ type: 'success', message: '数据槽及其数据已删除' }); void load() } catch (error) { alert2(notify, error, '数据槽删除失败') }
  }
  const removeReport = async (report: Report) => {
    if (report.id === undefined || !await confirm({ title: '删除上报记录', message: '删除后该记录不再计入 200KB 累计配额。', confirmLabel: '删除', danger: true })) return
    try { await api.deleteReportFor(slug, report.id); setSelected(null); notify({ type: 'success', message: '记录已删除' }); void load() } catch (error) { alert2(notify, error, '记录删除失败') }
  }
  const removeStore = async (item: DataStoreRecord) => {
    if (item.id === undefined || !await confirm({ title: '删除单码数据', message: `将删除单码 ${dataStoreLicenseLabel(item)} 在数据槽 ${dataStoreSlotLabel(item)} 中的当前快照，操作不可恢复。`, confirmLabel: '删除', danger: true })) return
    try { await api.dataStoreDeleteFor(slug, item.id); notify({ type: 'success', message: '单码数据已删除' }); void load() } catch (error) { alert2(notify, error, '单码数据删除失败') }
  }
  const usageFor = (slot: DataSlot) => usage.find((row) => row.slug === slot.slug)
  const clearHistory = async () => {
    if (!selectedSlot || !await confirm({ title: `清空 ${selectedSlot.name} 的历史`, message: '只会删除该数据槽的接收历史，不会删除单码当前快照。操作不可恢复。', confirmLabel: '清空历史', danger: true })) return
    try { const result = await api.clearDataSlotHistory(slug, selectedSlot.slug); notify({ type: 'success', message: `已清空 ${result.deleted} 条历史记录` }); void load() } catch (error) { alert2(notify, error, '清空历史失败') }
  }
  const selectedStore = selectedSlot ? store.filter((item) => dataStoreSlotLabel(item) === selectedSlot.slug) : []
  const selectedReports = selectedSlot ? reports.filter((item) => (item.dataSlot || item.slotSlug || item.slotId || '') === selectedSlot.slug || (item.dataSlot || item.slotSlug || '') === selectedSlot.slug) : []
  const filteredStore = useMemo(() => {
    const query = storeQuery.trim().toLowerCase()
    if (!query) return store
    return store.filter((item) => [dataStoreLicenseLabel(item), dataStoreSlotLabel(item), formatPayload(item.value), String(item.size ?? ''), String(item.version ?? ''), String(item.updatedAt ?? '')].join(' ').toLowerCase().includes(query))
  }, [store, storeQuery])
  return <>
    <div className="toolbar">
      {selectedSlot ? <button className="button secondary small" onClick={() => { setSelectedSlot(null); setTab('slots') }}><ArrowLeft size={13} />返回数据槽</button> : null}
      <div className="tabs inline-tabs">
        {selectedSlot ? <>
          <button className={tab === 'reports' ? 'active' : ''} onClick={() => setTab('reports')}><ArrowDownToLine size={14} />接收历史</button>
          <button className={tab === 'store' ? 'active' : ''} onClick={() => setTab('store')}><KeyRound size={14} />单码数据</button>
        </> : <button className="active"><Database size={14} />数据槽</button>}
      </div>
      {selectedSlot && tab === 'store' && <div className="search-box"><Search size={14} /><input value={storeQuery} onChange={(event) => setStoreQuery(event.target.value)} placeholder="搜索单码或 JSON…" aria-label="搜索单码数据" /></div>}
      <span style={{ flex: 1 }} />
      {selectedSlot ? <span className="inline-meta"><Database size={12} />{selectedSlot.name} · {selectedSlot.slug}</span> : <span className="inline-meta"><LockKeyhole size={12} />槽本身不限总量 · 选中槽位后查看内部数据</span>}
      {!selectedSlot && <button className="button primary small" onClick={create}><Plus size={13} />新建数据槽</button>}
    </div>
    {!selectedSlot && <section className="panel table-panel"><TableHeader eyebrow="DATA SLOTS" title="选择数据槽" count={`${slots.length} 个`} />
      <p className="section-description" style={{ padding: '0 22px 16px', margin: 0 }}>数据槽本身不限总量。选择一个槽位后，在槽位内部查看接收历史和每个单码的当前快照。</p>
      <DataTable loading={loading} emptyIcon={Database} emptyTitle="暂无数据槽" emptyDescription="创建数据槽即可开始接收数据。"
        columns={['名称', 'slug', '状态', '单码当前快照', '最近接收', '操作']}
        rows={slots.map((slot) => { const row = usageFor(slot); return [<strong className="cell-primary">{slot.name}</strong>, <code>{slot.slug}</code>, <StatusBadge status={slot.enabled === false ? 'disabled' : 'active'} />, String(row?.recordCount ?? 0), formatDate(row?.lastReceivedAt || undefined),
          <div className="row-actions"><button className="button primary small" onClick={() => { setSelectedSlot(slot); setTab('reports'); void load() }}>进入槽位 <ChevronRight size={13} /></button><button className="button ghost small" onClick={() => void toggleSlot(slot)}>{slot.enabled === false ? '启用' : '停用'}</button><button className="icon-button danger-button" title="删除" onClick={() => void removeSlot(slot)}><Trash2 size={14} /></button></div>] })} />
    </section>}
    {selectedSlot && tab === 'reports' && <section className="panel table-panel"><div className="history-toolbar"><div className="history-heading"><TableHeader eyebrow="RECEIVE HISTORY" title={`${selectedSlot.name} · 接收历史`} count={`${selectedReports.length} 条`} /><p className="history-description">每次 overwrite / append 请求都会留下一条历史记录。</p></div><button className="button danger small history-clear" onClick={() => void clearHistory()}><Trash2 size={13} />清空历史</button></div>
      <DataTable loading={loading} emptyIcon={ArrowDownToLine} emptyTitle="暂无接收历史" emptyDescription="该槽位还没有客户端上报记录。"
        columns={['时间', '单码', '机器', '大小', '摘要', '详情']}
        rows={selectedReports.map((item) => [formatDate(item.receivedAt), <code>{item.publicId || item.licenseId || '—'}</code>, <code>{truncate(item.machineHash || '—', 16)}</code>, formatBytes(item.size), <code>{truncate(item.sha256 || '—', 16)}</code>, <button className="button ghost small" onClick={() => setSelected(item)}><Eye size={13} />查看</button>])} />
    </section>}
    {selectedSlot && tab === 'store' && <section className="panel table-panel"><TableHeader eyebrow="CURRENT SNAPSHOTS" title={`${selectedSlot.name} · 单码数据`} count={`${filteredStore.length} / ${store.length} 条`} />
      <DataTable loading={loading} emptyIcon={KeyRound} emptyTitle="暂无单码数据" emptyDescription="客户端写入后，每个单码在此槽位只保留一份最终快照。"
        columns={['单码', '当前 value（JSON）', '大小', '版本', '更新时间', '操作']}
        rows={filteredStore.filter((item) => dataStoreSlotLabel(item) === selectedSlot.slug).map((item) => [<code>{dataStoreLicenseLabel(item)}</code>, <pre style={{ margin: 0, maxWidth: 460, maxHeight: 180, overflow: 'auto', whiteSpace: 'pre-wrap', color: 'var(--muted-strong)', font: '13px/1.55 var(--mono)' }}>{formatPayload(item.value)}</pre>, formatBytes(item.size), <span className="mono">v{item.version ?? '—'}</span>, formatDate(item.updatedAt), <button className="icon-button danger-button" title="删除单码数据" onClick={() => void removeStore(item)}><Trash2 size={14} /></button>])} />
    </section>}
    {selected && <ReportDetailModal slug={slug} report={selected} onClose={() => setSelected(null)} onDelete={() => void removeReport(selected)} />}
  </>
}
function ReportDetailModal({ slug, report, onClose, onDelete }: { slug: string; report: Report; onClose: () => void; onDelete: () => void }) {
  const [detail, setDetail] = useState(report)
  const [loading, setLoading] = useState(report.id !== undefined)
  useEffect(() => { if (report.id === undefined) return; api.reportFor(slug, report.id).then((payload) => setDetail(asRecord<Report>(payload))).finally(() => setLoading(false)) }, [slug, report.id])
  return <Modal eyebrow="PAYLOAD / DECRYPTED" title="上报详情" onClose={onClose}>
    <div className="detail-grid" style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 12, padding: '18px 24px 6px' }}>
      <div><span>数据槽</span><code>{detail.dataSlot || detail.slotId || '—'}</code></div>
      <div><span>单码</span><code>{detail.publicId || detail.licenseId || '—'}</code></div>
      <div><span>接收时间</span><strong>{formatDate(detail.receivedAt)}</strong></div>
      <div><span>大小</span><strong>{formatBytes(detail.size)}</strong></div>
    </div>
    <div style={{ padding: '12px 24px 0' }}><strong style={{ fontSize: 13 }}>Payload</strong>{!loading && <button className="button ghost small" style={{ marginLeft: 8 }} onClick={() => void copyText(formatPayload(detail.payload))}><Clipboard size={12} />复制</button>}</div>
    <pre className="payload-view" style={{ margin: '8px 24px 16px' }}>{loading ? '正在读取加密 payload…' : formatPayload(detail.payload)}</pre>
    <div className="modal-actions"><button className="button danger" onClick={onDelete}><Trash2 size={14} />删除记录</button><button className="button secondary" onClick={onClose}>关闭</button></div>
  </Modal>
}

function FilesPage({ slug, refreshKey, notify }: { slug: string; refreshKey: number; notify: (toast: Toast) => void }) {
  const [items, setItems] = useState<ResourceFile[]>([])
  const [loading, setLoading] = useState(true)
  const [uploading, setUploading] = useState(false)
  const { confirm } = useDialogs()
  const load = async () => { setLoading(true); try { setItems(asList<ResourceFile>(await api.resourcesFor(slug), ['items'])) } catch { setItems([]) } finally { setLoading(false) } }
  useEffect(() => { void load() }, [slug, refreshKey])
  const upload = async (files: FileList | null) => {
    if (!files?.length) return
    setUploading(true)
    let ok = 0
    for (const file of Array.from(files)) {
      try { await api.uploadResource(slug, file); ok += 1 } catch (error) { notify({ type: 'error', message: `${file.name}: ${getErrorMessage(error, '上传失败')}` }) }
    }
    setUploading(false)
    if (ok) { notify({ type: 'success', message: `已上传 ${ok} 个文件` }); void load() }
  }
  const remove = async (file: ResourceFile) => {
    if (file.id === undefined || !await confirm({ title: `删除 ${file.originalName}`, message: '客户端将无法再下载该文件。', confirmLabel: '删除', danger: true })) return
    try { await api.deleteResource(slug, file.id); notify({ type: 'success', message: '文件已删除' }); void load() } catch (error) { alert2(notify, error, '删除失败') }
  }
  return <>
    <div className="content-intro"><div><p>任意文件上传后即可被客户端通过 manifest + file_chunk 加密下载，服务端校验 SHA-256。</p><span className="inline-meta"><LockKeyhole size={12} />存储名随机 · 不由 Web 直接暴露</span></div>
      <label className={`button primary ${uploading ? 'button' : ''}`} style={{ visibility: uploading ? 'visible' : 'visible' }}>
        {uploading ? <span className="button-spinner" /> : <Upload size={14} />}{uploading ? '上传中…' : '上传文件'}
        <input type="file" multiple style={{ display: 'none' }} onChange={(event) => { void upload(event.target.files); event.currentTarget.value = '' }} />
      </label>
    </div>
    <section className="panel panel-pad">
      <div className="table-heading no-padding"><div><p className="eyebrow"><span className="eyebrow-dot" />FILE RESOURCES</p><h2>文件资源</h2></div><span className="count-label">{items.length} 个文件</span></div>
      {loading ? <VariableLoading /> : items.length === 0 ? <EmptyState icon={Package} title="暂无文件" description="上传第一个文件，客户端即可通过加密 manifest 发现它。" /> :
        <div className="file-list">{items.map((file) => <div className="file-row" key={String(file.id)}>
          <span className="file-name"><FileText size={16} /><span style={{ overflow: 'hidden', textOverflow: 'ellipsis' }}>{file.originalName}</span></span>
          <span className="file-meta">{formatBytes(file.size)} · {file.mime || 'application/octet-stream'} · {formatDate(file.createdAt)}</span>
          <button className="code-button" title="复制 SHA-256" onClick={() => void copyText(file.sha256)}><span>{truncate(file.sha256, 14)}</span><Copy size={12} /></button>
          <StatusBadge status="active" />
          <div className="file-actions"><button className="icon-button danger-button" title="删除" onClick={() => void remove(file)}><Trash2 size={15} /></button></div>
        </div>)}</div>}
    </section>
  </>
}

function SoftwareSecurityPage({ slug, refreshKey, notify }: { slug: string; refreshKey: number; notify: (toast: Toast) => void }) {
  const [form, setForm] = useState<Record<string, unknown>>({ machineCheck: true, ipCheck: false, ipChangePolicy: 'allow', heartbeatTimeout: 300, sessionTtl: 86400 })
  const [loading, setLoading] = useState(true)
  const [saving, setSaving] = useState(false)
  useEffect(() => { api.securityFor(slug).then((payload) => setForm((current) => ({ ...current, ...payload }))).catch(() => undefined).finally(() => setLoading(false)) }, [slug, refreshKey])
  const save = async (event: FormEvent) => { event.preventDefault(); setSaving(true); try { await api.updateSecurityFor(slug, form); notify({ type: 'success', message: '软件安全策略已保存' }) } catch (error) { alert2(notify, error, '安全策略保存失败') } finally { setSaving(false) } }
  return <section className="panel security-main"><div className="section-heading"><div><p className="eyebrow"><span className="eyebrow-dot" />SOFTWARE SECURITY / {slug}</p><h2>机器、IP 与会话策略</h2><p className="section-description">策略作用域仅限当前软件槽位，变更会影响后续客户端请求。</p></div><ShieldCheck size={18} className="green-icon" /></div>
    {loading ? <VariableLoading /> : <form className="security-form wide" onSubmit={save}>
      <div className="check-grid"><label className="checkbox-label"><input type="checkbox" checked={Boolean(form.machineCheck)} onChange={(event) => setForm({ ...form, machineCheck: event.target.checked })} />启用机器证明</label><label className="checkbox-label"><input type="checkbox" checked={Boolean(form.ipCheck)} onChange={(event) => setForm({ ...form, ipCheck: event.target.checked })} />启用 IP 校验</label></div>
      <div className="form-row"><label>IP 变化策略<select value={String(form.ipChangePolicy || 'allow')} onChange={(event) => setForm({ ...form, ipChangePolicy: event.target.value })}><option value="allow">允许变化</option><option value="update">变化后更新绑定</option><option value="deny">拒绝变化</option></select></label><label>心跳超时（秒）<input type="number" min="30" value={Number(form.heartbeatTimeout || 300)} onChange={(event) => setForm({ ...form, heartbeatTimeout: Number(event.target.value) })} /></label></div>
      <div className="form-row"><label>Session TTL（秒）<input type="number" min="60" value={Number(form.sessionTtl || 86400)} onChange={(event) => setForm({ ...form, sessionTtl: Number(event.target.value) })} /></label><div /></div>
      <div className="security-summary"><ShieldCheck size={15} /><span>后续 heartbeat、变量、报告和文件请求必须携带有效 session、机器证明、时间戳和 nonce。</span></div>
      <button className="button primary" disabled={saving}>{saving ? '保存中…' : <><Save size={14} />保存安全策略</>}</button>
    </form>}
  </section>
}

function DocsPage() {
  const endpoint = '/api/v2/client/{software_slot}'
  const aadReq = 'jur10n:client:v2:{software_slot}:{key_version}:request'
  const aadRes = 'jur10n:client:v2:{software_slot}:{key_version}:response'
  const heartbeat = 300
  const windowMs = 60000
  const quotaKb = 200
  return <div className="docs-layout">
    <aside className="docs-index">
      <p className="eyebrow"><span className="eyebrow-dot" />REFERENCE</p>
      <strong>jur10n-client-v2</strong>
      <a href="#ds-overview">协议概述</a>
      <a href="#ds-crypto">加密规范</a>
      <a href="#ds-envelope">请求信封</a>
      <a href="#ds-login">login 登录</a>
      <a href="#ds-heartbeat">heartbeat 心跳</a>
      <a href="#ds-vars">pull_variables 变量</a>
      <a href="#ds-report">report 上报</a>
      <a href="#ds-files">manifest / file_chunk</a>
      <a href="#ds-session">会话与绑定规则</a>
      <a href="#ds-errors">错误码</a>
      <a href="#ds-python">Python 示例</a>
    </aside>
    <article className="panel docs-content">
      <div className="docs-title"><div><p className="eyebrow"><span className="eyebrow-dot" />CLIENT API</p><h2>jur10n 客户端协议 v2</h2><p>每软件独立 AES-256-GCM 加密通道。所有业务 JSON 都在密文内，HTTP 层统一 200 + 二进制。</p></div></div>
      <DocSection id="ds-overview" title="协议概述">
        <p>客户端通过单一入口与服务器通信：<code>POST {endpoint}</code>，<code>Content-Type: application/octet-stream</code>。路由中的 <code>software_slot</code> 用于选择该软件独立的 AES 密钥；业务字段全部在密文内。任何解密失败、格式错误、时间戳偏差过大或 nonce 重放都会返回加密的错误包，抓包者无法区分具体原因。</p>
        <ul>
          <li>传输层 HTTPS；应用层 AES-256-GCM（12 字节 IV + 密文 + 16 字节 tag）。</li>
          <li>时间戳允许与服务器相差不超过 <code>{(windowMs / 1000).toFixed(0)} 秒</code>。</li>
          <li>每个请求必须携带新的 nonce；服务器保存 5 分钟去重。</li>
          <li>登录后所有操作需要有效 session，并且 <code>{heartbeat} 秒</code>内至少成功心跳一次。</li>
        </ul>
      </DocSection>
      <DocSection id="ds-crypto" title="加密规范">
        <p>每个软件槽位有独立的 32 字节密钥（管理端生成、一次性导出）。密文包布局：</p>
        <pre>{`packet = IV(12B) || AES-256-GCM-ciphertext || GCM-tag(16B)
AAD(request)  = ${aadReq}
AAD(response) = ${aadRes}`}</pre>
        <p>密钥版本 <code>key_version</code> 参与 AAD，因此新旧版本密文互不通用。请求头可带 <code>X-Key-Version</code> 帮助服务器选密钥；包内 <code>key_version</code> 必须与实际解密密钥一致。轮换密钥后所有旧会话立即失效。</p>
      </DocSection>
      <DocSection id="ds-envelope" title="请求信封字段">
        <table className="doc-table"><thead><tr><th>字段</th><th>类型</th><th>说明</th></tr></thead><tbody>
          <tr><td><code>protocol</code></td><td>string</td><td>固定 <code>jur10n-client-v2</code></td></tr>
          <tr><td><code>key_version</code></td><td>int</td><td>密钥版本，≥1</td></tr>
          <tr><td><code>timestamp</code></td><td>int</td><td>Unix 毫秒，±{windowMs / 1000}s</td></tr>
          <tr><td><code>nonce</code></td><td>string</td><td>16–256 位 URL-safe 随机串，一次一用</td></tr>
          <tr><td><code>op</code></td><td>string</td><td>login / heartbeat / pull_variables / report / manifest / file_chunk</td></tr>
          <tr><td><code>code</code></td><td>string</td><td>login 时的卡密</td></tr>
          <tr><td><code>machine_proof</code></td><td>string</td><td>客户端硬件指纹 HMAC（启用机器校验时必填）</td></tr>
          <tr><td><code>session_token</code> / <code>session_id</code></td><td>string</td><td>登录后操作必填</td></tr>
        </tbody></table>
      </DocSection>
      <DocSection id="ds-login" title="login — 登录并建立会话">
        <pre>{`{
  "protocol": "jur10n-client-v2",
  "key_version": 1,
  "timestamp": ${'{'}Date.now(){'}'},
  "nonce": "随机 nonce",
  "op": "login",
  "code": "JUR-XXXXXXXX",
  "machine_proof": "客户端机器证明"
}`}</pre>
        <p>成功返回（解密后 <code>data</code>）：</p>
        <pre>{`{
  "sessionToken": "...", "sessionId": "...",
  "serverTime": 1730000000000,
  "heartbeatInterval": ${heartbeat},
  "expiresAt": "2026-09-05T00:00:00.000Z",
  "publicId": "卡密公开 ID"
}`}</pre>
        <p>首次登录自动绑定机器；非绑定机器返回 <code>MACHINE_MISMATCH</code>。同一台机器允许多个并行会话（多进程场景）。</p>
      </DocSection>
      <DocSection id="ds-heartbeat" title="heartbeat — 保持会话活跃">
        <pre>{`{ "op": "heartbeat", "session_token": "...", "session_id": "...", "machine_proof": "...", "timestamp": ..., "nonce": "..." }`}</pre>
        <p>返回 <code>serverTime</code>、<code>heartbeatInterval</code>、<code>expiresAt</code>。超过 <code>{heartbeat} 秒</code>没有成功心跳，会话失活，后续请求返回 <code>SESSION_INACTIVE</code>，必须重新登录。</p>
      </DocSection>
      <DocSection id="ds-vars" title="pull_variables — 拉取内部变量">
        <pre>{`{ "op": "pull_variables", "session_token": "...", "session_id": "...", "machine_proof": "...", "since_version": 0 }`}</pre>
        <p>返回 <code>{'{'} variables: [{'{'} key, value, version, updatedAt {'}'}], latestVersion {'}'}</code>。只返回启用变量中版本号大于 <code>since_version</code> 的条目；把返回的 <code>latestVersion</code> 作为下一次的游标。</p>
      </DocSection>
      <DocSection id="ds-report" title="report — 上报数据">
        <pre>{`{ "op": "report", "data_slot": "events", "data": { "event": "boot" }, "session_token": "...", ... }`}</pre>
        <p>每个单码在每个数据槽累计上限固定为 <code>{quotaKb} KB</code>（当前已存数据总量，删除记录会释放额度）。超出返回 <code>QUOTA_EXCEEDED</code>，单包超过 128KB 返回 <code>PAYLOAD_TOO_LARGE</code>。成功返回 <code>{'{'} id, accepted, receivedAt, size, sha256, quotaBytes, usedBytes {'}'}</code>。</p>
      </DocSection>
      <DocSection id="ds-files" title="manifest / file_chunk — 文件分发">
        <pre>{`{ "op": "manifest", ... }   → { "resources": [ { "id": 1, "originalName": "setup.exe", "sha256": "...", "size": 123456 } ] }
{ "op": "file_chunk", "file_id": 1, "offset": 0, "length": 65536, ... }`}</pre>
        <p>file_chunk 返回 <code>{'{'} fileId, offset, length, totalSize, sha256, chunk(base64), eof {'}'}</code>。客户端按 offset 顺序拼接，最终校验 manifest 中的 SHA-256。单次最大 64KB，超出自动截断。</p>
      </DocSection>
      <DocSection id="ds-session" title="会话、机器绑定与 IP 策略">
        <ul>
          <li>机器绑定：首次登录绑定，之后校验 machine proof；管理端可重置绑定。</li>
          <li>IP 策略：每软件可配 deny / update / allow；默认关闭 IP 校验。</li>
          <li>会话数量：同一机器不限制并行会话数量，适配多进程客户端。</li>
          <li>管理端可随时撤销指定会话，客户端下一次请求即返回 <code>SESSION_REVOKED</code>。</li>
        </ul>
      </DocSection>
      <DocSection id="ds-errors" title="错误码">
        <p>错误同样以加密包返回（HTTP 200），解密后形如 <code>{'{'} ok: false, status: 401, error: "MACHINE_MISMATCH" {'}'}</code>。</p>
        <div className="error-code-grid">{[
          ['INVALID_REQUEST', '请求格式或字段非法'],
          ['INVALID_PROTOCOL', 'protocol 字段不匹配'],
          ['INVALID_KEY_VERSION', '密钥版本不一致'],
          ['TIMESTAMP_INVALID', '时间戳偏差超过窗口'],
          ['REPLAY_DETECTED', 'nonce 重放'],
          ['RATE_LIMITED', '每 IP 每分钟限流'],
          ['INVALID_CREDENTIALS', '卡密不存在或已封禁'],
          ['LICENSE_EXPIRED', '卡密已过期'],
          ['MACHINE_PROOF_REQUIRED', '缺少机器证明'],
          ['MACHINE_MISMATCH', '机器与绑定不匹配'],
          ['IP_MISMATCH', 'IP 策略拒绝'],
          ['DEVICE_LIMIT', '超出设备绑定上限'],
          ['SESSION_REQUIRED', '缺少会话'],
          ['SESSION_REVOKED', '会话被撤销'],
          ['SESSION_EXPIRED', '会话已过期'],
          ['SESSION_INACTIVE', '心跳超时会话失活'],
          ['KEY_REVOKED', '密钥版本已撤销'],
          ['SOFTWARE_DISABLED', '软件槽位已停用'],
          ['DATA_SLOT_NOT_FOUND', '数据槽不存在或停用'],
          ['RECEIVING_DISABLED', '服务端已关闭数据接收'],
          ['PAYLOAD_TOO_LARGE', '单包超过 128KB'],
          ['QUOTA_EXCEEDED', `超过 ${quotaKb}KB 累计配额`],
          ['STORAGE_LIMIT', '服务器磁盘低水位'],
          ['FILE_NOT_FOUND', '文件不存在或已删除'],
          ['INVALID_OFFSET', '文件读取偏移非法'],
        ].map(([code, meaning]) => <div key={code}><code>{code}</code><span>{meaning}</span></div>)}</div>
      </DocSection>
      <DocSection id="ds-python" title="Python 客户端示例">
        <pre>{`from cryptography.hazmat.primitives.ciphers.aead import AESGCM
import json, secrets, time, requests

BASE = "https://server.example.com/api/v2/client/" + "your-slot"  # TODO(需要补充)：换成你的 API 域名
KEY  = base64.urlsafe_b64decode(KEY_B64URL + "=" * (-len(KEY_B64URL) % 4))

def aad(direction):
    return f"jur10n:client:v2:your-slot:1:{direction}".encode()

def call(payload):
    payload |= {"protocol": "jur10n-client-v2", "key_version": 1,
                "timestamp": int(time.time() * 1000), "nonce": secrets.token_urlsafe(24)}
    iv = secrets.token_bytes(12)
    data = iv + AESGCM(KEY).encrypt(iv, json.dumps(payload).encode(), aad("request"))
    r = requests.post(BASE, data=data, headers={"Content-Type": "application/octet-stream", "X-Key-Version": "1"})
    return json.loads(AESGCM(KEY).decrypt(r.content[:12], r.content[12:], aad("response")))

print(call({"op": "login", "code": "JUR-XXXX", "machine_proof": "..."})
)`}</pre>
        <p>完整可运行的 PyQt 桌面测试工具见仓库 <code>examples/pyqt_client.py</code>，覆盖登录、心跳、变量、上报、文件下载全部操作。</p>
      </DocSection>
    </article>
  </div>
}
function DocSection({ id, title, children }: { id: string; title: string; children: ReactNode }) { return <section className="doc-section" id={id}><h3>{title}</h3>{children}</section> }

function MonitoringPage({ refreshKey }: { refreshKey: number }) {
  const [snapshot, setSnapshot] = useState<MonitoringSnapshot | null>(null)
  const [error, setError] = useState('')
  const [loading, setLoading] = useState(true)
  useEffect(() => {
    let alive = true
    const load = () => { api.globalMonitoring().then((payload) => { if (alive) { setSnapshot(payload); setError('') } }).catch((reason) => { if (alive) setError(getErrorMessage(reason, '监控接口不可用')) }).finally(() => { if (alive) setLoading(false) }) }
    load()
    const timer = window.setInterval(load, 30000)
    return () => { alive = false; window.clearInterval(timer) }
  }, [refreshKey])
  const totals = snapshot?.totals
  const rssPercent = snapshot?.memory?.rss ? Math.min(100, Math.round(snapshot.memory.rss / (512 * 1024 * 1024) * 100)) : 0
  const diskPercent = snapshot?.storage?.totalBytes ? Math.min(100, Math.round((1 - snapshot.storage.freeBytes! / snapshot.storage.totalBytes) * 100)) : 0
  return <>
    {error && <InlineError message={error} />}
    <div className="monitor-grid">
      <MetricCard icon={Activity} label="近一小时请求" value={totals?.requestsLastHour} sample={snapshot?.generatedAt} loading={loading} />
      <MetricCard icon={Wifi} label="活跃会话" value={totals?.activeSessions} sample={snapshot?.generatedAt} loading={loading} />
      <MetricCard icon={AlertTriangle} label="失活心跳" value={totals?.staleSessions} sample={snapshot?.generatedAt} loading={loading} />
      <MetricCard icon={FileKey2} label="卡密总数" value={totals?.licenses} sample={snapshot?.generatedAt} loading={loading} />
      <MetricCard icon={ServerCog} label="软件槽位" value={totals?.softwareCount} sample={snapshot?.generatedAt} loading={loading} />
      <MetricCard icon={Gauge} label="负载均值" text={snapshot?.loadAverage?.map((value) => value.toFixed(2)).join(' / ')} sample={snapshot?.generatedAt} loading={loading} />
    </div>
    <div className="monitor-columns">
      <section className="panel panel-pad">
        <div className="section-heading"><div><p className="eyebrow"><span className="eyebrow-dot" />SOFTWARES</p><h2>槽位明细</h2></div><span className="live-indicator"><span className="status-pulse" />30s refresh</span></div>
        <div className="table-scroll"><table className="doc-table"><thead><tr><th>软件</th><th>状态</th><th>请求/时</th><th>活跃</th><th>失活</th><th>卡密</th></tr></thead><tbody>
          {(snapshot?.items || []).map((item) => <tr key={item.slug}><td><strong className="cell-primary">{item.name}</strong><code className="muted" style={{ fontSize: 11 }}>{item.slug}</code></td><td><StatusBadge status={item.status === 'active' ? 'active' : 'disabled'} /></td><td>{item.requestsLastHour ?? 0}</td><td>{item.activeSessions ?? 0}</td><td>{item.staleSessions ?? 0}</td><td>{item.licenses ?? 0}</td></tr>)}
          {!loading && (snapshot?.items || []).length === 0 && <tr><td colSpan={6}><span className="muted">暂无数据</span></td></tr>}
        </tbody></table></div>
      </section>
      <section className="panel panel-pad monitor-panel">
        <div className="section-heading"><div><p className="eyebrow"><span className="eyebrow-dot" />RESOURCE HEALTH</p><h2>资源健康</h2></div><Gauge size={16} className="muted-icon" /></div>
        <ResourceBar label="内存 RSS" percent={rssPercent} detail={snapshot?.memory?.rss ? formatBytes(snapshot.memory.rss) : '—'} />
        <ResourceBar label="磁盘已用" percent={diskPercent} detail={snapshot?.storage ? `${formatBytes(snapshot.storage.freeBytes)} 可用 / ${formatBytes(snapshot.storage.totalBytes)}` : '—'} />
        <ResourceBar label="CPU（累计 user+system）" percent={Math.min(100, Math.round(((snapshot?.cpu?.user ?? 0) + (snapshot?.cpu?.system ?? 0)) / 1_000_000))} detail={snapshot?.cpu ? `${formatMetric(Math.round((snapshot.cpu.user ?? 0) / 1000))} + ${formatMetric(Math.round((snapshot.cpu.system ?? 0) / 1000))} ms` : '—'} />
        <div className="check-list">
          <CheckItem title="SQLite 日志模式" detail={snapshot?.sqlite?.journalMode || '—'} />
          <CheckItem title="采样时间" detail={snapshot?.generatedAt ? formatDate(snapshot.generatedAt) : '—'} />
        </div>
      </section>
    </div>
  </>
}
function MetricCard({ icon: Icon, label, value, text, sample, loading }: { icon: typeof Activity; label: string; value?: number; text?: string; sample?: string; loading: boolean }) {
  return <div className="metric-card"><div className="metric-card-top"><span>{label}</span><Icon size={15} /></div>
    <strong>{loading ? <span className="skeleton inline" /> : text ?? (value === undefined ? '—' : formatMetric(value))}</strong>
    <small>{sample ? `采样于 ${formatDate(sample)}` : '等待后端指标'}</small></div>
}
function ResourceBar({ label, percent, detail }: { label: string; percent: number; detail: string }) {
  const normalized = Math.min(100, Math.max(0, Math.round(percent) || 0))
  return <div className="resource-bar"><div><span>{label}</span><code>{normalized}%</code></div><div className="bar-track"><span style={{ width: `${normalized}%` }} /></div><small>{detail}</small></div>
}

function GlobalSecurityPage({ refreshKey, notify }: { refreshKey: number; notify: (toast: Toast) => void }) {
  const [form, setForm] = useState<SecuritySettings>({ perMinute: 30, loginPerMinute: 10, maxClientPacketBytes: 262144, maxUploadBytes: 131072 })
  const [receive, setReceive] = useState<ReceiveSettings>({ enabled: true, maxPayloadBytes: 131072 })
  const [loading, setLoading] = useState(true)
  const [saving, setSaving] = useState(false)
  useEffect(() => { Promise.all([api.security(), api.receiveSettings()]).then(([security, incoming]) => { setForm((current) => ({ ...current, ...asRecord<SecuritySettings>(security) })); setReceive(asRecord<{ settings: ReceiveSettings }>(incoming).settings || receive) }).catch(() => undefined).finally(() => setLoading(false)) }, [refreshKey])
  const save = async (event: FormEvent) => { event.preventDefault(); setSaving(true); try { await Promise.all([api.updateSecurity(form), api.updateReceiveSettings(receive)]); notify({ type: 'success', message: '全局安全设置已保存' }) } catch (error) { alert2(notify, error, '全局安全设置保存失败') } finally { setSaving(false) } }
  return <div className="security-grid">
    <section className="panel security-main"><div className="section-heading"><div><p className="eyebrow"><span className="eyebrow-dot" />GLOBAL GUARDRAILS</p><h2>全局安全边界</h2><p className="section-description">覆盖所有软件槽位的入口限流、包大小和存储低水位。</p></div><ShieldCheck size={18} className="green-icon" /></div>
      {loading ? <VariableLoading /> : <form className="security-form" onSubmit={save}>
        <div className="form-row"><label>每 IP 每分钟请求数<input type="number" min="1" max="10000" value={form.perMinute} onChange={(event) => setForm({ ...form, perMinute: Number(event.target.value) })} /></label><label>登录失败每分钟<input type="number" min="1" max="100" value={form.loginPerMinute} onChange={(event) => setForm({ ...form, loginPerMinute: Number(event.target.value) })} /></label></div>
        <div className="form-row"><label>最大客户端包（KiB）<input type="number" min="1" value={Math.round(Number(form.maxClientPacketBytes || 0) / 1024)} onChange={(event) => setForm({ ...form, maxClientPacketBytes: Number(event.target.value) * 1024 })} /></label><label>最大上报（KiB）<input type="number" min="1" value={Math.round(receive.maxPayloadBytes / 1024)} onChange={(event) => setReceive({ ...receive, maxPayloadBytes: Number(event.target.value) * 1024 })} /></label></div>
        <label className="checkbox-label"><input type="checkbox" checked={receive.enabled} onChange={(event) => setReceive({ ...receive, enabled: event.target.checked })} />启用全局数据接收</label>
        <button className="button primary" disabled={saving}>{saving ? '保存中…' : <><Save size={14} />保存全局设置</>}</button>
      </form>}
    </section>
    <section className="panel security-side"><div className="section-heading"><div><p className="eyebrow"><span className="eyebrow-dot" />CONTROL CHECKS</p><h2>保护状态</h2></div><LockKeyhole size={17} className="green-icon" /></div>
      <div className="check-list">
        <CheckItem title="管理会话" detail="HttpOnly + CSRF 校验" />
        <CheckItem title="客户端加密" detail="v2 per-software AES-GCM" />
        <CheckItem title="审计记录" detail="高危操作必须留痕" />
        <CheckItem title="文件目录" detail="不由 Web server 直接暴露" />
      </div>
    </section>
  </div>
}
function CheckItem({ title, detail }: { title: string; detail: string }) { return <div className="check-item"><CheckCircle2 size={16} /><span><strong>{title}</strong><small>{detail}</small></span></div> }

function AuditPage({ refreshKey }: { refreshKey: number }) {
  const [items, setItems] = useState<AuditEntry[]>([])
  const [loading, setLoading] = useState(true)
  const [query, setQuery] = useState('')
  useEffect(() => { setLoading(true); api.audit({ search: query, limit: 100 }).then((payload) => setItems(asList<AuditEntry>(payload, ['items']))).catch(() => setItems([])).finally(() => setLoading(false)) }, [refreshKey])
  const filtered = useMemo(() => query ? items.filter((item) => JSON.stringify(item).toLowerCase().includes(query.toLowerCase())) : items, [items, query])
  return <>
    <div className="toolbar"><div className="search-box"><Search size={14} /><input value={query} onChange={(event) => setQuery(event.target.value)} placeholder="搜索操作、对象、用户名…" /></div><span className="toolbar-note"><LockKeyhole size={13} />只读 · 敏感字段已脱敏</span></div>
    <section className="panel table-panel"><TableHeader eyebrow="AUDIT TRAIL" title="审计日志" count={`${filtered.length} 条`} />
      <DataTable loading={loading} emptyIcon={FileText} emptyTitle="暂无审计记录" emptyDescription="管理员操作会自动记录在这里。"
        columns={['时间', '操作', '对象', '对象 ID', '操作者', '元数据']}
        rows={filtered.map((item) => [formatDate(item.createdAt), <strong className="cell-primary">{item.action || '—'}</strong>, item.objectType || '系统', <code>{item.objectId || '—'}</code>, item.username || '管理员', <span className="detail-cell">{formatMetadata(item.metadata)}</span>])} />
    </section>
  </>
}

function TableHeader({ eyebrow, title, count }: { eyebrow: string; title: string; count: string }) { return <div className="table-heading"><div><p className="eyebrow"><span className="eyebrow-dot" />{eyebrow}</p><h2>{title}</h2></div><span className="count-label">{count}</span></div> }
function DataTable({ loading, emptyIcon, emptyTitle, emptyDescription, columns, rows }: { loading: boolean; emptyIcon: typeof FileKey2; emptyTitle: string; emptyDescription: string; columns: string[]; rows: ReactNode[][] }) {
  return <div className="table-scroll"><table><thead><tr>{columns.map((column, index) => <th key={index}>{column}</th>)}</tr></thead>
    <tbody>{loading ? <TableLoading columns={columns.length} /> : rows.length === 0 ? <tr><td colSpan={columns.length}><EmptyState icon={emptyIcon} title={emptyTitle} description={emptyDescription} /></td></tr> : rows.map((row, index) => <tr key={index}>{row.map((cell, cellIndex) => <td key={cellIndex}>{cell}</td>)}</tr>)}</tbody></table></div>
}
function TableLoading({ columns }: { columns: number }) { return <>{[1, 2, 3, 4].map((row) => <tr key={row}>{Array.from({ length: columns }).map((_, column) => <td key={column}><span className="skeleton" /></td>)}</tr>)}</> }
function VariableLoading() { return <div className="loading-rows"><span className="skeleton" /><span className="skeleton" /><span className="skeleton" /></div> }
function StatCard({ icon: Icon, label, value, hint }: { icon: typeof Activity; label: string; value?: number; hint: string }) { return <div className="stat-card"><div className="stat-icon"><Icon size={16} /></div><div className="stat-meta"><span>{label}</span><strong>{value === undefined ? '—' : formatMetric(value)}</strong><small>{hint}</small></div></div> }
function Metric({ label, value }: { label: string; value?: number }) { return <div><span>{label}</span><strong>{value === undefined ? '—' : formatMetric(value)}</strong></div> }
function StatusBadge({ status }: { status?: string }) { const normalized = normalizedStatus(status); const labels: Record<string, string> = { active: '有效', enabled: '启用', success: '成功', received: '已接收', expired: '过期', disabled: '停用', revoked: '已封禁', failed: '失败', error: '异常', pending: '处理中', draft: '草稿', published: '已发布' }; return <span className={`status-badge ${normalized}`}><span />{labels[normalized] || status || '未知'}</span> }
function normalizedStatus(status?: string | null, expiresAt?: string | null) { if (expiresAt && new Date(expiresAt).getTime() < Date.now()) return 'expired'; return String(status || 'active').toLowerCase() }
function EmptyState({ icon: Icon, title, description, action, compact = false }: { icon: typeof KeyRound; title: string; description: string; action?: ReactNode; compact?: boolean }) { return <div className={`empty-state ${compact ? 'compact' : ''}`}><div className="empty-icon"><Icon size={19} /></div><strong>{title}</strong><p>{description}</p>{action}</div> }
function InlineError({ message }: { message: string }) { return <div className="inline-error"><AlertTriangle size={15} /><span>{message}</span></div> }
function ToastMessage({ toast, onClose }: { toast: Toast; onClose: () => void }) { const Icon = toast.type === 'success' ? CheckCircle2 : toast.type === 'error' ? XCircle : AlertTriangle; return <div className={`toast toast-${toast.type}`} role="status"><Icon size={16} /><span>{toast.message}</span><button className="icon-button" onClick={onClose} aria-label="关闭提示"><X size={14} /></button></div> }
function Modal({ eyebrow, title, children, onClose }: { eyebrow: string; title: string; children: ReactNode; onClose: () => void }) { return <div className="modal-backdrop"><div className="modal" role="dialog" aria-modal="true"><div className="modal-header"><div><p className="eyebrow"><span className="eyebrow-dot" />{eyebrow}</p><h2>{title}</h2></div><button className="icon-button" onClick={onClose} aria-label="关闭"><X size={17} /></button></div>{children}</div></div> }
function NotFoundSlot({ onBack }: { onBack: () => void }) { return <section className="panel"><EmptyState icon={ServerCog} title="找不到软件槽位" description="该槽位可能已被删除。" action={<button className="button secondary small" onClick={onBack}><ArrowLeft size={13} />返回总览</button>} /></section> }
function formatMetric(value: number) { return Number.isInteger(value) ? new Intl.NumberFormat('zh-CN').format(value) : value.toFixed(2) }
function formatDate(value?: string | null, dateOnly = false) { if (!value) return '—'; const date = new Date(value); if (Number.isNaN(date.getTime())) return value; return new Intl.DateTimeFormat('zh-CN', dateOnly ? { month: 'short', day: 'numeric' } : { month: '2-digit', day: '2-digit', hour: '2-digit', minute: '2-digit', hour12: false }).format(date) }
function formatBytes(value?: number) { if (typeof value !== 'number' || !Number.isFinite(value)) return '—'; if (value < 1024) return `${value} B`; if (value < 1024 * 1024) return `${(value / 1024).toFixed(1)} KB`; if (value < 1024 * 1024 * 1024) return `${(value / (1024 * 1024)).toFixed(1)} MB`; return `${(value / (1024 * 1024 * 1024)).toFixed(1)} GB` }
function formatPayload(value: unknown) { if (value === undefined || value === null) return '（无 payload）'; if (typeof value === 'string') return value; try { return JSON.stringify(value, null, 2) } catch { return String(value) } }
function dataStoreLicenseLabel(item: DataStoreRecord) { return String(item.publicId || item.licenseId || '—') }
function dataStoreSlotLabel(item: DataStoreRecord) { return String(item.slotSlug || item.slotId || '—') }
function formatMetadata(value: unknown) { if (value === undefined || value === null) return '—'; if (typeof value === 'string') return value; try { return JSON.stringify(value) } catch { return String(value) } }
function truncate(value: string, length: number) { return value.length > length ? `${value.slice(0, length)}…` : value }
async function copyText(text: string) { if (!navigator.clipboard) throw new Error('当前浏览器不支持复制'); await navigator.clipboard.writeText(text) }
function getErrorMessage(error: unknown, fallback: string) { return error instanceof ApiError ? error.message : error instanceof Error ? error.message : fallback }
export default App
