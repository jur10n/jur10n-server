export const API_BASE_URL = (import.meta.env.VITE_API_BASE_URL || '').replace(/\/$/, '')

let csrfToken = ''
const CSRF_STORAGE_KEY = 'jur10n.dashboard.csrf-token'

type QueryValue = string | number | boolean | undefined | null
export type QueryParams = Record<string, QueryValue>

function normalizeSoftware(value: SoftwareSlot): SoftwareSlot {
  const record = value as SoftwareSlot & Record<string, unknown>
  const freeSoftware = typeof record.freeSoftware === 'boolean'
    ? record.freeSoftware
    : typeof record.free_software === 'boolean'
      ? record.free_software
      : typeof record.isFree === 'boolean'
        ? record.isFree
        : typeof record.is_free === 'boolean'
          ? record.is_free
          : undefined
  return {
    ...value,
    enabled: value.status ? value.status !== 'disabled' : value.enabled,
    ...(freeSoftware === undefined ? {} : { freeSoftware }),
  }
}

function toSoftwarePayload(body: Partial<SoftwareSlotForm> | Record<string, unknown>) {
  const payload = { ...body } as Record<string, unknown>
  if (Object.prototype.hasOwnProperty.call(payload, 'enabled')) {
    payload.status = payload.enabled ? 'active' : 'disabled'
    delete payload.enabled
  }
  if (Object.prototype.hasOwnProperty.call(payload, 'freeSoftware')) {
    payload.isFree = Boolean(payload.freeSoftware)
    delete payload.freeSoftware
  }
  return payload
}

export class ApiError extends Error {
  status: number
  code?: string
  details?: unknown

  constructor(message: string, status: number, code?: string, details?: unknown) {
    super(message)
    this.name = 'ApiError'
    this.status = status
    this.code = code
    this.details = details
  }
}

export type RequestOptions = Omit<RequestInit, 'body'> & { body?: unknown }

function readCsrfToken() {
  if (csrfToken) return csrfToken
  if (typeof window !== 'undefined') {
    try { csrfToken = window.sessionStorage.getItem(CSRF_STORAGE_KEY) || '' } catch { /* Storage may be unavailable. */ }
  }
  return csrfToken
}

function saveCsrfToken(token: string | null | undefined) {
  csrfToken = token || ''
  if (typeof window !== 'undefined') {
    try {
      if (csrfToken) window.sessionStorage.setItem(CSRF_STORAGE_KEY, csrfToken)
      else window.sessionStorage.removeItem(CSRF_STORAGE_KEY)
    } catch { /* The in-memory token is enough for this page session. */ }
  }
}

function clearCsrfToken() { saveCsrfToken('') }

function isBinaryBody(body: unknown): body is BodyInit {
  return body instanceof Blob || body instanceof ArrayBuffer || ArrayBuffer.isView(body)
}

async function request<T>(path: string, options: RequestOptions = {}): Promise<T> {
  const method = String(options.method || 'GET').toUpperCase()
  const headers = new Headers(options.headers)
  const binary = isBinaryBody(options.body)
  if (options.body !== undefined && !binary) headers.set('content-type', 'application/json')
  headers.set('accept', 'application/json')
  if (!['GET', 'HEAD', 'OPTIONS'].includes(method)) {
    const token = readCsrfToken()
    if (token) headers.set('X-CSRF-Token', token)
  }

  const response = await fetch(`${API_BASE_URL}${path}`, {
    ...options,
    method,
    headers,
    credentials: 'include',
    body: options.body === undefined ? undefined : binary ? (options.body as BodyInit) : JSON.stringify(options.body),
  })
  const contentType = response.headers.get('content-type') || ''
  let payload: unknown = null
  if (response.status !== 204) {
    try { payload = contentType.includes('json') ? await response.json() : await response.text() } catch { payload = null }
  }
  if (!response.ok) {
    const record = payload && typeof payload === 'object' && !Array.isArray(payload) ? payload as Record<string, unknown> : null
    const code = typeof record?.code === 'string' ? record.code : typeof record?.error === 'string' ? record.error : undefined
    const message = typeof record?.message === 'string' ? record.message : code || (response.status === 401 ? '登录已失效，请重新登录' : `请求失败（${response.status}）`)
    if (response.status === 401) clearCsrfToken()
    throw new ApiError(message, response.status, code, payload)
  }
  return payload as T
}

function toQuery(params?: QueryParams) {
  if (!params) return ''
  const query = new URLSearchParams()
  Object.entries(params).forEach(([key, value]) => { if (value !== undefined && value !== null && value !== '') query.set(key, String(value)) })
  const value = query.toString()
  return value ? `?${value}` : ''
}

export interface AuthResponse { user: User; csrfToken?: string | null; [key: string]: unknown }
export interface User { id?: string | number; username?: string; role?: string; mustChangePassword?: boolean; [key: string]: unknown }
export interface Overview { licenses?: number; activeLicenses?: number; variables?: number; reportsToday?: number; reports?: number; activeSessions?: number; [key: string]: unknown }
export interface SoftwareSlot {
  id?: string | number
  slug: string
  name: string
  description?: string
  announcement?: string
  announcementUpdatedAt?: string | null
  status?: string
  enabled?: boolean
  machineCheck?: boolean
  ipCheck?: boolean
  ipChangePolicy?: string
  heartbeatTimeout?: number
  sessionTtl?: number
  freeSoftware?: boolean
  protocolVersion?: string
  currentKeyVersion?: number
  keyFingerprint?: string
  createdAt?: string
  updatedAt?: string
  licenseCount?: number
  activeLicenseCount?: number
  variableCount?: number
  dataSlotCount?: number
  activeSessions?: number
  qps?: number
  storageUsedBytes?: number
  [key: string]: unknown
}
export interface SoftwareSlotForm { slug?: string; name?: string; description?: string; enabled?: boolean; machineCheck?: boolean; ipCheck?: boolean; ipChangePolicy?: string; heartbeatTimeout?: number; sessionTtl?: number; freeSoftware?: boolean; [key: string]: unknown }
export interface SoftwareKey { id?: string | number; softwareId?: string | number; version?: number; fingerprint?: string; status?: string; notBefore?: string; notAfter?: string; createdAt?: string; revokedAt?: string; exportedAt?: string; [key: string]: unknown }
export interface License {
  id?: string | number
  publicId: string
  code?: string | null
  status?: string
  expiresAt?: string | null
  maxDevices?: number
  deviceCount?: number
  machineHash?: string | null
  boundAt?: string | null
  note?: string
  createdAt?: string
  lastUsedAt?: string | null
  [key: string]: unknown
}
export interface LicenseGenerateForm { count?: number; prefix?: string; expiresAt?: string; maxDevices?: number; note?: string; codes?: string[] }
export interface LicenseBatchForm { action: 'ban' | 'activate' | 'reset-binding' | 'delete'; ids: Array<string | number> }
export interface LicenseBinding { id?: string | number; licenseId?: string | number; publicId?: string; machineHash?: string; ipHash?: string; firstBoundAt?: string; lastVerifiedAt?: string; resetAt?: string; [key: string]: unknown }
export interface ClientSession { id?: string | number; licenseId?: string | number; publicId?: string; machineHash?: string; ipHash?: string; createdAt?: string; lastHeartbeatAt?: string; expiresAt?: string; revokedAt?: string; active?: boolean; [key: string]: unknown }
export interface VariableForm { key: string; value: unknown; enabled?: boolean; [key: string]: unknown }
export interface RemoteVariable extends VariableForm { id?: string | number; version?: number; createdAt?: string; updatedAt?: string; [key: string]: unknown }
export interface DataSlot { id?: string | number; slug: string; name: string; description?: string; enabled?: boolean; [key: string]: unknown }
export interface DataSlotForm { slug: string; name: string; description?: string; enabled?: boolean; [key: string]: unknown }
export interface DataUsage { slotId?: string | number; slug?: string; name?: string; enabled?: boolean; usedBytes?: number; recordCount?: number; lastReceivedAt?: string | null; quotaBytes?: number; updatedAt?: string; [key: string]: unknown }
export interface DataStoreRecord { id?: string | number; slotId?: string | number; slotSlug?: string; licenseId?: string | number; publicId?: string; value?: unknown; size?: number; sha256?: string; version?: number; createdAt?: string; updatedAt?: string; [key: string]: unknown }
export interface Announcement { softwareSlot?: string; announcement?: string; updatedAt?: string | null; [key: string]: unknown }
export interface Report { id?: string | number; dataSlot?: string; slotId?: string | number; slotSlug?: string; publicId?: string; licenseId?: string | number; machineHash?: string; size?: number; sha256?: string; receivedAt?: string; status?: string; payload?: unknown; [key: string]: unknown }
export interface ReceiveSettings { enabled: boolean; maxPayloadBytes: number; [key: string]: unknown }
export interface ResourceFile { id?: string | number; softwareId?: string | number; originalName: string; sha256: string; size: number; mime?: string; status?: string; createdAt?: string; [key: string]: unknown }
export interface MonitoringSoftwareRow { slug?: string; name?: string; status?: string; requestsLastHour?: number; activeSessions?: number; staleSessions?: number; licenses?: number; [key: string]: unknown }
export interface MonitoringSnapshot {
  generatedAt?: string
  totals?: { requestsLastHour?: number; activeSessions?: number; staleSessions?: number; licenses?: number; softwareCount?: number }
  items?: MonitoringSoftwareRow[]
  memory?: { rss?: number; heapTotal?: number; heapUsed?: number; external?: number }
  cpu?: { user?: number; system?: number }
  loadAverage?: number[]
  storage?: { freeBytes?: number; totalBytes?: number } | null
  sqlite?: { journalMode?: string }
  [key: string]: unknown
}
export interface RateLimitSettings { perMinute: number; loginPerMinute?: number; maxClientPacketBytes?: number; maxUploadBytes?: number; diskLowWatermarkBytes?: number; [key: string]: unknown }
export interface SecuritySettings extends RateLimitSettings { [key: string]: unknown }
export interface SoftwareSecurity { protocolVersion?: string; machineCheck?: boolean; ipCheck?: boolean; ipChangePolicy?: string; heartbeatTimeout?: number; sessionTtl?: number; [key: string]: unknown }
export interface AuditEntry { id?: string | number; action?: string; objectType?: string; objectId?: string; username?: string; metadata?: unknown; createdAt?: string; [key: string]: unknown }
export interface ApiDocument { title?: string; description?: string; protocol?: string; endpoint?: string; contentType?: string; timestampWindowMs?: number; heartbeatTimeoutSeconds?: number; packetLimitBytes?: number; reportLimitBytes?: number; slotQuotaBytes?: number; operations?: Array<Record<string, unknown> | string>; errorCodes?: Array<Record<string, unknown>>; aad?: { request?: string; response?: string }; software?: SoftwareSlot; [key: string]: unknown }

export interface VpnNode {
  name?: string
  protocol?: string
  transport?: string
  address?: string
  port?: number
  camouflage?: string
  [key: string]: unknown
}
export interface VpnInfo {
  enabled?: boolean
  name?: string | null
  server?: string | null
  subscriptionUrl?: string | null
  updatedAt?: string | null
  nodes?: VpnNode[]
  message?: string
  [key: string]: unknown
}

export const api = {
  login: async (username: string, password: string) => { const payload = await request<AuthResponse>('/api/admin/login', { method: 'POST', body: { username, password } }); saveCsrfToken(payload.csrfToken); return payload },
  me: async () => { const payload = await request<AuthResponse>('/api/admin/me'); saveCsrfToken(payload.csrfToken); return payload },
  changePassword: (password: string) => request<{ ok: boolean }>('/api/admin/password', { method: 'POST', body: { password } }),
  logout: async () => { try { return await request<{ ok: boolean }>('/api/admin/logout', { method: 'POST' }) } finally { clearCsrfToken() } },
  overview: () => request<Overview>('/api/admin/overview'),

  // Software slots.
  softwareSlots: async (params?: QueryParams) => { const payload = await request<{ items: SoftwareSlot[] }>(`/api/admin/software${toQuery(params)}`); return { ...payload, items: (payload.items || []).map(normalizeSoftware) } },
  softwareSlot: async (slug: string) => { const payload = await request<{ software: SoftwareSlot }>(`/api/admin/software/${encodeURIComponent(slug)}`); return normalizeSoftware(payload.software) },
  createSoftwareSlot: async (body: SoftwareSlotForm) => { const payload = await request<{ software: SoftwareSlot }>('/api/admin/software', { method: 'POST', body: toSoftwarePayload(body) }); return normalizeSoftware(payload.software) },
  updateSoftwareSlot: async (slug: string, body: Partial<SoftwareSlotForm>) => { const payload = await request<{ software: SoftwareSlot }>(`/api/admin/software/${encodeURIComponent(slug)}`, { method: 'PATCH', body: toSoftwarePayload(body) }); return normalizeSoftware(payload.software) },
  deleteSoftwareSlot: (slug: string) => request<{ ok: boolean }>(`/api/admin/software/${encodeURIComponent(slug)}`, { method: 'DELETE' }),
  softwareKeys: (slug: string) => request<{ items: SoftwareKey[] }>(`/api/admin/software/${encodeURIComponent(slug)}/keys`),
  rotateSoftwareKey: (slug: string) => request<{ key: SoftwareKey; exportRequired?: boolean }>(`/api/admin/software/${encodeURIComponent(slug)}/keys/rotate`, { method: 'POST', body: {} }),
  exportSoftwareConfig: (slug: string, version: number | string) => request<Record<string, unknown>>(`/api/admin/software/${encodeURIComponent(slug)}/keys/${encodeURIComponent(String(version))}/export`, { method: 'POST', body: {} }),

  // Variables.
  variablesFor: (slug: string) => request<{ items: RemoteVariable[] }>(`/api/admin/software/${encodeURIComponent(slug)}/variables`),
  createVariableFor: (slug: string, body: VariableForm) => request<{ ok: boolean }>(`/api/admin/software/${encodeURIComponent(slug)}/variables`, { method: 'POST', body }),
  updateVariableFor: (slug: string, id: string | number, body: Partial<VariableForm>) => request<{ ok: boolean }>(`/api/admin/software/${encodeURIComponent(slug)}/variables/${encodeURIComponent(String(id))}`, { method: 'PATCH', body }),
  deleteVariableFor: (slug: string, id: string | number) => request<{ ok: boolean }>(`/api/admin/software/${encodeURIComponent(slug)}/variables/${encodeURIComponent(String(id))}`, { method: 'DELETE' }),

  // Licenses, bindings and sessions.
  licensesFor: (slug: string, params?: QueryParams) => request<{ items: License[]; page?: number; limit?: number; total?: number }>(`/api/admin/software/${encodeURIComponent(slug)}/licenses${toQuery(params)}`),
  createLicenseFor: (slug: string, body: LicenseGenerateForm) => request<{ codes: string[]; count: number; duplicates?: string[] }>(`/api/admin/software/${encodeURIComponent(slug)}/licenses`, { method: 'POST', body }),
  batchLicenses: (slug: string, body: LicenseBatchForm) => request<{ ok: boolean; changed: number }>(`/api/admin/software/${encodeURIComponent(slug)}/licenses/batch`, { method: 'POST', body }),
  updateLicenseFor: (slug: string, id: string | number, body: { status?: string; expiresAt?: string; maxDevices?: number; note?: string }) => request<{ license: License }>(`/api/admin/software/${encodeURIComponent(slug)}/licenses/${encodeURIComponent(String(id))}`, { method: 'PATCH', body }),
  deleteLicenseFor: (slug: string, id: string | number) => request<{ ok: boolean }>(`/api/admin/software/${encodeURIComponent(slug)}/licenses/${encodeURIComponent(String(id))}`, { method: 'DELETE' }),
  resetBinding: (slug: string, licenseId: string | number) => request<{ ok: boolean }>(`/api/admin/software/${encodeURIComponent(slug)}/licenses/${encodeURIComponent(String(licenseId))}/reset-binding`, { method: 'POST', body: {} }),
  bindingsFor: (slug: string) => request<{ items: LicenseBinding[] }>(`/api/admin/software/${encodeURIComponent(slug)}/bindings`),
  sessionsFor: (slug: string) => request<{ items: ClientSession[] }>(`/api/admin/software/${encodeURIComponent(slug)}/sessions`),
  revokeSession: (slug: string, sessionId: string | number) => request<{ ok: boolean }>(`/api/admin/software/${encodeURIComponent(slug)}/sessions/${encodeURIComponent(String(sessionId))}/revoke`, { method: 'POST', body: {} }),

  // Data slots, usage and reports.
  dataSlotsFor: (slug: string) => request<{ items: DataSlot[]; quotaBytes?: number }>(`/api/admin/software/${encodeURIComponent(slug)}/data-slots`),
  createDataSlot: (slug: string, body: DataSlotForm) => request<{ dataSlot: DataSlot; quotaBytes?: number }>(`/api/admin/software/${encodeURIComponent(slug)}/data-slots`, { method: 'POST', body }),
  updateDataSlot: (slug: string, id: string | number, body: Partial<DataSlotForm>) => request<{ ok: boolean }>(`/api/admin/software/${encodeURIComponent(slug)}/data-slots/${encodeURIComponent(String(id))}`, { method: 'PATCH', body }),
  deleteDataSlot: (slug: string, id: string | number, force = false) => request<{ ok: boolean; deletedRecords?: number }>(`/api/admin/software/${encodeURIComponent(slug)}/data-slots/${encodeURIComponent(String(id))}${force ? '?force=true' : ''}`, { method: 'DELETE' }),
  dataUsageFor: (slug: string) => request<{ items: DataUsage[] }>(`/api/admin/software/${encodeURIComponent(slug)}/data-slots/usage`),
  clearDataSlotHistory: (slug: string, slot: string) => request<{ ok: boolean; deleted: number }>(`/api/admin/software/${encodeURIComponent(slug)}/data-slots/${encodeURIComponent(slot)}/history`, { method: 'DELETE' }),
  dataStoreFor: (slug: string, params?: QueryParams) => request<{ items: DataStoreRecord[] }>(`/api/admin/software/${encodeURIComponent(slug)}/data-store${toQuery(params)}`),
  dataStoreDeleteFor: (slug: string, id: string | number) => request<{ ok: boolean }>(`/api/admin/software/${encodeURIComponent(slug)}/data-store/${encodeURIComponent(String(id))}`, { method: 'DELETE' }),
  getAnnouncement: (slug: string) => request<Announcement>(`/api/admin/software/${encodeURIComponent(slug)}/announcement`),
  updateAnnouncement: (slug: string, announcement: string) => request<Announcement>(`/api/admin/software/${encodeURIComponent(slug)}/announcement`, { method: 'PUT', body: { announcement } }),
  reportsFor: (slug: string, params?: QueryParams) => request<{ items: Report[]; page?: number; limit?: number; total?: number }>(`/api/admin/software/${encodeURIComponent(slug)}/reports${toQuery(params)}`),
  reportFor: (slug: string, id: string | number) => request<Report>(`/api/admin/software/${encodeURIComponent(slug)}/reports/${encodeURIComponent(String(id))}`),
  deleteReportFor: (slug: string, id: string | number) => request<{ ok: boolean }>(`/api/admin/software/${encodeURIComponent(slug)}/reports/${encodeURIComponent(String(id))}`, { method: 'DELETE' }),

  // File resources.
  resourcesFor: (slug: string) => request<{ items: ResourceFile[] }>(`/api/admin/software/${encodeURIComponent(slug)}/resources`),
  uploadResource: async (slug: string, file: File) => {
    // Chunked upload session: init -> PUT 4 MiB chunks -> complete. Every request
    // stays small, so no whole-file base64 copy is held in memory.
    const base = `/api/admin/software/${encodeURIComponent(slug)}/uploads`
    const init = await request<{ uploadId: string; offset: number }>(base, { method: 'POST', body: { originalName: file.name, size: file.size, mime: file.type || 'application/octet-stream' } })
    const chunkSize = 4 * 1024 * 1024
    let offset = Number(init.offset) || 0
    while (offset < file.size) {
      const chunk = file.slice(offset, Math.min(offset + chunkSize, file.size))
      try {
        const part = await request<{ offset: number; complete: boolean }>(`${base}/${encodeURIComponent(init.uploadId)}`, {
          method: 'PUT',
          headers: { 'x-upload-offset': String(offset), 'content-type': 'application/octet-stream' },
          body: chunk,
        })
        offset = Number(part.offset) || offset + chunk.size
      } catch (error) {
        if (error instanceof ApiError && error.status === 409) {
          const expected = (error.details as { expectedOffset?: number } | null)?.expectedOffset
          if (typeof expected === 'number' && expected >= 0 && expected < offset) { offset = expected; continue }
        }
        throw error
      }
    }
    return request<{ resource: ResourceFile }>(`${base}/${encodeURIComponent(init.uploadId)}/complete`, { method: 'POST', body: {} })
  },
  deleteResource: (slug: string, id: string | number) => request<{ ok: boolean }>(`/api/admin/software/${encodeURIComponent(slug)}/resources/${encodeURIComponent(String(id))}`, { method: 'DELETE' }),

  // API 文档为协议级静态说明，不按软件槽位加载。
  globalMonitoring: () => request<MonitoringSnapshot>('/api/admin/monitoring'),

  // VPN 模块（服务端 sing-box 订阅）。
  vpn: async () => { const payload = await request<{ vpn: VpnInfo }>('/api/admin/vpn'); return payload?.vpn || { enabled: false } },
  securityFor: async (slug: string) => { const payload = await request<{ security: SoftwareSecurity }>(`/api/admin/software/${encodeURIComponent(slug)}/security`); return payload.security || {} },
  updateSecurityFor: async (slug: string, body: Record<string, unknown>) => { const payload = await request<{ security: SoftwareSecurity }>(`/api/admin/software/${encodeURIComponent(slug)}/security`, { method: 'PUT', body }); return payload.security || {} },
  security: () => request<SecuritySettings>('/api/admin/security'),
  updateSecurity: (body: Partial<SecuritySettings>) => request<SecuritySettings>('/api/admin/security', { method: 'PUT', body }),
  receiveSettings: () => request<{ settings: ReceiveSettings }>('/api/admin/receive-settings'),
  updateReceiveSettings: (body: ReceiveSettings) => request<{ settings: ReceiveSettings }>('/api/admin/receive-settings', { method: 'PUT', body }),
  audit: (params?: QueryParams) => request<{ items: AuditEntry[]; page?: number; limit?: number; total?: number }>(`/api/admin/audit${toQuery(params)}`),
}

export function unwrap<T>(payload: unknown, keys: string[] = []): T {
  if (payload && typeof payload === 'object' && !Array.isArray(payload)) {
    const record = payload as Record<string, unknown>
    for (const key of keys) if (record[key] !== undefined) return record[key] as T
    if ('data' in record) return record.data as T
    if ('result' in record) return record.result as T
  }
  return payload as T
}

export function asList<T>(payload: unknown, keys: string[] = []): T[] {
  const value = unwrap<unknown>(payload, keys)
  if (Array.isArray(value)) return value as T[]
  if (value && typeof value === 'object') {
    const record = value as Record<string, unknown>
    for (const key of ['items', 'records', 'rows', 'list', 'slots', 'variables', 'licenses', 'sessions', 'bindings', 'dataSlots', 'resources', 'releases', 'files']) {
      if (Array.isArray(record[key])) return record[key] as T[]
    }
  }
  return []
}

export function asRecord<T extends object = Record<string, unknown>>(payload: unknown): T {
  const value = unwrap<unknown>(payload)
  return value && typeof value === 'object' && !Array.isArray(value) ? value as T : {} as T
}
