// Typed client for the LabWarden REST API (/api/v1).

export type Severity = "Critical" | "High" | "Medium" | "Low" | "Negligible" | "Unknown"
export const SEVERITIES: Severity[] = ["Critical", "High", "Medium", "Low", "Negligible", "Unknown"]
export type TriageStatus = "open" | "acknowledged" | "ignored" | "false_positive"
export const TRIAGE_STATUSES: TriageStatus[] = ["open", "acknowledged", "ignored", "false_positive"]

export interface Counts {
  critical: number
  high: number
  medium: number
  low: number
  negligible: number
  unknown: number
  total: number
  fixable: number
}

export interface List<T> {
  items: T[]
  total: number
  page: number
  size: number
}

export interface NameCount {
  name: string
  count: number
}

export interface Summary {
  findings: Counts
  unique: Counts
  kev: number
  hosts: number
  stale_hosts: number
  failing_hosts: number
  targets: number
  new_last_7d: number
  scans_24h: number
  last_scan: string
  by_fix_state: NameCount[]
  by_pkg_type: NameCount[]
  by_group: NameCount[]
  by_status: NameCount[]
  top_vulns: { id: string; severity: Severity; risk: number; epss: number; kev: boolean; hosts: number; packages: string }[]
  top_hosts: ({ id: number; name: string; score: number } & Counts)[]
  top_packages: NameCount[]
}

export interface DailyStat extends Counts {
  day: string
  hosts: number
  kev: number
}

export interface VulnRow {
  id: string
  severity: Severity
  description: string
  aliases: string
  cvss: number
  epss: number
  epss_pct: number
  kev: boolean
  risk: number
  hosts: number
  instances: number
  packages: string
  fixable: boolean
  first_seen: string
  status: TriageStatus
}

export interface FindingRow {
  id: number
  vuln_id: string
  severity: Severity
  pkg_name: string
  pkg_version: string
  pkg_type: string
  purl: string
  location: string
  fix_state: string
  fix_versions: string
  risk: number
  epss: number
  kev: boolean
  cvss: number
  first_seen: string
  target_id: number
  target_name: string
  host_id: number
  host_name: string
  group: string
  status: TriageStatus
}

export interface VulnDetail {
  id: string
  severity: Severity
  description: string
  data_source: string
  namespace: string
  urls: string
  cvss: number
  cvss_vector: string
  epss: number
  epss_pct: number
  kev: boolean
  cwes: string
  aliases: string
  risk: number
  first_seen: string
  updated_at: string
  status: TriageStatus
  note: string
}

export type HostStatus = "ok" | "stale" | "failing"

export interface HostRow extends Counts {
  id: number
  name: string
  kind: string
  group: string
  os: string
  arch: string
  ip: string
  agent_version: string
  notes: string
  interval_sec: number
  first_seen: string
  last_seen: string
  last_run_status: string
  status: HostStatus
  targets: number
  score: number
}

export interface TargetRow extends Counts {
  id: number
  name: string
  type: string
  distro: string
  first_seen: string
  last_scanned: string
  retired_at: string
}

export interface GroupRow extends Counts {
  name: string
  hosts: number
  stale: number
}

export interface ScanRow extends Counts {
  id: number
  host_id: number
  host_name: string
  target_id: number
  target_name: string
  target_type: string
  source: string
  run_id: string
  grype_version: string
  db_built: string
  scanned_at: string
  received_at: string
  duration_ms: number
  new: number
  fixed: number
}

export interface EventRow {
  id: number
  ts: string
  level: "debug" | "info" | "warn" | "error"
  source: string
  host: string
  run_id: string
  message: string
}

export interface Token {
  id: number
  name: string
  prefix: string
  created_at: string
  last_used: string
}

export interface CentralTarget {
  id: number
  ref: string
  host_name: string
  group: string
  interval_min: number
  enabled: boolean
  last_run: string
  last_status: string
  created_at: string
}

export interface SystemInfo {
  version: string
  auth_enabled: boolean
  max_report_mb: number
  notify: { enabled: boolean; format: string; min_severity: string; kev: boolean }
  scanner: {
    available: boolean
    grype_version: string
    db_built: string
    db_schema: string
    db_checked: string
    db_error?: string
    running?: string
  }
  queue: { queued: number; running: number; failed_24h: number }
}

export interface Me {
  authenticated: boolean
  auth_enabled: boolean
  version: string
}

export class ApiError extends Error {
  status: number
  constructor(status: number, message: string) {
    super(message)
    this.status = status
  }
}

type Params = Record<string, string | number | boolean | string[] | undefined | null>

export function qs(params: Params = {}): string {
  const u = new URLSearchParams()
  for (const [k, v] of Object.entries(params)) {
    if (v === undefined || v === null || v === "" || v === false) continue
    if (Array.isArray(v)) {
      if (v.length) u.set(k, v.join(","))
    } else {
      u.set(k, String(v))
    }
  }
  const s = u.toString()
  return s ? `?${s}` : ""
}

let onUnauthorized: () => void = () => {}
export function setUnauthorizedHandler(fn: () => void) {
  onUnauthorized = fn
}

async function request<T>(method: string, path: string, body?: unknown): Promise<T> {
  const res = await fetch(`/api/v1${path}`, {
    method,
    credentials: "same-origin",
    headers: body !== undefined ? { "Content-Type": "application/json" } : undefined,
    body: body !== undefined ? JSON.stringify(body) : undefined,
  })
  if (res.status === 401 && !path.startsWith("/auth/")) onUnauthorized()
  if (!res.ok) {
    let msg = res.statusText
    try {
      const j = await res.json()
      msg = j.error ?? msg
    } catch {
      /* not JSON */
    }
    throw new ApiError(res.status, msg)
  }
  return (await res.json()) as T
}

export const api = {
  get: <T>(path: string, params?: Params) => request<T>("GET", path + qs(params)),
  post: <T>(path: string, body: unknown = {}) => request<T>("POST", path, body),
  put: <T>(path: string, body: unknown) => request<T>("PUT", path, body),
  patch: <T>(path: string, body: unknown) => request<T>("PATCH", path, body),
  del: <T>(path: string) => request<T>("DELETE", path),
}
