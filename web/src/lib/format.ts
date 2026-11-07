const rtf = new Intl.RelativeTimeFormat(undefined, { numeric: "auto" })

export function ago(iso?: string): string {
  if (!iso) return "never"
  const t = Date.parse(iso)
  if (Number.isNaN(t)) return iso
  const s = Math.round((t - Date.now()) / 1000)
  const abs = Math.abs(s)
  if (abs < 60) return rtf.format(s, "second")
  if (abs < 3600) return rtf.format(Math.round(s / 60), "minute")
  if (abs < 86400) return rtf.format(Math.round(s / 3600), "hour")
  if (abs < 86400 * 45) return rtf.format(Math.round(s / 86400), "day")
  return new Date(t).toLocaleDateString()
}

export function dateTime(iso?: string): string {
  if (!iso) return "—"
  const t = Date.parse(iso)
  return Number.isNaN(t) ? iso : new Date(t).toLocaleString()
}

export function shortDate(day: string): string {
  const t = Date.parse(day)
  return Number.isNaN(t) ? day : new Date(t).toLocaleDateString(undefined, { month: "short", day: "numeric" })
}

const nf = new Intl.NumberFormat()
export const num = (n?: number) => nf.format(n ?? 0)

export function pct(n?: number, digits = 1): string {
  if (!n) return "—"
  return `${(n * 100).toFixed(digits)}%`
}

export function duration(ms?: number): string {
  if (!ms) return "—"
  const s = Math.round(ms / 1000)
  if (s < 60) return `${s}s`
  const m = Math.floor(s / 60)
  if (m < 60) return `${m}m ${s % 60}s`
  return `${Math.floor(m / 60)}h ${m % 60}m`
}

export function interval(sec?: number): string {
  if (!sec) return "—"
  if (sec % 86400 === 0) return `${sec / 86400}d`
  if (sec % 3600 === 0) return `${sec / 3600}h`
  return `${Math.round(sec / 60)}m`
}

export const statusLabel = (s: string) => s.replace(/_/g, " ").replace(/^\w/, (c) => c.toUpperCase())

export function splitList(s?: string): string[] {
  if (!s) return []
  try {
    const v = JSON.parse(s)
    if (Array.isArray(v)) return v.map(String).filter(Boolean)
  } catch {
    /* comma separated */
  }
  return s.split(/[,\s]+/).filter(Boolean)
}
