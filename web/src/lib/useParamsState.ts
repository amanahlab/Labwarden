import { useCallback } from "react"
import { useSearchParams } from "react-router"

type Value = string | number | string[] | undefined | null

// Table state (filters, sort, page) lives in the URL so views are linkable
// and survive reloads. Any change other than the page resets to page 1.
export function useParamsState(defaults: Record<string, string> = {}) {
  const [sp, setSp] = useSearchParams()

  const get = useCallback((k: string) => sp.get(k) ?? defaults[k] ?? "", [sp, defaults])
  const getList = useCallback((k: string) => (sp.get(k) ?? "").split(",").filter(Boolean), [sp])

  const set = useCallback(
    (patch: Record<string, Value>) => {
      setSp(
        (prev) => {
          const n = new URLSearchParams(prev)
          for (const [k, v] of Object.entries(patch)) {
            const s = Array.isArray(v) ? v.join(",") : v == null ? "" : String(v)
            if (s === "" || s === defaults[k]) n.delete(k)
            else n.set(k, s)
          }
          if (!("page" in patch)) n.delete("page")
          return n
        },
        { replace: true },
      )
    },
    [setSp, defaults],
  )

  const page = Math.max(1, Number(sp.get("page") ?? 1) || 1)
  const size = Number(sp.get("size") ?? defaults.size ?? 25) || 25

  const toggleSort = useCallback(
    (key: string) => {
      const cur = sp.get("sort") ?? defaults.sort
      const order = sp.get("order") ?? defaults.order ?? "desc"
      if (cur === key) set({ sort: key, order: order === "desc" ? "asc" : "desc" })
      else set({ sort: key, order: "desc" })
    },
    [sp, defaults, set],
  )

  return { sp, get, getList, set, page, size, toggleSort, sort: get("sort"), order: get("order") || "desc" }
}
