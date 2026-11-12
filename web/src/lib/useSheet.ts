import { useCallback, useEffect, useRef } from "react"
import { useLocation, useNavigate, useSearchParams } from "react-router"

// Side sheets open from the URL (?sheet=<name>): they can be linked to, and
// Back closes them. Opening adds a history entry. Closing steps back to the
// entry before it when this hook made it; a sheet reached by a link has no
// such entry, so there the parameter is dropped in place.
export function useSheet(name: string) {
  const [sp, setSp] = useSearchParams()
  const navigate = useNavigate()
  const pushed = (useLocation().state as { sheet?: string } | null)?.sheet === name
  const open = sp.get("sheet") === name
  // A second close before the URL has caught up must not go back twice.
  const closing = useRef(false)
  useEffect(() => {
    closing.current = false
  }, [open])

  const show = useCallback(() => {
    setSp(
      (prev) => {
        const n = new URLSearchParams(prev)
        n.set("sheet", name)
        return n
      },
      { state: { sheet: name } },
    )
  }, [name, setSp])

  const hide = useCallback(() => {
    if (!open || closing.current) return
    closing.current = true
    if (pushed) {
      navigate(-1)
      return
    }
    setSp(
      (prev) => {
        const n = new URLSearchParams(prev)
        n.delete("sheet")
        return n
      },
      { replace: true },
    )
  }, [open, pushed, navigate, setSp])

  return { open, show, hide }
}
