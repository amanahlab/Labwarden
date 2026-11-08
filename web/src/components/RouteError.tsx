import { useEffect, useState } from "react"
import { isRouteErrorResponse, useRouteError } from "react-router"
import { Button } from "@chakra-ui/react"
import { LuRefreshCw, LuTriangleAlert } from "react-icons/lu"
import { Empty } from "@/components/common"

const RELOADED = "labwarden-chunk-reload"

// A redeploy replaces the hashed page chunks; an open tab then fails to load them.
function isStaleChunk(err: unknown) {
  return err instanceof Error && /dynamically imported module|Importing a module script failed|Unable to preload/i.test(err.message)
}

export function RouteError() {
  const err = useRouteError()
  const stale = isStaleChunk(err)
  // Reload at most once per 10s so a genuinely missing chunk cannot loop.
  const [reloadedRecently] = useState(() => Date.now() - Number(sessionStorage.getItem(RELOADED) ?? 0) < 10_000)

  useEffect(() => {
    if (stale && !reloadedRecently) {
      sessionStorage.setItem(RELOADED, String(Date.now()))
      window.location.reload()
    }
  }, [stale, reloadedRecently])

  if (stale && !reloadedRecently) return null
  const message = isRouteErrorResponse(err) ? `${err.status} ${err.statusText}` : err instanceof Error ? err.message : String(err)
  return (
    <Empty
      icon={<LuTriangleAlert />}
      title={stale ? "LabWarden was updated" : "This page failed to load"}
      description={stale ? "Reload to get the new version." : message}
      action={
        <Button size="sm" variant="outline" onClick={() => window.location.reload()}>
          <LuRefreshCw /> Reload
        </Button>
      }
    />
  )
}
