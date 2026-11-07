import { useEffect } from "react"
import { createBrowserRouter, RouterProvider } from "react-router"
import { useQuery, useQueryClient } from "@tanstack/react-query"
import { Center, Spinner } from "@chakra-ui/react"
import { api, setUnauthorizedHandler, type Me } from "@/lib/api"
import { Layout } from "@/components/Layout"
import { LoginPage } from "@/pages/Login"
import { OverviewPage } from "@/pages/Overview"
import { VulnerabilitiesPage } from "@/pages/Vulnerabilities"
import { VulnDetailPage } from "@/pages/VulnDetail"
import { HostsPage } from "@/pages/Hosts"
import { HostDetailPage } from "@/pages/HostDetail"
import { ScansPage } from "@/pages/Scans"
import { LogsPage } from "@/pages/Logs"
import { SettingsPage } from "@/pages/Settings"
import { NotFoundPage } from "@/pages/NotFound"

const router = createBrowserRouter([
  {
    path: "/",
    element: <Layout />,
    children: [
      { index: true, element: <OverviewPage /> },
      { path: "vulnerabilities", element: <VulnerabilitiesPage /> },
      { path: "vulnerabilities/:id", element: <VulnDetailPage /> },
      { path: "hosts", element: <HostsPage /> },
      { path: "hosts/:id", element: <HostDetailPage /> },
      { path: "scans", element: <ScansPage /> },
      { path: "logs", element: <LogsPage /> },
      { path: "settings", element: <SettingsPage /> },
      { path: "*", element: <NotFoundPage /> },
    ],
  },
])

export function useMe() {
  return useQuery({ queryKey: ["me"], queryFn: () => api.get<Me>("/auth/me"), staleTime: 60_000 })
}

export function App() {
  const qc = useQueryClient()
  const me = useMe()

  useEffect(() => {
    setUnauthorizedHandler(() => qc.invalidateQueries({ queryKey: ["me"] }))
  }, [qc])

  if (me.isPending)
    return (
      <Center h="100vh">
        <Spinner size="lg" color="colorPalette.solid" />
      </Center>
    )
  if (me.data && !me.data.authenticated) return <LoginPage />
  return <RouterProvider router={router} />
}
