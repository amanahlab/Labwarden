import { useEffect } from "react"
import { createBrowserRouter, RouterProvider } from "react-router"
import { useQuery, useQueryClient } from "@tanstack/react-query"
import { Center, Spinner } from "@chakra-ui/react"
import { api, setUnauthorizedHandler, type Me } from "@/lib/api"
import { Layout } from "@/components/Layout"
import { LoginPage } from "@/pages/Login"

const Loading = () => (
  <Center h="100vh">
    <Spinner size="lg" color="colorPalette.solid" />
  </Center>
)

// Each page is its own chunk; the router loads it on first navigation.
const router = createBrowserRouter([
  {
    path: "/",
    element: <Layout />,
    HydrateFallback: Loading,
    children: [
      { index: true, lazy: async () => ({ Component: (await import("@/pages/Overview")).OverviewPage }) },
      { path: "vulnerabilities", lazy: async () => ({ Component: (await import("@/pages/Vulnerabilities")).VulnerabilitiesPage }) },
      { path: "vulnerabilities/:id", lazy: async () => ({ Component: (await import("@/pages/VulnDetail")).VulnDetailPage }) },
      { path: "hosts", lazy: async () => ({ Component: (await import("@/pages/Hosts")).HostsPage }) },
      { path: "hosts/:id", lazy: async () => ({ Component: (await import("@/pages/HostDetail")).HostDetailPage }) },
      { path: "scans", lazy: async () => ({ Component: (await import("@/pages/Scans")).ScansPage }) },
      { path: "logs", lazy: async () => ({ Component: (await import("@/pages/Logs")).LogsPage }) },
      { path: "settings", lazy: async () => ({ Component: (await import("@/pages/Settings")).SettingsPage }) },
      { path: "*", lazy: async () => ({ Component: (await import("@/pages/NotFound")).NotFoundPage }) },
    ],
  },
])

function useMe() {
  return useQuery({ queryKey: ["me"], queryFn: () => api.get<Me>("/auth/me"), staleTime: 60_000 })
}

export function App() {
  const qc = useQueryClient()
  const me = useMe()

  useEffect(() => {
    setUnauthorizedHandler(() => qc.invalidateQueries({ queryKey: ["me"] }))
  }, [qc])

  if (me.isPending) return <Loading />
  if (me.data && !me.data.authenticated) return <LoginPage />
  return <RouterProvider router={router} />
}
