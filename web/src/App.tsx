import { useEffect } from "react"
import { createBrowserRouter, RouterProvider } from "react-router"
import { useQuery, useQueryClient } from "@tanstack/react-query"
import { Center, Spinner } from "@chakra-ui/react"
import { api, setUnauthorizedHandler, type Me } from "@/lib/api"
import { Layout } from "@/components/Layout"
import { LoginPage } from "@/pages/Login"
import { RouteError } from "@/components/RouteError"

const Loading = () => (
  <Center h="100vh">
    <Spinner size="lg" color="colorPalette.solid" />
  </Center>
)

// Each page is its own chunk; the router loads it on first navigation.
// handle.title is the section name the layout shows in the top bar.
const router = createBrowserRouter([
  {
    path: "/",
    element: <Layout />,
    HydrateFallback: Loading,
    children: [
      {
        // Pathless wrapper: page errors render inside the layout.
        errorElement: <RouteError />,
        children: [
      { index: true, handle: { title: "Overview" }, lazy: async () => ({ Component: (await import("@/pages/Overview")).OverviewPage }) },
      { path: "vulnerabilities", handle: { title: "Vulnerabilities" }, lazy: async () => ({ Component: (await import("@/pages/Vulnerabilities")).VulnerabilitiesPage }) },
      { path: "vulnerabilities/:id", handle: { title: "Vulnerabilities" }, lazy: async () => ({ Component: (await import("@/pages/VulnDetail")).VulnDetailPage }) },
      { path: "hosts", handle: { title: "Hosts" }, lazy: async () => ({ Component: (await import("@/pages/Hosts")).HostsPage }) },
      { path: "hosts/:id", handle: { title: "Hosts" }, lazy: async () => ({ Component: (await import("@/pages/HostDetail")).HostDetailPage }) },
      { path: "scans", handle: { title: "Scans" }, lazy: async () => ({ Component: (await import("@/pages/Scans")).ScansPage }) },
      { path: "logs", handle: { title: "Logs" }, lazy: async () => ({ Component: (await import("@/pages/Logs")).LogsPage }) },
      { path: "settings", handle: { title: "Settings" }, lazy: async () => ({ Component: (await import("@/pages/Settings")).SettingsPage }) },
      { path: "*", handle: { title: "Not found" }, lazy: async () => ({ Component: (await import("@/pages/NotFound")).NotFoundPage }) },
        ],
      },
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
