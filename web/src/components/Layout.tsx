import { useEffect, useRef, useState, type ReactNode } from "react"
import { Link, NavLink, Outlet, useLocation, useMatches, useNavigate, useNavigation } from "react-router"
import { useQuery, useQueryClient } from "@tanstack/react-query"
import { Badge, Box, Button, CloseButton, Drawer, Flex, HStack, Heading, IconButton, Input, InputGroup, Kbd, Portal, Separator, Stack, chakra } from "@chakra-ui/react"
import {
  LuActivity,
  LuContainer,
  LuGauge,
  LuLogOut,
  LuMenu,
  LuPanelLeftClose,
  LuPanelLeftOpen,
  LuPlus,
  LuScrollText,
  LuSearch,
  LuServer,
  LuSettings,
  LuShieldAlert,
} from "react-icons/lu"
import { BrandLockup, BrandMark } from "@/components/Brand"
import { AddHostSheet } from "@/components/AddHostSheet"
import { ScannerStatus } from "@/components/ScannerStatus"
import { ColorModeButton } from "@/components/ui/color-mode"
import { Tooltip } from "@/components/ui/tooltip"
import { api, type Me, type Summary } from "@/lib/api"
import { num } from "@/lib/format"
import { useSheet } from "@/lib/useSheet"

type NavEntry = { to: string; label: string; icon: typeof LuGauge; end?: boolean }

// What needs attention, then how the data got here; Settings sits at the bottom.
const NAV_FINDINGS: NavEntry[] = [
  { to: "/", label: "Overview", icon: LuGauge, end: true },
  { to: "/vulnerabilities", label: "Vulnerabilities", icon: LuShieldAlert },
  { to: "/hosts", label: "Hosts", icon: LuServer },
  { to: "/images", label: "Images", icon: LuContainer },
]
const NAV_ACTIVITY: NavEntry[] = [
  { to: "/scans", label: "Scans", icon: LuActivity },
  { to: "/logs", label: "Logs", icon: LuScrollText },
]
const NAV_SETTINGS: NavEntry = { to: "/settings", label: "Settings", icon: LuSettings }

const COLLAPSED_KEY = "labwarden.sidebar-collapsed"

// Storage can be unavailable (private mode, blocked cookies): the rail then
// just does not persist.
function readCollapsed() {
  try {
    return localStorage.getItem(COLLAPSED_KEY) === "1"
  } catch {
    return false
  }
}

const NavItem = chakra(NavLink)

function NavRow({ entry, badge, collapsed, onNavigate }: { entry: NavEntry; badge?: ReactNode; collapsed?: boolean; onNavigate?: () => void }) {
  const item = (
    <NavItem
      to={entry.to}
      end={entry.end}
      onClick={onNavigate}
      aria-label={collapsed ? entry.label : undefined}
      position="relative"
      display="flex"
      alignItems="center"
      justifyContent={collapsed ? "center" : undefined}
      gap="3"
      h="9"
      px={collapsed ? "0" : "3"}
      rounded="l2"
      textStyle="sm"
      fontWeight="medium"
      color="fg.muted"
      _hover={{ bg: "bg.emphasized/60", color: "fg" }}
      // The current page is a raised chip: sheet colour, hairline, heavier
      // weight. It never relies on a colour change alone.
      css={{
        "&.active": {
          bg: "surface",
          color: "fg",
          fontWeight: "semibold",
          boxShadow: "0 0 0 1px {colors.border}",
        },
      }}
    >
      <entry.icon size={16} />
      {!collapsed && entry.label}
      {badge && (
        <Box ms={collapsed ? undefined : "auto"} position={collapsed ? "absolute" : undefined} top="-1" right="-1" lineHeight="1">
          {badge}
        </Box>
      )}
    </NavItem>
  )
  return collapsed ? (
    <Tooltip content={entry.label} positioning={{ placement: "right" }}>
      {item}
    </Tooltip>
  ) : (
    item
  )
}

function Sidebar({ collapsed, onToggle, onNavigate }: { collapsed?: boolean; onToggle?: () => void; onNavigate?: () => void }) {
  const qc = useQueryClient()
  const me = qc.getQueryData<Me>(["me"])
  const summary = useQuery({ queryKey: ["summary"], queryFn: () => api.get<Summary>("/summary") })
  const addHost = useSheet("add-host")
  const s = summary.data
  const badges: Record<string, ReactNode> = {
    "/vulnerabilities": s?.unique.critical ? (
      <Badge size="xs" colorPalette="red" variant="solid" aria-label={`${s.unique.critical} critical`}>
        {num(s.unique.critical)}
      </Badge>
    ) : null,
    "/hosts":
      s && s.stale_hosts + s.failing_hosts > 0 ? (
        <Badge size="xs" colorPalette="yellow" variant="subtle" aria-label={`${s.stale_hosts + s.failing_hosts} stale or failing`}>
          {s.stale_hosts + s.failing_hosts}
        </Badge>
      ) : null,
  }
  const rows = (entries: NavEntry[]) => entries.map((n) => <NavRow key={n.to} entry={n} badge={badges[n.to]} collapsed={collapsed} onNavigate={onNavigate} />)

  return (
    <>
      {/* The wordmark is artwork: never retype "LabWarden" in a font next to the symbol. */}
      <Flex align="center" gap="2" direction={collapsed ? "column" : "row"} ps={collapsed ? "0" : "2"} minH="9">
        {collapsed ? <BrandMark size={28} /> : <BrandLockup width={128} />}
        {!collapsed && me?.version && (
          <Badge size="xs" variant="outline" color="fg.muted">
            {me.version}
          </Badge>
        )}
        {onToggle && (
          <Tooltip content={collapsed ? "Expand sidebar" : "Collapse sidebar"} positioning={{ placement: "right" }}>
            <IconButton aria-label={collapsed ? "Expand sidebar" : "Collapse sidebar"} aria-expanded={!collapsed} variant="ghost" size="xs" color="fg.muted" ms={collapsed ? undefined : "auto"} onClick={onToggle}>
              {collapsed ? <LuPanelLeftOpen /> : <LuPanelLeftClose />}
            </IconButton>
          </Tooltip>
        )}
      </Flex>

      {collapsed ? (
        <Tooltip content="Add host" positioning={{ placement: "right" }}>
          <IconButton size="sm" aria-label="Add host" w="full" onClick={addHost.show}>
            <LuPlus />
          </IconButton>
        </Tooltip>
      ) : (
        <Button
          size="sm"
          w="full"
          onClick={() => {
            onNavigate?.()
            addHost.show()
          }}
        >
          <LuPlus /> Add host
        </Button>
      )}

      <Stack as="nav" aria-label="Main" gap="1">
        {rows(NAV_FINDINGS)}
        <Separator my="2" />
        {rows(NAV_ACTIVITY)}
      </Stack>

      <Stack gap="3" mt="auto">
        <ScannerStatus collapsed={collapsed} onNavigate={onNavigate} />
        <Stack as="nav" aria-label="Settings" gap="1">
          {rows([NAV_SETTINGS])}
        </Stack>
      </Stack>
    </>
  )
}

export function Layout() {
  const qc = useQueryClient()
  const navigate = useNavigate()
  const navigating = useNavigation().state === "loading"
  const { pathname } = useLocation()
  const [open, setOpen] = useState(false)
  const [collapsed, setCollapsed] = useState(readCollapsed)
  const [search, setSearch] = useState("")
  const me = qc.getQueryData<Me>(["me"])
  const main = useRef<HTMLDivElement>(null)
  // Each route names its section (App.tsx); the deepest match wins.
  const title = useMatches()
    .map((m) => (m.handle as { title?: string } | undefined)?.title)
    .filter(Boolean)
    .at(-1)

  // The sheet scrolls, not the window: start every page at its top.
  useEffect(() => {
    main.current?.scrollTo(0, 0)
  }, [pathname])

  function toggleCollapsed() {
    setCollapsed((c) => {
      try {
        localStorage.setItem(COLLAPSED_KEY, c ? "0" : "1")
      } catch {
        /* not persisted */
      }
      return !c
    })
  }

  async function logout() {
    await api.post("/auth/logout").catch(() => {})
    qc.clear()
    await qc.invalidateQueries({ queryKey: ["me"] })
    window.location.assign("/")
  }

  return (
    <Flex h="100dvh" overflow="hidden" bg="canvas">
      <Flex as="aside" display={{ base: "none", lg: "flex" }} direction="column" gap="4" w={collapsed ? "16" : "60"} flexShrink={0} py="3" px="3" overflowY="auto">
        <Sidebar collapsed={collapsed} onToggle={toggleCollapsed} />
      </Flex>

      <Drawer.Root open={open} onOpenChange={(e) => setOpen(e.open)} placement="start" size="xs">
        <Portal>
          <Drawer.Backdrop />
          <Drawer.Positioner>
            <Drawer.Content bg="canvas">
              <Drawer.Body display="flex" flexDirection="column" gap="4" py="3" px="3">
                <Sidebar onNavigate={() => setOpen(false)} />
              </Drawer.Body>
              <Drawer.CloseTrigger asChild>
                <CloseButton size="sm" />
              </Drawer.CloseTrigger>
            </Drawer.Content>
          </Drawer.Positioner>
        </Portal>
      </Drawer.Root>

      <Flex direction="column" flex="1" minW="0">
        <Flex as="header" h="14" flexShrink={0} ps={{ base: "2", lg: "3" }} pe={{ base: "2", lg: "3" }} align="center" gap="2">
          <IconButton aria-label="Open menu" variant="ghost" size="sm" display={{ lg: "none" }} onClick={() => setOpen(true)}>
            <LuMenu />
          </IconButton>
          <Heading as="h1" size="lg" letterSpacing="-0.01em" truncate ps={{ lg: "2" }}>
            {title}
          </Heading>
          <HStack ms="auto" gap="1">
            <chakra.form
              display={{ base: "none", md: "block" }}
              w="80"
              me="1"
              role="search"
              onSubmit={(e) => {
                e.preventDefault()
                const q = search.trim()
                if (q) navigate(`/vulnerabilities?q=${encodeURIComponent(q)}`)
                setSearch("")
              }}
            >
              <InputGroup startElement={<LuSearch />} endElement={<Kbd size="sm">↵</Kbd>}>
                <Input size="sm" bg="surface" value={search} onChange={(e) => setSearch(e.currentTarget.value)} placeholder="Search CVE, package, host…" aria-label="Search vulnerabilities" />
              </InputGroup>
            </chakra.form>
            {/* No room for the field on a phone: the Vulnerabilities page starts with its own search box. */}
            <IconButton asChild aria-label="Search vulnerabilities" variant="ghost" size="sm" display={{ md: "none" }}>
              <Link to="/vulnerabilities">
                <LuSearch />
              </Link>
            </IconButton>
            <ColorModeButton />
            {me?.auth_enabled && (
              <Tooltip content="Sign out">
                <IconButton aria-label="Sign out" variant="ghost" size="sm" onClick={logout}>
                  <LuLogOut />
                </IconButton>
              </Tooltip>
            )}
          </HStack>
        </Flex>
        {/* The content sheet: the one raised surface on the canvas, and the scroll container. */}
        <Box
          as="main"
          ref={main}
          flex="1"
          minH="0"
          overflowY="auto"
          bg="surface"
          borderWidth="1px"
          rounded="sheet"
          ms={{ base: "2", lg: "0" }}
          me={{ base: "2", lg: "3" }}
          mb={{ base: "2", lg: "3" }}
          aria-busy={navigating}
        >
          <Box px={{ base: "3", md: "6" }} py={{ base: "4", md: "6" }} maxW="1600px" mx="auto" opacity={navigating ? 0.6 : 1} transition="opacity 0.15s">
            <Outlet />
          </Box>
        </Box>
      </Flex>
      <AddHostSheet />
    </Flex>
  )
}
