import { useState, type ReactNode } from "react"
import { NavLink, Outlet, useNavigate, useNavigation } from "react-router"
import { useQuery, useQueryClient } from "@tanstack/react-query"
import { Box, Badge, Drawer, Flex, HStack, IconButton, Portal, Stack, Text, CloseButton, chakra, Input, InputGroup, Kbd } from "@chakra-ui/react"
import {
  LuActivity,
  LuGauge,
  LuLogOut,
  LuMenu,
  LuScrollText,
  LuServer,
  LuSettings,
  LuShieldAlert,
  LuSearch,
} from "react-icons/lu"
import { BrandLockup } from "@/components/Brand"
import { ColorModeButton } from "@/components/ui/color-mode"
import { Tooltip } from "@/components/ui/tooltip"
import { api, type Me, type Summary } from "@/lib/api"
import { num } from "@/lib/format"

const NAV = [
  { to: "/", label: "Overview", icon: LuGauge, end: true },
  { to: "/vulnerabilities", label: "Vulnerabilities", icon: LuShieldAlert },
  { to: "/hosts", label: "Hosts", icon: LuServer },
  { to: "/scans", label: "Scans", icon: LuActivity },
  { to: "/logs", label: "Logs", icon: LuScrollText },
  { to: "/settings", label: "Settings", icon: LuSettings },
]

const NavItem = chakra(NavLink)

function Nav({ onNavigate }: { onNavigate?: () => void }) {
  const summary = useQuery({ queryKey: ["summary"], queryFn: () => api.get<Summary>("/summary") })
  const badges: Record<string, ReactNode> = {
    "/vulnerabilities": summary.data?.unique.critical ? (
      <Badge size="xs" colorPalette="red" variant="solid" ms="auto">
        {num(summary.data.unique.critical)}
      </Badge>
    ) : null,
    "/hosts":
      summary.data && summary.data.stale_hosts + summary.data.failing_hosts > 0 ? (
        <Badge size="xs" colorPalette="yellow" variant="subtle" ms="auto">
          {summary.data.stale_hosts + summary.data.failing_hosts}
        </Badge>
      ) : null,
  }
  return (
    <Stack gap="0.5" as="nav" aria-label="Main">
      {NAV.map((n) => (
        <NavItem
          key={n.to}
          to={n.to}
          end={n.end}
          onClick={onNavigate}
          display="flex"
          alignItems="center"
          gap="3"
          px="3"
          py="2"
          rounded="md"
          textStyle="sm"
          fontWeight="medium"
          color="fg.muted"
          _hover={{ bg: "bg.muted", color: "fg" }}
          // On the neutral palette the hover gray is close to any active fill,
          // so the active item also gets a heavier weight and an Ink edge bar.
          css={{
            "&.active": {
              bg: "colorPalette.muted",
              color: "fg",
              fontWeight: "semibold",
              boxShadow: "inset 3px 0 0 {colors.colorPalette.solid}",
            },
          }}
        >
          <n.icon size={16} />
          {n.label}
          {badges[n.to]}
        </NavItem>
      ))}
    </Stack>
  )
}

// The wordmark is artwork: never retype "LabWarden" in a font next to the symbol.
function Brand() {
  return (
    <Box px="3" mb="6">
      <BrandLockup />
    </Box>
  )
}

export function Layout() {
  const qc = useQueryClient()
  const navigate = useNavigate()
  const navigating = useNavigation().state === "loading"
  const [open, setOpen] = useState(false)
  const [search, setSearch] = useState("")
  const me = qc.getQueryData<Me>(["me"])

  async function logout() {
    await api.post("/auth/logout").catch(() => {})
    qc.clear()
    await qc.invalidateQueries({ queryKey: ["me"] })
    window.location.assign("/")
  }

  return (
    <Flex minH="100vh">
      <Box
        as="aside"
        display={{ base: "none", lg: "flex" }}
        flexDirection="column"
        w="60"
        flexShrink={0}
        borderEndWidth="1px"
        bg="surface"
        py="5"
        px="3"
        position="sticky"
        top="0"
        h="100vh"
      >
        <Brand />
        <Nav />
        <Box mt="auto" px="3">
          <Text textStyle="xs" color="fg.subtle">
            LabWarden {me?.version ?? ""}
          </Text>
        </Box>
      </Box>

      <Drawer.Root open={open} onOpenChange={(e) => setOpen(e.open)} placement="start" size="xs">
        <Portal>
          <Drawer.Backdrop />
          <Drawer.Positioner>
            <Drawer.Content>
              <Drawer.Body pt="5">
                <Brand />
                <Nav onNavigate={() => setOpen(false)} />
              </Drawer.Body>
              <Drawer.CloseTrigger asChild>
                <CloseButton size="sm" />
              </Drawer.CloseTrigger>
            </Drawer.Content>
          </Drawer.Positioner>
        </Portal>
      </Drawer.Root>

      <Flex direction="column" flex="1" minW="0">
        <Flex
          as="header"
          h="14"
          px={{ base: "3", md: "6" }}
          align="center"
          gap="3"
          borderBottomWidth="1px"
          bg="surface"
          position="sticky"
          top="0"
          zIndex="docked"
        >
          <IconButton aria-label="Open menu" variant="ghost" size="sm" display={{ lg: "none" }} onClick={() => setOpen(true)}>
            <LuMenu />
          </IconButton>
          <chakra.form
            w={{ base: "full", md: "96" }}
            role="search"
            onSubmit={(e) => {
              e.preventDefault()
              const q = search.trim()
              if (q) navigate(`/vulnerabilities?q=${encodeURIComponent(q)}`)
              setSearch("")
            }}
          >
            <InputGroup startElement={<LuSearch />} endElement={<Kbd size="sm">↵</Kbd>}>
              <Input size="sm" value={search} onChange={(e) => setSearch(e.currentTarget.value)} placeholder="Search CVE, package, host…" aria-label="Search vulnerabilities" />
            </InputGroup>
          </chakra.form>
          <HStack ms="auto" gap="1">
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
        <Box as="main" flex="1" px={{ base: "3", md: "6", xl: "8" }} py="6" maxW="1600px" w="full" mx="auto" aria-busy={navigating}>
          <Box opacity={navigating ? 0.6 : 1} transition="opacity 0.15s">
            <Outlet />
          </Box>
        </Box>
      </Flex>
    </Flex>
  )
}
