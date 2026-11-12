import { Link } from "react-router"
import { useQuery } from "@tanstack/react-query"
import { Box, Flex, HStack, Stack, Text } from "@chakra-ui/react"
import { LuDatabase } from "react-icons/lu"
import { Tooltip } from "@/components/ui/tooltip"
import { api, type SystemInfo } from "@/lib/api"
import { ago } from "@/lib/format"

type Level = "ok" | "busy" | "warn" | "error"

// The dot repeats what the headline says; it is never the only signal.
const DOT: Record<Level, string> = { ok: "green.solid", busy: "blue.solid", warn: "yellow.solid", error: "red.solid" }

function read(s: SystemInfo): { level: Level; headline: string } {
  const pending = s.queue.running + s.queue.queued
  if (!s.scanner.available) return { level: "error", headline: "Grype not found" }
  if (s.scanner.db_error) return { level: "error", headline: "DB update failed" }
  if (!s.scanner.db_built) return { level: "warn", headline: "No vulnerability DB yet" }
  if (pending > 0) return { level: "busy", headline: `Matching, ${pending} in queue` }
  if (s.queue.failed_24h > 0) return { level: "warn", headline: `${s.queue.failed_24h} failed in 24 h` }
  return { level: "ok", headline: "Up to date" }
}

// Sidebar card: is the central scanner healthy and how old is its Grype DB.
// GET /system reads cached state, so a slow poll costs the server nothing.
export function ScannerStatus({ collapsed, onNavigate }: { collapsed?: boolean; onNavigate?: () => void }) {
  const q = useQuery({ queryKey: ["system"], queryFn: () => api.get<SystemInfo>("/system"), refetchInterval: 60_000 })
  const s = q.data
  if (!s) return null
  const { level, headline } = read(s)
  const dot = <Box w="2" h="2" rounded="full" bg={DOT[level]} flexShrink={0} />

  if (collapsed)
    return (
      <Tooltip content={`Scanner: ${headline}`} positioning={{ placement: "right" }}>
        <Flex asChild align="center" justify="center" h="9" rounded="l2" color="fg.muted" position="relative" _hover={{ bg: "bg.emphasized/60", color: "fg" }}>
          <Link to="/settings" aria-label={`Scanner: ${headline}`}>
            <LuDatabase size={16} />
            <Box position="absolute" top="1.5" right="3">
              {dot}
            </Box>
          </Link>
        </Flex>
      </Tooltip>
    )

  return (
    <Stack asChild gap="1.5" p="3" rounded="l3" bg="surface" borderWidth="1px" textStyle="xs" _hover={{ borderColor: "border.emphasized" }}>
      <Link to="/settings" onClick={onNavigate} aria-label={`Scanner: ${headline}. Open settings`}>
        <HStack gap="2">
          {dot}
          <Text fontWeight="semibold" textStyle="sm">
            Scanner
          </Text>
        </HStack>
        <Text color={level === "error" ? "fg.error" : "fg"}>{headline}</Text>
        <Text color="fg.muted">
          {s.scanner.db_built ? `Grype DB built ${ago(s.scanner.db_built)}` : "Grype DB not downloaded"}
          {s.queue.next_db_update && ` · next check ${ago(s.queue.next_db_update)}`}
        </Text>
      </Link>
    </Stack>
  )
}
