import { Link } from "react-router"
import { Badge, Box, HStack, Link as CLink, Stack, Table, Text } from "@chakra-ui/react"
import { LuActivity, LuCircleAlert, LuInfo, LuScrollText, LuTriangleAlert, LuBug } from "react-icons/lu"
import type { EventRow, List, ScanRow } from "@/lib/api"
import { ago, dateTime, duration, num } from "@/lib/format"
import { DataTable, Empty, Header, LoadingRows, Mono, SeverityCounts, SortHeader } from "@/components/common"
import { Tooltip } from "@/components/ui/tooltip"
import type { useParamsState } from "@/lib/useParamsState"

type PS = ReturnType<typeof useParamsState>

export function ScanTable({ data, loading, hideHost }: { data?: List<ScanRow>; loading?: boolean; hideHost?: boolean }) {
  const cols = hideHost ? 7 : 8
  return (
    <DataTable minW="5xl">
      <Table.Header>
        <Table.Row>
          <Header>Received</Header>
          {!hideHost && <Header>Host</Header>}
          <Header>Target</Header>
          <Header>Findings</Header>
          <Header textAlign="end">Total</Header>
          <Header>Change</Header>
          <Header>Source</Header>
          <Header>Scanner</Header>
        </Table.Row>
      </Table.Header>
      <Table.Body>
        {loading && <LoadingRows cols={cols} />}
        {data?.items.map((s) => (
          <Table.Row key={s.id}>
            <Table.Cell whiteSpace="nowrap">
              <Tooltip content={`Scanned ${dateTime(s.scanned_at)}, received ${dateTime(s.received_at)}`}>
                <Text>{ago(s.received_at)}</Text>
              </Tooltip>
              <Text textStyle="xs" color="fg.muted">
                took {duration(s.duration_ms)}
              </Text>
            </Table.Cell>
            {!hideHost && (
              <Table.Cell>
                <CLink asChild fontWeight="medium">
                  <Link to={`/hosts/${s.host_id}`}>{s.host_name}</Link>
                </CLink>
              </Table.Cell>
            )}
            <Table.Cell maxW="64">
              <Text truncate title={s.target_name}>
                {s.target_name}
              </Text>
              <Text textStyle="xs" color="fg.muted">
                {s.target_type}
              </Text>
            </Table.Cell>
            <Table.Cell>
              <SeverityCounts counts={s} />
            </Table.Cell>
            <Table.Cell textAlign="end" fontVariantNumeric="tabular-nums">
              {num(s.total)}
            </Table.Cell>
            <Table.Cell>
              <HStack gap="1">
                {s.new > 0 && (
                  <Badge colorPalette="yellow" variant="subtle" size="sm">
                    +{s.new} new
                  </Badge>
                )}
                {s.fixed > 0 && (
                  <Badge colorPalette="green" variant="subtle" size="sm">
                    −{s.fixed} fixed
                  </Badge>
                )}
                {!s.new && !s.fixed && (
                  <Text textStyle="xs" color="fg.subtle">
                    no change
                  </Text>
                )}
              </HStack>
            </Table.Cell>
            <Table.Cell>
              <Badge variant="outline" size="sm">
                {s.source}
              </Badge>
            </Table.Cell>
            <Table.Cell>
              <Stack gap="0">
                <Text textStyle="xs">grype {s.grype_version || "?"}</Text>
                <Text textStyle="xs" color="fg.muted">
                  DB {s.db_built ? ago(s.db_built) : "unknown"}
                </Text>
              </Stack>
            </Table.Cell>
          </Table.Row>
        ))}
        {data && data.items.length === 0 && (
          <Table.Row>
            <Table.Cell colSpan={cols}>
              <Empty icon={<LuActivity />} title="No scans yet" />
            </Table.Cell>
          </Table.Row>
        )}
      </Table.Body>
    </DataTable>
  )
}

const LEVEL: Record<string, { palette: string; icon: typeof LuInfo }> = {
  debug: { palette: "gray", icon: LuBug },
  info: { palette: "blue", icon: LuInfo },
  warn: { palette: "yellow", icon: LuTriangleAlert },
  error: { palette: "red", icon: LuCircleAlert },
}

export function LevelBadge({ level }: { level: string }) {
  const l = LEVEL[level] ?? LEVEL.info
  return (
    <Badge colorPalette={l.palette} variant="subtle" size="sm" gap="1" textTransform="uppercase" w="16" justifyContent="center">
      <l.icon />
      {level}
    </Badge>
  )
}

export function EventTable({ data, loading, hideHost, ps, onRun }: { data?: List<EventRow>; loading?: boolean; hideHost?: boolean; ps?: PS; onRun?: (run: string) => void }) {
  const cols = hideHost ? 4 : 5
  return (
    <DataTable minW="4xl">
      <Table.Header>
        <Table.Row>
          {ps ? <SortHeader label="Time" k="ts" sort={ps.sort} order={ps.order} onSort={ps.toggleSort} w="44" /> : <Header w="44">Time</Header>}
          <Header w="24">Level</Header>
          <Header w="24">Source</Header>
          {!hideHost && <Header w="40">Host</Header>}
          <Header>Message</Header>
        </Table.Row>
      </Table.Header>
      <Table.Body>
        {loading && <LoadingRows cols={cols} />}
        {data?.items.map((e) => (
          <Table.Row key={e.id} bg={e.level === "error" ? { _light: "red.50", _dark: "red.950/40" } : undefined}>
            <Table.Cell whiteSpace="nowrap" verticalAlign="top">
              <Mono>{dateTime(e.ts)}</Mono>
            </Table.Cell>
            <Table.Cell verticalAlign="top">
              <LevelBadge level={e.level} />
            </Table.Cell>
            <Table.Cell verticalAlign="top" color="fg.muted">
              {e.source}
            </Table.Cell>
            {!hideHost && (
              <Table.Cell verticalAlign="top">
                {e.host ? (
                  <Text fontWeight="medium" truncate maxW="40">
                    {e.host}
                  </Text>
                ) : (
                  <Text color="fg.subtle">—</Text>
                )}
              </Table.Cell>
            )}
            <Table.Cell verticalAlign="top">
              <Box>
                <Text textStyle="sm" whiteSpace="pre-wrap" wordBreak="break-word">
                  {e.message}
                </Text>
                {e.run_id && (
                  <Text
                    as={onRun ? "button" : "span"}
                    textStyle="xs"
                    color="fg.subtle"
                    fontFamily="mono"
                    onClick={onRun ? () => onRun(e.run_id) : undefined}
                    _hover={onRun ? { color: "fg", textDecoration: "underline" } : undefined}
                  >
                    run {e.run_id}
                  </Text>
                )}
              </Box>
            </Table.Cell>
          </Table.Row>
        ))}
        {data && data.items.length === 0 && (
          <Table.Row>
            <Table.Cell colSpan={cols}>
              <Empty icon={<LuScrollText />} title="No log entries" />
            </Table.Cell>
          </Table.Row>
        )}
      </Table.Body>
    </DataTable>
  )
}
