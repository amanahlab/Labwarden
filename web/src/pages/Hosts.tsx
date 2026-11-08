import { useMemo } from "react"
import { Link } from "react-router"
import { keepPreviousData, useQuery } from "@tanstack/react-query"
import { Badge, Card, Collapsible, Flex, HStack, Link as CLink, SegmentGroup, Stack, Table, Text } from "@chakra-ui/react"
import { LuChevronDown, LuServer } from "react-icons/lu"
import { api, type Counts, type GroupRow, type HostRow, type List } from "@/lib/api"
import { ago, dateTime, interval, num } from "@/lib/format"
import { useParamsState } from "@/lib/useParamsState"
import {
  DataTable,
  Empty,
  ErrorBox,
  FilterBar,
  Header,
  HostStatusBadge,
  LoadingRows,
  PageHeader,
  Pager,
  SearchInput,
  Select,
  SeverityCounts,
  SortHeader,
} from "@/components/common"
import { ClearFilters } from "@/components/filters"
import { Tooltip } from "@/components/ui/tooltip"
import { KindTag } from "@/components/KindTag"
import { KIND_LABEL } from "@/lib/options"

const DEFAULTS = { view: "list", sort: "score", order: "desc", size: "25" }
const FILTER_KEYS = ["q", "group", "kind", "status"]

export function HostsPage() {
  const ps = useParamsState(DEFAULTS)
  const view = ps.get("view")
  const grouped = view !== "list"
  const filters = { q: ps.get("q"), group: ps.get("group"), kind: ps.get("kind"), status: ps.get("status") }
  const params = grouped
    ? { ...filters, page: 1, size: 500, sort: ps.sort, order: ps.order }
    : { ...filters, page: ps.page, size: ps.size, sort: ps.sort, order: ps.order }
  const hosts = useQuery({
    queryKey: ["hosts", params],
    queryFn: () => api.get<List<HostRow>>("/hosts", params),
    placeholderData: keepPreviousData,
  })
  const groups = useQuery({ queryKey: ["groups"], queryFn: () => api.get<GroupRow[]>("/groups") })
  const hasFilters = FILTER_KEYS.some((k) => ps.sp.has(k))

  return (
    <>
      <PageHeader title="Hosts" description="Machines and images reporting to LabWarden, with their latest scan results." />
      <Stack gap="3" mb="4">
        <HStack gap="2" wrap="wrap">
          <SegmentGroup.Root size="sm" value={view} onValueChange={(e) => ps.set({ view: e.value })} bg="surface">
            <SegmentGroup.Indicator />
            <SegmentGroup.Items
              items={[
                { value: "list", label: "List" },
                { value: "group", label: "By group" },
                { value: "kind", label: "By kind" },
              ]}
            />
          </SegmentGroup.Root>
          <SearchInput value={filters.q} onChange={(v) => ps.set({ q: v })} placeholder="Host name, IP, OS…" />
        </HStack>
        <FilterBar>
          <Select label="Group" value={filters.group} onChange={(v) => ps.set({ group: v })} options={(groups.data ?? []).map((g) => g.name)} placeholder="All groups" />
          <Select label="Kind" value={filters.kind} onChange={(v) => ps.set({ kind: v })} options={Object.entries(KIND_LABEL)} placeholder="All kinds" />
          <Select
            label="Health"
            value={filters.status}
            onChange={(v) => ps.set({ status: v })}
            options={[
              ["ok", "Healthy"],
              ["stale", "Stale"],
              ["failing", "Failing"],
            ]}
            placeholder="Any health"
          />
          <ClearFilters show={hasFilters} onClear={() => ps.set(Object.fromEntries(FILTER_KEYS.map((k) => [k, null])))} />
        </FilterBar>
      </Stack>

      {hosts.error && <ErrorBox error={hosts.error} />}
      {grouped ? (
        <GroupedHosts ps={ps} hosts={hosts.data?.items} by={view === "kind" ? "kind" : "group"} />
      ) : (
        <>
          <HostTable ps={ps} hosts={hosts.data?.items} loading={hosts.isPending} />
          <Pager total={hosts.data?.total ?? 0} page={ps.page} size={ps.size} onPage={(p) => ps.set({ page: p })} onSize={(s) => ps.set({ size: s })} />
        </>
      )}
    </>
  )
}

type PS = ReturnType<typeof useParamsState>

function HostTable({ ps, hosts, loading, compact }: { ps: PS; hosts?: HostRow[]; loading?: boolean; compact?: boolean }) {
  const sh = { sort: ps.sort, order: ps.order, onSort: ps.toggleSort }
  return (
    <DataTable minW="5xl">
      <Table.Header>
        <Table.Row>
          <SortHeader label="Host" k="name" {...sh} />
          <SortHeader label="Kind" k="kind" {...sh} />
          {!compact && <SortHeader label="Group" k="group" {...sh} />}
          <SortHeader label="Health" k="status" {...sh} />
          <SortHeader label="Active findings" k="score" {...sh} />
          <SortHeader label="Total" k="total" textAlign="end" {...sh} />
          <SortHeader label="Targets" k="targets" textAlign="end" {...sh} />
          <Header>Interval</Header>
          <SortHeader label="Last seen" k="last_seen" {...sh} />
        </Table.Row>
      </Table.Header>
      <Table.Body>
        {loading && <LoadingRows cols={compact ? 8 : 9} />}
        {hosts?.map((h) => (
          <Table.Row key={h.id}>
            <Table.Cell>
              <Stack gap="0">
                <CLink asChild fontWeight="semibold">
                  <Link to={`/hosts/${h.id}`}>{h.name}</Link>
                </CLink>
                <Text textStyle="xs" color="fg.muted" truncate maxW="60">
                  {[h.os, h.ip].filter(Boolean).join(" · ") || "—"}
                </Text>
              </Stack>
            </Table.Cell>
            <Table.Cell>
              <KindTag kind={h.kind} />
            </Table.Cell>
            {!compact && (
              <Table.Cell>
                <Badge variant="outline" size="sm">
                  {h.group}
                </Badge>
              </Table.Cell>
            )}
            <Table.Cell>
              <HostStatusBadge status={h.status} />
            </Table.Cell>
            <Table.Cell>
              <SeverityCounts counts={h} />
            </Table.Cell>
            <Table.Cell textAlign="end" fontVariantNumeric="tabular-nums">
              {num(h.total)}
            </Table.Cell>
            <Table.Cell textAlign="end" fontVariantNumeric="tabular-nums">
              {num(h.targets)}
            </Table.Cell>
            <Table.Cell color="fg.muted">{interval(h.interval_sec)}</Table.Cell>
            <Table.Cell color="fg.muted" whiteSpace="nowrap">
              <Tooltip content={dateTime(h.last_seen)}>
                <span>{ago(h.last_seen)}</span>
              </Tooltip>
            </Table.Cell>
          </Table.Row>
        ))}
        {hosts && hosts.length === 0 && (
          <Table.Row>
            <Table.Cell colSpan={9}>
              <Empty icon={<LuServer />} title="No hosts match" description="Install an agent from Settings, or loosen the filters." />
            </Table.Cell>
          </Table.Row>
        )}
      </Table.Body>
    </DataTable>
  )
}

const ZERO: Counts = { critical: 0, high: 0, medium: 0, low: 0, negligible: 0, unknown: 0, total: 0, fixable: 0 }

function GroupedHosts({ ps, hosts, by }: { ps: PS; hosts?: HostRow[]; by: "group" | "kind" }) {
  const sections = useMemo(() => {
    const m = new Map<string, { hosts: HostRow[]; counts: Counts; unhealthy: number }>()
    for (const h of hosts ?? []) {
      const key = by === "kind" ? h.kind : h.group
      const s = m.get(key) ?? { hosts: [], counts: { ...ZERO }, unhealthy: 0 }
      s.hosts.push(h)
      for (const k of Object.keys(ZERO) as (keyof Counts)[]) s.counts[k] += h[k]
      if (h.status !== "ok") s.unhealthy++
      m.set(key, s)
    }
    return [...m.entries()].sort((a, b) => b[1].counts.critical * 100 + b[1].counts.high - (a[1].counts.critical * 100 + a[1].counts.high) || a[0].localeCompare(b[0]))
  }, [hosts, by])

  if (!hosts) return <HostTable ps={ps} loading compact={by === "group"} />
  if (sections.length === 0) return <Empty icon={<LuServer />} title="No hosts match" />
  return (
    <Stack gap="4">
      {sections.map(([name, s]) => (
        <Collapsible.Root key={name} defaultOpen>
          <Card.Root variant="outline" bg="surface">
            <Collapsible.Trigger asChild>
              <Flex as="button" w="full" px="4" py="3" align="center" gap="4" cursor="pointer" textAlign="start" wrap="wrap" _hover={{ bg: "bg.muted" }} roundedTop="l3">
                <Collapsible.Indicator transition="transform 0.2s" _open={{ transform: "rotate(180deg)" }}>
                  <LuChevronDown />
                </Collapsible.Indicator>
                <Stack gap="0" minW="40">
                  <Text fontWeight="semibold">{by === "kind" ? (KIND_LABEL[name] ?? name) : name}</Text>
                  <Text textStyle="xs" color="fg.muted">
                    {s.hosts.length} host{s.hosts.length === 1 ? "" : "s"}
                    {s.unhealthy > 0 && ` · ${s.unhealthy} need attention`}
                  </Text>
                </Stack>
                <SeverityCounts counts={s.counts} />
                <Text ms="auto" textStyle="sm" color="fg.muted" fontVariantNumeric="tabular-nums">
                  {num(s.counts.total)} findings
                </Text>
              </Flex>
            </Collapsible.Trigger>
            <Collapsible.Content>
              <Card.Body p="0" borderTopWidth="1px">
                <HostTable ps={ps} hosts={s.hosts} compact={by === "group"} />
              </Card.Body>
            </Collapsible.Content>
          </Card.Root>
        </Collapsible.Root>
      ))}
    </Stack>
  )
}
