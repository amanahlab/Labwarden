import { Link } from "react-router"
import { keepPreviousData, useQuery } from "@tanstack/react-query"
import { Badge, Button, HStack, IconButton, Link as CLink, SegmentGroup, Stack, Table, Text } from "@chakra-ui/react"
import { LuDownload, LuServer, LuShieldCheck } from "react-icons/lu"
import { api, qs, type FindingRow, type GroupRow, type HostVulnRow, type List, type LocationRow, type Summary, type VulnRow } from "@/lib/api"
import { ago, num, pct, splitList } from "@/lib/format"
import { useParamsState } from "@/lib/useParamsState"
import {
  DataTable,
  Empty,
  ErrorBox,
  FilterBar,
  FixBadge,
  Header,
  KevBadge,
  LoadingRows,
  Mono,
  PageHeader,
  Pager,
  SearchInput,
  Select,
  SeverityBadge,
  SeverityCounts,
  SortHeader,
  TriageBadge,
} from "@/components/common"
import { ClearFilters, KevToggle, SeverityChips } from "@/components/filters"
import { KindTag } from "@/components/KindTag"
import { FIX_OPTIONS, STATUS_OPTIONS } from "@/lib/options"

const DEFAULTS = { view: "vulns", sort: "severity", order: "desc", status: "active", size: "25" }
const FILTER_KEYS = ["q", "severity", "fix", "kev", "group", "pkg_type", "status", "host_id", "target_id", "location"]

export function VulnerabilitiesPage() {
  const ps = useParamsState(DEFAULTS)
  const view = ps.get("view")
  const filters = {
    q: ps.get("q"),
    severity: ps.getList("severity"),
    fix: ps.get("fix"),
    kev: ps.get("kev") === "true",
    group: ps.get("group"),
    pkg_type: ps.get("pkg_type"),
    status: ps.get("status"),
    host_id: ps.get("host_id"),
    target_id: ps.get("target_id"),
    location: ps.get("location"),
  }
  const params = { ...filters, page: ps.page, size: ps.size, sort: ps.sort, order: ps.order }

  const groups = useQuery({ queryKey: ["groups"], queryFn: () => api.get<GroupRow[]>("/groups") })
  const summary = useQuery({ queryKey: ["summary"], queryFn: () => api.get<Summary>("/summary") })
  const vulns = useQuery({
    queryKey: ["vulns", params],
    queryFn: () => api.get<List<VulnRow>>("/vulnerabilities", params),
    enabled: view === "vulns",
    placeholderData: keepPreviousData,
  })
  const findings = useQuery({
    queryKey: ["findings", params],
    queryFn: () => api.get<List<FindingRow>>("/findings", params),
    enabled: view === "findings",
    placeholderData: keepPreviousData,
  })
  const hosts = useQuery({
    queryKey: ["vuln-hosts", params],
    queryFn: () => api.get<List<HostVulnRow>>("/findings/by-host", params),
    enabled: view === "hosts",
    placeholderData: keepPreviousData,
  })
  const locations = useQuery({
    queryKey: ["vuln-locations", params],
    queryFn: () => api.get<List<LocationRow>>("/findings/by-location", params),
    enabled: view === "locations",
    placeholderData: keepPreviousData,
  })
  const q = view === "findings" ? findings : view === "hosts" ? hosts : view === "locations" ? locations : vulns
  const hasFilters = FILTER_KEYS.some((k) => ps.sp.has(k))

  return (
    <>
      <PageHeader
        title="Vulnerabilities"
        description="Every vulnerability Grype reported in the latest scan of each target."
        actions={
          <Button asChild size="sm" variant="outline" bg="surface">
            <a href={`/api/v1/vulnerabilities/export.csv${qs({ ...filters, sort: ps.sort, order: ps.order })}`}>
              <LuDownload /> Export CSV
            </a>
          </Button>
        }
      />

      <Stack gap="3" mb="4">
        <HStack gap="2" wrap="wrap">
          <SegmentGroup.Root size="sm" value={view} onValueChange={(e) => ps.set({ view: e.value, sort: null, order: null })} bg="surface">
            <SegmentGroup.Indicator />
            <SegmentGroup.Items
              items={[
                { value: "vulns", label: "By vulnerability" },
                { value: "findings", label: "By package instance" },
                { value: "hosts", label: "By host" },
                { value: "locations", label: "By location" },
              ]}
            />
          </SegmentGroup.Root>
          <SearchInput value={filters.q} onChange={(v) => ps.set({ q: v })} placeholder="CVE / GHSA, package, host, description…" w={{ base: "full", md: "96" }} />
        </HStack>
        <FilterBar>
          <SeverityChips value={filters.severity} onChange={(v) => ps.set({ severity: v })} />
          <KevToggle value={filters.kev} onChange={(v) => ps.set({ kev: v ? "true" : null })} />
          <Select label="Fix state" value={filters.fix} onChange={(v) => ps.set({ fix: v })} options={FIX_OPTIONS} placeholder="Any fix state" w="36" />
          <Select label="Triage status" value={filters.status} onChange={(v) => ps.set({ status: v })} options={STATUS_OPTIONS} w="52" />
          <Select label="Group" value={filters.group} onChange={(v) => ps.set({ group: v })} options={(groups.data ?? []).map((g) => g.name)} placeholder="All groups" w="36" />
          <Select
            label="Ecosystem"
            value={filters.pkg_type}
            onChange={(v) => ps.set({ pkg_type: v })}
            options={(summary.data?.by_pkg_type ?? []).map((t) => t.name)}
            placeholder="All ecosystems"
            w="36"
          />
          {filters.host_id && (
            <Button size="xs" variant="subtle" onClick={() => ps.set({ host_id: null })}>
              Host #{filters.host_id} ✕
            </Button>
          )}
          {(filters.location || filters.target_id) && (
            <Button size="xs" variant="subtle" maxW="sm" title={filters.location} onClick={() => ps.set({ location: null, target_id: null })}>
              <Text truncate>{filters.location ? `Path ${filters.location}` : `Target #${filters.target_id}`}</Text> ✕
            </Button>
          )}
          <ClearFilters show={hasFilters} onClear={() => ps.set(Object.fromEntries(FILTER_KEYS.map((k) => [k, null])))} />
        </FilterBar>
      </Stack>

      {q.error && <ErrorBox error={q.error} />}
      {view === "findings" ? (
        <FindingTable ps={ps} data={findings.data} loading={findings.isPending} />
      ) : view === "hosts" ? (
        <HostVulnTable ps={ps} data={hosts.data} loading={hosts.isPending} />
      ) : view === "locations" ? (
        <LocationTable ps={ps} data={locations.data} loading={locations.isPending} />
      ) : (
        <VulnTable ps={ps} data={vulns.data} loading={vulns.isPending} />
      )}
      <Pager total={q.data?.total ?? 0} page={ps.page} size={ps.size} onPage={(p) => ps.set({ page: p })} onSize={(s) => ps.set({ size: s })} />
    </>
  )
}

type PS = ReturnType<typeof useParamsState>

// drill links to the package-instance view narrowed by patch, keeping the
// other filters; sort and page reset because the columns differ.
function drill(ps: PS, patch: Record<string, string | number>) {
  const n = new URLSearchParams(ps.sp)
  for (const k of ["sort", "order", "page", "host_id", "target_id", "location"]) n.delete(k)
  n.set("view", "findings")
  for (const [k, v] of Object.entries(patch)) n.set(k, String(v))
  return `?${n}`
}

function HostVulnTable({ ps, data, loading }: { ps: PS; data?: List<HostVulnRow>; loading: boolean }) {
  const sh = { sort: ps.sort, order: ps.order, onSort: ps.toggleSort }
  return (
    <DataTable minW="5xl">
      <Table.Header>
        <Table.Row>
          <SortHeader label="Host" k="host" {...sh} />
          <Header>Kind</Header>
          <SortHeader label="Group" k="group" {...sh} />
          <SortHeader label="Severity" k="severity" {...sh} />
          <SortHeader label="Vulns" k="vulns" textAlign="end" {...sh} />
          <SortHeader label="Instances" k="total" textAlign="end" {...sh} />
          <Header textAlign="end">KEV</Header>
          <SortHeader label="Max risk" k="risk" textAlign="end" {...sh} />
          <SortHeader label="First seen" k="first_seen" {...sh} />
        </Table.Row>
      </Table.Header>
      <Table.Body>
        {loading && <LoadingRows cols={9} />}
        {data?.items.map((h) => (
          <Table.Row key={h.host_id}>
            <Table.Cell>
              <HStack gap="1">
                <CLink asChild fontWeight="semibold">
                  <Link to={drill(ps, { host_id: h.host_id })}>{h.host_name}</Link>
                </CLink>
                <IconButton asChild size="2xs" variant="ghost" aria-label={`Open host ${h.host_name}`}>
                  <Link to={`/hosts/${h.host_id}`}>
                    <LuServer />
                  </Link>
                </IconButton>
              </HStack>
            </Table.Cell>
            <Table.Cell>
              <KindTag kind={h.kind} />
            </Table.Cell>
            <Table.Cell>
              <Badge variant="outline" size="sm">
                {h.group}
              </Badge>
            </Table.Cell>
            <Table.Cell>
              <SeverityCounts counts={h} />
            </Table.Cell>
            <Table.Cell textAlign="end" fontVariantNumeric="tabular-nums">
              {num(h.vulns)}
            </Table.Cell>
            <Table.Cell textAlign="end" fontVariantNumeric="tabular-nums">
              {num(h.total)}
            </Table.Cell>
            <Table.Cell textAlign="end" fontVariantNumeric="tabular-nums">
              {h.kev ? num(h.kev) : "—"}
            </Table.Cell>
            <Table.Cell textAlign="end" fontVariantNumeric="tabular-nums">
              {h.max_risk ? h.max_risk.toFixed(1) : "—"}
            </Table.Cell>
            <Table.Cell color="fg.muted" whiteSpace="nowrap">
              {ago(h.first_seen)}
            </Table.Cell>
          </Table.Row>
        ))}
        {data && data.items.length === 0 && (
          <Table.Row>
            <Table.Cell colSpan={9}>
              <Empty icon={<LuShieldCheck />} title="No hosts match" description="Try removing some filters." />
            </Table.Cell>
          </Table.Row>
        )}
      </Table.Body>
    </DataTable>
  )
}

function LocationTable({ ps, data, loading }: { ps: PS; data?: List<LocationRow>; loading: boolean }) {
  const sh = { sort: ps.sort, order: ps.order, onSort: ps.toggleSort }
  return (
    <DataTable minW="6xl">
      <Table.Header>
        <Table.Row>
          <SortHeader label="Location" k="location" {...sh} />
          <SortHeader label="Host / target" k="host" {...sh} />
          <Header>Packages</Header>
          <SortHeader label="Severity" k="severity" {...sh} />
          <SortHeader label="Vulns" k="vulns" textAlign="end" {...sh} />
          <SortHeader label="Instances" k="total" textAlign="end" {...sh} />
          <SortHeader label="Max risk" k="risk" textAlign="end" {...sh} />
          <SortHeader label="First seen" k="first_seen" {...sh} />
        </Table.Row>
      </Table.Header>
      <Table.Body>
        {loading && <LoadingRows cols={8} />}
        {data?.items.map((l) => (
          <Table.Row key={`${l.target_id}:${l.location}`}>
            <Table.Cell maxW="80">
              <CLink asChild fontFamily="mono" textStyle="xs" title={l.location}>
                {/* An empty path can't be a filter value, so it drills to the whole target. */}
                <Link to={drill(ps, l.location ? { host_id: l.host_id, target_id: l.target_id, location: l.location } : { host_id: l.host_id, target_id: l.target_id })}>
                  <Text truncate>{l.location || "— (no path)"}</Text>
                </Link>
              </CLink>
            </Table.Cell>
            <Table.Cell maxW="56">
              <Stack gap="0">
                <CLink asChild fontWeight="medium">
                  <Link to={`/hosts/${l.host_id}`}>{l.host_name}</Link>
                </CLink>
                <Text truncate textStyle="xs" color="fg.muted" title={l.target_name}>
                  {l.target_name}
                </Text>
              </Stack>
            </Table.Cell>
            <Table.Cell maxW="48">
              <Text truncate title={l.packages}>
                {l.packages}
              </Text>
            </Table.Cell>
            <Table.Cell>
              <SeverityCounts counts={l} />
            </Table.Cell>
            <Table.Cell textAlign="end" fontVariantNumeric="tabular-nums">
              {num(l.vulns)}
            </Table.Cell>
            <Table.Cell textAlign="end" fontVariantNumeric="tabular-nums">
              {num(l.total)}
            </Table.Cell>
            <Table.Cell textAlign="end" fontVariantNumeric="tabular-nums">
              {l.max_risk ? l.max_risk.toFixed(1) : "—"}
            </Table.Cell>
            <Table.Cell color="fg.muted" whiteSpace="nowrap">
              {ago(l.first_seen)}
            </Table.Cell>
          </Table.Row>
        ))}
        {data && data.items.length === 0 && (
          <Table.Row>
            <Table.Cell colSpan={8}>
              <Empty icon={<LuShieldCheck />} title="No locations match" description="Try removing some filters." />
            </Table.Cell>
          </Table.Row>
        )}
      </Table.Body>
    </DataTable>
  )
}

function VulnTable({ ps, data, loading }: { ps: PS; data?: List<VulnRow>; loading: boolean }) {
  const sh = { sort: ps.sort, order: ps.order, onSort: ps.toggleSort }
  return (
    <DataTable minW="5xl">
      <Table.Header>
        <Table.Row>
          <SortHeader label="Vulnerability" k="id" {...sh} />
          <SortHeader label="Severity" k="severity" {...sh} />
          <SortHeader label="Packages" k="package" {...sh} />
          <SortHeader label="CVSS" k="cvss" textAlign="end" {...sh} />
          <SortHeader label="EPSS" k="epss" textAlign="end" {...sh} />
          <SortHeader label="Risk" k="risk" textAlign="end" {...sh} />
          <SortHeader label="Hosts" k="hosts" textAlign="end" {...sh} />
          <SortHeader label="Instances" k="instances" textAlign="end" {...sh} />
          <Header>Fix</Header>
          <SortHeader label="First seen" k="first_seen" {...sh} />
          <Header>Status</Header>
        </Table.Row>
      </Table.Header>
      <Table.Body>
        {loading && <LoadingRows cols={11} />}
        {data?.items.map((v) => (
          <Table.Row key={v.id}>
            <Table.Cell>
              <Stack gap="0.5">
                <HStack gap="2">
                  <CLink asChild fontWeight="semibold" fontFamily="mono" textStyle="xs">
                    <Link to={`/vulnerabilities/${encodeURIComponent(v.id)}`}>{v.id}</Link>
                  </CLink>
                  {v.kev && <KevBadge />}
                </HStack>
                {v.aliases && (
                  <Text textStyle="xs" color="fg.muted" truncate maxW="56">
                    {splitList(v.aliases).filter((a) => a !== v.id).join(", ")}
                  </Text>
                )}
              </Stack>
            </Table.Cell>
            <Table.Cell>
              <SeverityBadge severity={v.severity} />
            </Table.Cell>
            <Table.Cell maxW="56">
              <Text truncate title={v.packages}>
                {v.packages}
              </Text>
            </Table.Cell>
            <Table.Cell textAlign="end" fontVariantNumeric="tabular-nums">
              {v.cvss ? v.cvss.toFixed(1) : "—"}
            </Table.Cell>
            <Table.Cell textAlign="end" fontVariantNumeric="tabular-nums" title={v.epss_pct ? `${pct(v.epss_pct)} percentile` : undefined}>
              {pct(v.epss)}
            </Table.Cell>
            <Table.Cell textAlign="end" fontVariantNumeric="tabular-nums">
              {v.risk ? v.risk.toFixed(1) : "—"}
            </Table.Cell>
            <Table.Cell textAlign="end" fontVariantNumeric="tabular-nums">
              {num(v.hosts)}
            </Table.Cell>
            <Table.Cell textAlign="end" fontVariantNumeric="tabular-nums">
              {num(v.instances)}
            </Table.Cell>
            <Table.Cell>{v.fixable ? <FixBadge state="fixed" /> : <FixBadge state="not-fixed" />}</Table.Cell>
            <Table.Cell color="fg.muted" whiteSpace="nowrap">
              {ago(v.first_seen)}
            </Table.Cell>
            <Table.Cell>
              <TriageBadge status={v.status} />
            </Table.Cell>
          </Table.Row>
        ))}
        {data && data.items.length === 0 && (
          <Table.Row>
            <Table.Cell colSpan={11}>
              <Empty icon={<LuShieldCheck />} title="No vulnerabilities match" description="Try removing some filters." />
            </Table.Cell>
          </Table.Row>
        )}
      </Table.Body>
    </DataTable>
  )
}

export function FindingTable({ ps, data, loading, hideHost }: { ps: PS; data?: List<FindingRow>; loading: boolean; hideHost?: boolean }) {
  const sh = { sort: ps.sort, order: ps.order, onSort: ps.toggleSort }
  const cols = hideHost ? 9 : 10
  return (
    <DataTable minW="6xl">
      <Table.Header>
        <Table.Row>
          <SortHeader label="Vulnerability" k="vuln_id" {...sh} />
          <SortHeader label="Severity" k="severity" {...sh} />
          <SortHeader label="Package" k="package" {...sh} />
          <SortHeader label="Type" k="pkg_type" {...sh} />
          <SortHeader label="Fix" k="fix_state" {...sh} />
          <SortHeader label="EPSS" k="epss" textAlign="end" {...sh} />
          {!hideHost && <SortHeader label="Host" k="host" {...sh} />}
          <SortHeader label="Target" k="target" {...sh} />
          <SortHeader label="First seen" k="first_seen" {...sh} />
          <Header>Status</Header>
        </Table.Row>
      </Table.Header>
      <Table.Body>
        {loading && <LoadingRows cols={cols} />}
        {data?.items.map((f) => (
          <Table.Row key={f.id}>
            <Table.Cell>
              <HStack gap="2">
                <CLink asChild fontWeight="semibold" fontFamily="mono" textStyle="xs">
                  <Link to={`/vulnerabilities/${encodeURIComponent(f.vuln_id)}`}>{f.vuln_id}</Link>
                </CLink>
                {f.kev && <KevBadge />}
              </HStack>
            </Table.Cell>
            <Table.Cell>
              <SeverityBadge severity={f.severity} />
            </Table.Cell>
            <Table.Cell maxW="64">
              <Stack gap="0">
                <Text truncate fontWeight="medium" title={f.purl}>
                  {f.pkg_name}{" "}
                  <Text as="span" color="fg.muted" fontWeight="normal">
                    {f.pkg_version}
                  </Text>
                </Text>
                {f.location && (
                  <Mono color="fg.subtle" truncate maxW="64">
                    {f.location}
                  </Mono>
                )}
              </Stack>
            </Table.Cell>
            <Table.Cell color="fg.muted">{f.pkg_type}</Table.Cell>
            <Table.Cell>
              <FixBadge state={f.fix_state} versions={f.fix_versions} />
            </Table.Cell>
            <Table.Cell textAlign="end" fontVariantNumeric="tabular-nums">
              {pct(f.epss)}
            </Table.Cell>
            {!hideHost && (
              <Table.Cell>
                <CLink asChild>
                  <Link to={`/hosts/${f.host_id}`}>{f.host_name}</Link>
                </CLink>
              </Table.Cell>
            )}
            <Table.Cell maxW="48">
              <Text truncate title={f.target_name} color="fg.muted">
                {f.target_name}
              </Text>
            </Table.Cell>
            <Table.Cell color="fg.muted" whiteSpace="nowrap">
              {ago(f.first_seen)}
            </Table.Cell>
            <Table.Cell>
              <TriageBadge status={f.status} />
            </Table.Cell>
          </Table.Row>
        ))}
        {data && data.items.length === 0 && (
          <Table.Row>
            <Table.Cell colSpan={cols}>
              <Empty icon={<LuShieldCheck />} title="No findings match" description="Try removing some filters." />
            </Table.Cell>
          </Table.Row>
        )}
      </Table.Body>
    </DataTable>
  )
}
