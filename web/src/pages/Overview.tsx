import type { ReactNode } from "react"
import { Link } from "react-router"
import { useQuery } from "@tanstack/react-query"
import { Badge, Box, Button, Card, Flex, Grid, GridItem, HStack, Heading, Link as CLink, SegmentGroup, SimpleGrid, Skeleton, Stack, Table, Text } from "@chakra-ui/react"
import { LuArrowRight, LuServer, LuShieldAlert, LuShieldCheck } from "react-icons/lu"
import { api, SEVERITIES, type Counts, type DailyStat, type Summary } from "@/lib/api"
import { ago, num, pct } from "@/lib/format"
import { ErrorBox, Header, KevBadge, KevMark, Panel, SegmentBar, SeverityBadge, SeverityCounts, StatCard, Empty, type Segment } from "@/components/common"
import { RankedBars, SeverityDonut, SeverityTrend } from "@/components/charts"
import { FIX_OPTIONS } from "@/lib/options"
import { useParamsState } from "@/lib/useParamsState"

const plural = (n: number, one: string, many: string) => `${num(n)} ${n === 1 ? one : many}`

// The page opens with the one thing to do next, then the facts behind it.
function StatusBanner({ s }: { s: Summary }) {
  const unhealthy = s.stale_hosts + s.failing_hosts
  let headline: ReactNode
  let action: { to: string; label: string } | undefined
  if (s.kev > 0) {
    headline = (
      <>
        <KevMark /> {plural(s.kev, "known-exploited vulnerability", "known-exploited vulnerabilities")} to fix first
      </>
    )
    action = { to: "/vulnerabilities?kev=true", label: "Review them" }
  } else if (s.unique.critical > 0) {
    headline = `${plural(s.unique.critical, "critical vulnerability", "critical vulnerabilities")} to review`
    action = { to: "/vulnerabilities?severity=Critical", label: "Review them" }
  } else if (unhealthy > 0) {
    headline = unhealthy === 1 ? "1 host is not reporting as expected" : `${num(unhealthy)} hosts are not reporting as expected`
    action = { to: "/hosts?status=stale", label: "Show hosts" }
  } else {
    headline = "Nothing urgent right now"
  }
  const facts = [
    `${plural(s.hosts, "host", "hosts")} and ${plural(s.targets, "scan target", "scan targets")}`,
    `last report ${ago(s.last_scan)}`,
    `${plural(s.new_last_7d, "new finding", "new findings")} this week`,
    `${plural(s.scans_24h, "scan", "scans")} in 24 h`,
  ]
  return (
    <Flex align={{ base: "start", md: "center" }} justify="space-between" gap="4" mb="6" direction={{ base: "column", md: "row" }}>
      <Box minW="0">
        <Heading as="h2" size={{ base: "xl", md: "2xl" }} letterSpacing="-0.02em" display="flex" alignItems="center" gap="2.5">
          {headline}
        </Heading>
        <Text color="fg.muted" textStyle="sm" mt="1.5">
          {facts.join(" · ")}
        </Text>
      </Box>
      {action && (
        <Button asChild size="sm" variant="outline" flexShrink={0}>
          <Link to={action.to}>
            {action.label} <LuArrowRight />
          </Link>
        </Button>
      )}
    </Flex>
  )
}

// Green for what can be fixed today; the rest are steps of neutral.
const FIX_COLORS: Record<string, string> = { fixed: "green.solid", "not-fixed": "fg.muted", "wont-fix": "fg.subtle", unknown: "border.emphasized" }

function KpiCards({ s }: { s: Summary }) {
  const severity: Segment[] = SEVERITIES.map((sev) => ({
    label: sev,
    value: s.unique[sev.toLowerCase() as keyof Counts],
    color: `sev.${sev.toLowerCase()}`,
    to: `/vulnerabilities?severity=${sev}`,
  }))
  const healthy = Math.max(0, s.hosts - s.stale_hosts - s.failing_hosts)
  const health: Segment[] = [
    { label: "Healthy", value: healthy, color: "green.solid", to: "/hosts?status=ok" },
    { label: "Stale", value: s.stale_hosts, color: "yellow.solid", to: "/hosts?status=stale" },
    { label: "Failing", value: s.failing_hosts, color: "red.solid", to: "/hosts?status=failing" },
  ]
  const fix: Segment[] = FIX_OPTIONS.map(([name, label]) => ({
    label,
    value: s.by_fix_state.find((x) => x.name === name)?.count ?? 0,
    color: FIX_COLORS[name],
    to: `/vulnerabilities?view=findings&fix=${name}`,
  }))
  const fixable = s.findings.total ? s.findings.fixable / s.findings.total : 0
  const kev = s.top_vulns.filter((v) => v.kev).slice(0, 3)

  return (
    <SimpleGrid columns={{ base: 1, md: 2, xl: 4 }} gap="4" mb="4">
      <StatCard label="Vulnerabilities" to="/vulnerabilities" value={num(s.unique.total)} unit={`in ${plural(s.findings.total, "finding", "findings")}`} icon={<LuShieldAlert />}>
        <SegmentBar segments={severity} />
      </StatCard>
      <StatCard label="Hosts" to="/hosts" value={num(s.hosts)} unit={healthy === s.hosts ? "all reporting" : `${num(healthy)} reporting on schedule`} icon={<LuServer />}>
        <SegmentBar segments={health} />
      </StatCard>
      <StatCard label="Fix available" to="/vulnerabilities?view=findings&fix=fixed" value={fixable ? pct(fixable, 0) : "0%"} unit={`${num(s.findings.fixable)} of ${num(s.findings.total)} findings`} icon={<LuShieldCheck />}>
        <SegmentBar segments={fix} />
      </StatCard>
      {/* The diamond is the alert light: the only Signal orange on the page. */}
      <StatCard label="Known exploited" to="/vulnerabilities?kev=true" value={num(s.kev)} unit="in the CISA KEV catalog" icon={<KevMark />}>
        {s.kev === 0 ? (
          <Text textStyle="xs" color="fg.muted">
            None of the active vulnerabilities is known to be exploited.
          </Text>
        ) : (
          <Stack gap="1.5">
            {kev.map((v) => (
              <HStack key={v.id} gap="2" justify="space-between" textStyle="xs">
                <CLink asChild fontFamily="mono" fontWeight="medium" flexShrink={0}>
                  <Link to={`/vulnerabilities/${encodeURIComponent(v.id)}`}>{v.id}</Link>
                </CLink>
                <Text color="fg.muted" truncate>
                  {v.packages}
                </Text>
              </HStack>
            ))}
            {s.kev > kev.length && (
              <Text textStyle="xs" color="fg.muted">
                {kev.length ? `and ${num(s.kev - kev.length)} more` : "Open the list to see them"}
              </Text>
            )}
          </Stack>
        )}
      </StatCard>
    </SimpleGrid>
  )
}

const TREND_DEFAULTS = { days: "30" }

export function OverviewPage() {
  const ps = useParamsState(TREND_DEFAULTS)
  const days = ps.get("days")
  const summary = useQuery({ queryKey: ["summary"], queryFn: () => api.get<Summary>("/summary"), refetchInterval: 60_000 })
  const trends = useQuery({ queryKey: ["trends", days], queryFn: () => api.get<DailyStat[]>("/trends", { days }) })
  const s = summary.data

  if (summary.error) return <ErrorBox error={summary.error} />
  if (!s)
    return (
      <>
        <Skeleton h="8" w={{ base: "full", md: "md" }} mb="2" />
        <Skeleton h="4" w={{ base: "3/4", md: "sm" }} mb="6" />
        <SimpleGrid columns={{ base: 1, md: 2, xl: 4 }} gap="4">
          {Array.from({ length: 4 }, (_, i) => (
            <Skeleton key={i} h="40" rounded="l3" />
          ))}
        </SimpleGrid>
      </>
    )

  if (s.hosts === 0)
    return (
      <Card.Root variant="outline" bg="surface">
        <Card.Body>
          <Empty
            icon={<LuServer />}
            title="No hosts have reported yet"
            description="Install the agent on a VM or Docker host, or add a registry image to scan centrally."
            action={
              <Button asChild size="sm">
                <Link to="/settings">
                  Set up an agent <LuArrowRight />
                </Link>
              </Button>
            }
          />
        </Card.Body>
      </Card.Root>
    )

  return (
    <>
      <StatusBanner s={s} />
      <KpiCards s={s} />

      <Grid templateColumns={{ base: "1fr", xl: "2fr 1fr" }} gap="4" mb="4">
        <GridItem minW="0">
          <Panel
            title="Findings over time"
            subtitle="Active findings by severity, one point per day"
            actions={
              <SegmentGroup.Root size="xs" value={days} onValueChange={(e) => ps.set({ days: e.value })}>
                <SegmentGroup.Indicator />
                <SegmentGroup.Items items={[{ value: "7", label: "7d" }, { value: "30", label: "30d" }, { value: "90", label: "90d" }]} />
              </SegmentGroup.Root>
            }
          >
            {trends.data ? <SeverityTrend data={trends.data} /> : <Skeleton h="72" />}
          </Panel>
        </GridItem>
        <Panel title="Vulnerabilities by severity" subtitle="Unique active vulnerabilities">
          <SeverityDonut counts={s.unique} caption="unique" />
        </Panel>
      </Grid>

      <Grid templateColumns={{ base: "1fr", xl: "1fr 1fr" }} gap="4" mb="4">
        <Panel
          title="Riskiest hosts"
          subtitle="Weighted by severity of active findings"
          p="0"
          actions={
            <CLink asChild textStyle="xs" color="fg.muted">
              <Link to="/hosts?sort=score&order=desc">All hosts</Link>
            </CLink>
          }
        >
          <Table.Root size="sm" mt="2">
            <Table.Header>
              <Table.Row>
                <Header>Host</Header>
                <Header>Severity</Header>
                <Header textAlign="end">Findings</Header>
              </Table.Row>
            </Table.Header>
            <Table.Body>
              {s.top_hosts.map((h) => (
                <Table.Row key={h.id}>
                  <Table.Cell>
                    <CLink asChild fontWeight="medium">
                      <Link to={`/hosts/${h.id}`}>{h.name}</Link>
                    </CLink>
                  </Table.Cell>
                  <Table.Cell>
                    <SeverityCounts counts={h} />
                  </Table.Cell>
                  <Table.Cell textAlign="end" fontVariantNumeric="tabular-nums">
                    {num(h.total)}
                  </Table.Cell>
                </Table.Row>
              ))}
            </Table.Body>
          </Table.Root>
        </Panel>
        <Panel
          title="Top vulnerabilities"
          subtitle="Ranked by Grype risk score (severity × EPSS × KEV)"
          p="0"
          actions={
            <CLink asChild textStyle="xs" color="fg.muted">
              <Link to="/vulnerabilities?sort=risk&order=desc">All vulnerabilities</Link>
            </CLink>
          }
        >
          <Table.Root size="sm" mt="2">
            <Table.Header>
              <Table.Row>
                <Header>Vulnerability</Header>
                <Header>Severity</Header>
                <Header>Package</Header>
                <Header textAlign="end">EPSS</Header>
                <Header textAlign="end">Hosts</Header>
              </Table.Row>
            </Table.Header>
            <Table.Body>
              {s.top_vulns.map((v) => (
                <Table.Row key={v.id}>
                  <Table.Cell>
                    <HStack gap="2">
                      <CLink asChild fontWeight="medium" fontFamily="mono" textStyle="xs">
                        <Link to={`/vulnerabilities/${encodeURIComponent(v.id)}`}>{v.id}</Link>
                      </CLink>
                      {v.kev && <KevBadge />}
                    </HStack>
                  </Table.Cell>
                  <Table.Cell>
                    <SeverityBadge severity={v.severity} />
                  </Table.Cell>
                  <Table.Cell maxW="40" truncate color="fg.muted">
                    {v.packages}
                  </Table.Cell>
                  <Table.Cell textAlign="end" fontVariantNumeric="tabular-nums">
                    {pct(v.epss)}
                  </Table.Cell>
                  <Table.Cell textAlign="end" fontVariantNumeric="tabular-nums">
                    {v.hosts}
                  </Table.Cell>
                </Table.Row>
              ))}
            </Table.Body>
          </Table.Root>
        </Panel>
      </Grid>

      <SimpleGrid columns={{ base: 1, md: 2, xl: 4 }} gap="4">
        <Panel title="By ecosystem" subtitle="Findings per package type">
          <RankedBars data={s.by_pkg_type.slice(0, 8)} hrefFor={(n) => `/vulnerabilities?view=findings&pkg_type=${encodeURIComponent(n)}`} />
        </Panel>
        <Panel title="Most affected packages" subtitle="Findings per package">
          <RankedBars data={s.top_packages.slice(0, 8)} hrefFor={(n) => `/vulnerabilities?view=findings&q=${encodeURIComponent(n)}`} />
        </Panel>
        <Panel title="Fix availability" subtitle="Findings by fix state">
          <RankedBars data={s.by_fix_state} />
        </Panel>
        <Panel title="Host groups" subtitle="Findings per group">
          <RankedBars data={s.by_group} hrefFor={(n) => `/hosts?group=${encodeURIComponent(n)}`} />
          <Stack mt="4" gap="1">
            {s.by_status
              .filter((x) => x.name !== "open")
              .map((x) => (
                <HStack key={x.name} justify="space-between" textStyle="xs" color="fg.muted">
                  <Text>Triaged as {x.name.replace("_", " ")}</Text>
                  <Badge size="sm" variant="outline">
                    {num(x.count)}
                  </Badge>
                </HStack>
              ))}
          </Stack>
        </Panel>
      </SimpleGrid>
    </>
  )
}
