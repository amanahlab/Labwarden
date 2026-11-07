import type { ReactNode } from "react"
import { Link } from "react-router"
import { useQuery } from "@tanstack/react-query"
import { Badge, Box, Button, Card, Grid, GridItem, HStack, Link as CLink, SegmentGroup, SimpleGrid, Skeleton, Stack, Table, Text } from "@chakra-ui/react"
import { LuArrowRight, LuClock, LuFlame, LuServer, LuShieldAlert, LuShieldCheck, LuSparkles } from "react-icons/lu"
import { api, type DailyStat, type Summary } from "@/lib/api"
import { ago, num, pct } from "@/lib/format"
import { ErrorBox, Header, KevBadge, PageHeader, Panel, SeverityBadge, SeverityCounts, Empty } from "@/components/common"
import { RankedBars, SeverityDonut, SeverityTrend } from "@/components/charts"
import { useParamsState } from "@/lib/useParamsState"

function Kpi(props: { label: string; value: ReactNode; hint?: ReactNode; icon: ReactNode; to?: string; tone?: string }) {
  const body = (
    <Card.Root variant="outline" bg="surface" size="sm" h="full" _hover={props.to ? { borderColor: "border.emphasized" } : undefined}>
      <Card.Body gap="1">
        <HStack justify="space-between" color="fg.muted">
          <Text textStyle="xs" fontWeight="medium" textTransform="uppercase" letterSpacing="wider">
            {props.label}
          </Text>
          <Box color={props.tone ?? "fg.subtle"}>{props.icon}</Box>
        </HStack>
        <Text textStyle="3xl" fontWeight="semibold" letterSpacing="-0.02em" fontVariantNumeric="tabular-nums">
          {props.value}
        </Text>
        {props.hint && (
          <Text textStyle="xs" color="fg.muted">
            {props.hint}
          </Text>
        )}
      </Card.Body>
    </Card.Root>
  )
  return props.to ? (
    <Link to={props.to} style={{ display: "block" }}>
      {body}
    </Link>
  ) : (
    body
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
      <SimpleGrid columns={{ base: 2, lg: 3, xl: 6 }} gap="4">
        {Array.from({ length: 6 }, (_, i) => (
          <Skeleton key={i} h="28" rounded="lg" />
        ))}
      </SimpleGrid>
    )

  if (s.hosts === 0)
    return (
      <>
        <PageHeader title="Overview" />
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
      </>
    )

  const fixable = s.findings.total ? s.findings.fixable / s.findings.total : 0
  const unhealthy = s.stale_hosts + s.failing_hosts

  return (
    <>
      <PageHeader
        title="Overview"
        description={
          <>
            Active findings across {num(s.hosts)} hosts and {num(s.targets)} scan targets · last report {ago(s.last_scan)}
          </>
        }
      />

      <SimpleGrid columns={{ base: 2, lg: 3, xl: 6 }} gap="4" mb="4">
        <Kpi label="Critical" value={num(s.unique.critical)} hint={`${num(s.findings.critical)} affected packages`} icon={<LuShieldAlert />} tone="sev.critical" to="/vulnerabilities?severity=Critical" />
        <Kpi label="High" value={num(s.unique.high)} hint={`${num(s.findings.high)} affected packages`} icon={<LuShieldAlert />} tone="sev.high" to="/vulnerabilities?severity=High" />
        <Kpi label="Known exploited" value={num(s.kev)} hint="CISA KEV catalog" icon={<LuFlame />} tone="red.fg" to="/vulnerabilities?kev=true" />
        <Kpi label="Fix available" value={pct(fixable, 0)} hint={`${num(s.findings.fixable)} of ${num(s.findings.total)} findings`} icon={<LuShieldCheck />} tone="green.fg" to="/vulnerabilities?fix=fixed" />
        <Kpi label="New this week" value={num(s.new_last_7d)} hint={`${num(s.scans_24h)} scans in 24h`} icon={<LuSparkles />} to="/vulnerabilities?sort=first_seen&order=desc" />
        <Kpi
          label="Hosts"
          value={num(s.hosts)}
          hint={unhealthy ? `${s.stale_hosts} stale · ${s.failing_hosts} failing` : "All reporting"}
          icon={unhealthy ? <LuClock /> : <LuServer />}
          tone={unhealthy ? "yellow.fg" : undefined}
          to={unhealthy ? "/hosts?status=stale" : "/hosts"}
        />
      </SimpleGrid>

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
