import { useMemo, useState } from "react"
import { Link, useParams } from "react-router"
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query"
import {
  Badge,
  Breadcrumb,
  Button,
  DataList,
  Field,
  Grid,
  HStack,
  Heading,
  RadioCard,
  Link as CLink,
  Skeleton,
  Stack,
  Table,
  Text,
  Textarea,
  Wrap,
} from "@chakra-ui/react"
import { LuExternalLink, LuPencil } from "react-icons/lu"
import { api, TRIAGE_STATUSES, type FindingRow, type TriageStatus, type VulnDetail } from "@/lib/api"
import { ago, dateTime, pct, splitList, statusLabel } from "@/lib/format"
import { DataTable, ErrorBox, FixBadge, Header, KevBadge, Mono, Panel, Select, SeverityBadge, TriageBadge } from "@/components/common"
import { Sheet, SheetBody, SheetFooter } from "@/components/Sheet"
import { useSheet } from "@/lib/useSheet"
import { toaster } from "@/components/ui/toaster"

interface VulnResponse {
  vulnerability: VulnDetail
  affected: FindingRow[]
  affected_total: number
}

// Only http(s) values from the vulnerability data become links.
const isWebURL = (u?: string): u is string => !!u && /^https?:\/\//i.test(u)

const TRIAGE_HELP: Record<TriageStatus, string> = {
  open: "Needs attention. Counted in all totals.",
  acknowledged: "Known and being worked on. Still counted as active.",
  ignored: "Accepted risk. Hidden from active totals.",
  false_positive: "Not applicable. Hidden from active totals.",
}

function cvssLabel(score: number) {
  if (!score) return ""
  if (score >= 9) return "Critical"
  if (score >= 7) return "High"
  if (score >= 4) return "Medium"
  return "Low"
}

export function VulnDetailPage() {
  const { id = "" } = useParams()
  const q = useQuery({ queryKey: ["vuln", id], queryFn: () => api.get<VulnResponse>(`/vulnerabilities/${encodeURIComponent(id)}`) })

  if (q.error) return <ErrorBox error={q.error} />
  if (!q.data) return <Skeleton h="96" rounded="lg" />
  const v = q.data.vulnerability
  const urls = splitList(v.urls).filter(isWebURL)
  const aliases = splitList(v.aliases).filter((a) => a !== v.id)
  const cwes = splitList(v.cwes)

  return (
    <>
      <Breadcrumb.Root mb="3" size="sm">
        <Breadcrumb.List>
          <Breadcrumb.Item>
            <Breadcrumb.Link asChild>
              <Link to="/vulnerabilities">Vulnerabilities</Link>
            </Breadcrumb.Link>
          </Breadcrumb.Item>
          <Breadcrumb.Separator />
          <Breadcrumb.Item>
            <Breadcrumb.CurrentLink>{v.id}</Breadcrumb.CurrentLink>
          </Breadcrumb.Item>
        </Breadcrumb.List>
      </Breadcrumb.Root>

      <Stack gap="2" mb="6">
        <HStack gap="3" wrap="wrap">
          <Heading size="2xl" fontFamily="mono" letterSpacing="-0.02em">
            {v.id}
          </Heading>
          <SeverityBadge severity={v.severity} />
          {v.kev && <KevBadge />}
          <TriageBadge status={v.status} />
        </HStack>
        {aliases.length > 0 && (
          <Text color="fg.muted" textStyle="sm">
            Also known as{" "}
            {aliases.map((a, i) => (
              <span key={a}>
                {i > 0 && ", "}
                <CLink asChild>
                  <Link to={`/vulnerabilities/${encodeURIComponent(a)}`}>{a}</Link>
                </CLink>
              </span>
            ))}
          </Text>
        )}
      </Stack>

      <Grid templateColumns={{ base: "1fr", xl: "2fr 1fr" }} gap="4" mb="4" alignItems="start">
        <Stack gap="4" minW="0">
          <Panel title="Description">
            <Text textStyle="sm" whiteSpace="pre-wrap" color={v.description ? "fg" : "fg.muted"}>
              {v.description || "No description was provided by the vulnerability data sources."}
            </Text>
            {urls.length > 0 && (
              <Stack mt="4" gap="1">
                <Text textStyle="xs" fontWeight="semibold" color="fg.muted" textTransform="uppercase" letterSpacing="wider">
                  References
                </Text>
                {urls.slice(0, 12).map((u) => (
                  <CLink key={u} href={u} target="_blank" rel="noopener noreferrer" textStyle="sm" colorPalette="blue" color="colorPalette.fg" wordBreak="break-all">
                    {u} <LuExternalLink />
                  </CLink>
                ))}
                {urls.length > 12 && (
                  <Text textStyle="xs" color="fg.muted">
                    and {urls.length - 12} more
                  </Text>
                )}
              </Stack>
            )}
          </Panel>
        </Stack>
        <Stack gap="4">
          <Panel title="Scoring">
            <DataList.Root orientation="horizontal" size="sm">
              <DataList.Item>
                <DataList.ItemLabel>CVSS</DataList.ItemLabel>
                <DataList.ItemValue>
                  {v.cvss ? (
                    <Stack gap="0.5">
                      <Text fontWeight="semibold">
                        {v.cvss.toFixed(1)} <Text as="span" color="fg.muted" fontWeight="normal">{cvssLabel(v.cvss)}</Text>
                      </Text>
                      {v.cvss_vector && <Mono color="fg.muted">{v.cvss_vector}</Mono>}
                    </Stack>
                  ) : (
                    "—"
                  )}
                </DataList.ItemValue>
              </DataList.Item>
              <DataList.Item>
                <DataList.ItemLabel>EPSS</DataList.ItemLabel>
                <DataList.ItemValue>
                  {v.epss ? `${pct(v.epss, 2)} chance of exploitation in 30 days (${pct(v.epss_pct, 0)} percentile)` : "—"}
                </DataList.ItemValue>
              </DataList.Item>
              <DataList.Item>
                <DataList.ItemLabel>Risk score</DataList.ItemLabel>
                <DataList.ItemValue>{v.risk ? v.risk.toFixed(2) : "—"}</DataList.ItemValue>
              </DataList.Item>
              <DataList.Item>
                <DataList.ItemLabel>Weakness</DataList.ItemLabel>
                <DataList.ItemValue>
                  <Wrap gap="1">
                    {cwes.length
                      ? cwes.map((c) => (
                          <Badge key={c} variant="outline" size="sm">
                            {c}
                          </Badge>
                        ))
                      : "—"}
                  </Wrap>
                </DataList.ItemValue>
              </DataList.Item>
              <DataList.Item>
                <DataList.ItemLabel>Source</DataList.ItemLabel>
                <DataList.ItemValue>
                  <Stack gap="0">
                    <Text>{v.namespace || "—"}</Text>
                    {isWebURL(v.data_source) && (
                      <CLink href={v.data_source} target="_blank" rel="noopener noreferrer" textStyle="xs" color="fg.muted" wordBreak="break-all">
                        {v.data_source}
                      </CLink>
                    )}
                  </Stack>
                </DataList.ItemValue>
              </DataList.Item>
              <DataList.Item>
                <DataList.ItemLabel>First seen</DataList.ItemLabel>
                <DataList.ItemValue title={dateTime(v.first_seen)}>{ago(v.first_seen)}</DataList.ItemValue>
              </DataList.Item>
            </DataList.Root>
          </Panel>
          <TriagePanel v={v} affected={q.data.affected} />
        </Stack>
      </Grid>

      <Heading size="md" mb="3">
        Affected packages{" "}
        <Text as="span" color="fg.muted" fontWeight="normal">
          ({q.data.affected_total})
        </Text>
      </Heading>
      <DataTable minW="5xl">
        <Table.Header>
          <Table.Row>
            <Header>Host</Header>
            <Header>Target</Header>
            <Header>Package</Header>
            <Header>Type</Header>
            <Header>Fix</Header>
            <Header>Location</Header>
            <Header>First seen</Header>
            <Header>Status</Header>
          </Table.Row>
        </Table.Header>
        <Table.Body>
          {q.data.affected.map((f) => (
            <Table.Row key={f.id}>
              <Table.Cell>
                <CLink asChild fontWeight="medium">
                  <Link to={`/hosts/${f.host_id}`}>{f.host_name}</Link>
                </CLink>
                <Text textStyle="xs" color="fg.muted">
                  {f.group}
                </Text>
              </Table.Cell>
              <Table.Cell maxW="56">
                <Text truncate title={f.target_name}>
                  {f.target_name}
                </Text>
              </Table.Cell>
              <Table.Cell>
                <Text fontWeight="medium">
                  {f.pkg_name}{" "}
                  <Text as="span" color="fg.muted" fontWeight="normal">
                    {f.pkg_version}
                  </Text>
                </Text>
              </Table.Cell>
              <Table.Cell color="fg.muted">{f.pkg_type}</Table.Cell>
              <Table.Cell>
                <FixBadge state={f.fix_state} versions={f.fix_versions} />
              </Table.Cell>
              <Table.Cell maxW="72">
                <Mono color="fg.muted" truncate>
                  {f.location || "—"}
                </Mono>
              </Table.Cell>
              <Table.Cell color="fg.muted" whiteSpace="nowrap">
                {ago(f.first_seen)}
              </Table.Cell>
              <Table.Cell>
                <TriageBadge status={f.status} />
              </Table.Cell>
            </Table.Row>
          ))}
        </Table.Body>
      </DataTable>
      {q.data.affected_total > q.data.affected.length && (
        <Text mt="2" textStyle="sm" color="fg.muted">
          Showing the first {q.data.affected.length}.{" "}
          <CLink asChild>
            <Link to={`/vulnerabilities?view=findings&q=${encodeURIComponent(v.id)}&status=all`}>See all instances</Link>
          </CLink>
        </Text>
      )}
    </>
  )
}

// The current triage, read-only; changing it happens in a sheet.
function TriagePanel({ v, affected }: { v: VulnDetail; affected: FindingRow[] }) {
  const sheet = useSheet("triage")
  return (
    <Panel
      title="Triage"
      subtitle="Applies to every host, unless a host has its own"
      actions={
        <Button size="sm" variant="outline" flexShrink={0} onClick={sheet.show}>
          <LuPencil /> Triage
        </Button>
      }
    >
      <Stack gap="2">
        <HStack gap="2" wrap="wrap">
          <TriageBadge status={v.status} />
          <Text textStyle="sm" color="fg.muted">
            {TRIAGE_HELP[v.status]}
          </Text>
        </HStack>
        {v.note && (
          <Text textStyle="sm" whiteSpace="pre-wrap">
            {v.note}
          </Text>
        )}
      </Stack>
      <Sheet open={sheet.open} onClose={sheet.hide} title={`Triage ${v.id}`} description="Decide for every host at once, or override the decision for a single host.">
        <TriageForm v={v} affected={affected} onDone={sheet.hide} />
      </Sheet>
    </Panel>
  )
}

function TriageForm({ v, affected, onDone }: { v: VulnDetail; affected: FindingRow[]; onDone: () => void }) {
  const qc = useQueryClient()
  const [scope, setScope] = useState("0")
  const [status, setStatus] = useState<TriageStatus>(v.status)
  const [note, setNote] = useState(v.note)
  const hosts = useMemo(() => {
    const m = new Map<number, string>()
    affected.forEach((f) => m.set(f.host_id, f.host_name))
    return [...m.entries()].sort((a, b) => a[1].localeCompare(b[1]))
  }, [affected])

  const changeScope = (next: string) => {
    setScope(next)
    if (next === "0") {
      setStatus(v.status)
      setNote(v.note)
    } else {
      setStatus(affected.find((f) => String(f.host_id) === next)?.status ?? "open")
      setNote("")
    }
  }

  const save = useMutation({
    mutationFn: () => api.put(`/vulnerabilities/${encodeURIComponent(v.id)}/triage`, { host_id: Number(scope), status, note }),
    onSuccess: () => {
      toaster.create({ type: "success", title: `${v.id} marked ${statusLabel(status).toLowerCase()}` })
      qc.invalidateQueries()
      onDone()
    },
    onError: (e) => toaster.create({ type: "error", title: "Could not save triage", description: (e as Error).message }),
  })
  const scopeLabel = scope === "0" ? "All hosts" : (hosts.find(([id]) => String(id) === scope)?.[1] ?? "One host")

  return (
    <>
      <SheetBody>
        <Stack gap="5">
          <Field.Root>
            <Field.Label>Scope</Field.Label>
            <Select
              label="Scope"
              w="full"
              value={scope}
              onChange={changeScope}
              options={[["0", "All hosts"], ...hosts.map(([id, name]) => [String(id), `Only ${name}`] as [string, string])]}
            />
          </Field.Root>
          <RadioCard.Root value={status} onValueChange={(e) => e.value && setStatus(e.value as TriageStatus)} variant="outline" size="sm">
            <RadioCard.Label>Status</RadioCard.Label>
            <Stack gap="2">
              {TRIAGE_STATUSES.map((s) => (
                <RadioCard.Item key={s} value={s} _checked={{ bg: "bg.muted" }}>
                  <RadioCard.ItemHiddenInput />
                  <RadioCard.ItemControl>
                    <RadioCard.ItemContent>
                      <RadioCard.ItemText>{statusLabel(s)}</RadioCard.ItemText>
                      <RadioCard.ItemDescription>{TRIAGE_HELP[s]}</RadioCard.ItemDescription>
                    </RadioCard.ItemContent>
                    <RadioCard.ItemIndicator />
                  </RadioCard.ItemControl>
                </RadioCard.Item>
              ))}
            </Stack>
          </RadioCard.Root>
          <Field.Root>
            <Field.Label>Note</Field.Label>
            <Textarea rows={5} value={note} onChange={(e) => setNote(e.currentTarget.value)} placeholder="Why, ticket link, mitigation…" maxLength={2000} />
          </Field.Root>
        </Stack>
      </SheetBody>
      <SheetFooter
        summary={
          <Text truncate>
            {scopeLabel} · {statusLabel(status)}
          </Text>
        }
      >
        <Button size="sm" variant="outline" onClick={onDone}>
          Cancel
        </Button>
        <Button size="sm" onClick={() => save.mutate()} loading={save.isPending}>
          Save triage
        </Button>
      </SheetFooter>
    </>
  )
}
