import { useState } from "react"
import { Link, useNavigate, useParams } from "react-router"
import { keepPreviousData, useMutation, useQuery, useQueryClient } from "@tanstack/react-query"
import {
  Badge,
  Breadcrumb,
  Button,
  Card,
  CloseButton,
  DataList,
  Dialog,
  Field,
  Flex,
  HStack,
  Heading,
  Input,
  Portal,
  SimpleGrid,
  Skeleton,
  Stack,
  Table,
  Tabs,
  Text,
  Textarea,
} from "@chakra-ui/react"
import { LuKeyRound, LuPencil, LuTrash2 } from "react-icons/lu"
import { api, type EventRow, type FindingRow, type HostRow, type List, type ScanRow, type TargetRow } from "@/lib/api"
import { ago, dateTime, interval, num } from "@/lib/format"
import { useParamsState } from "@/lib/useParamsState"
import { DataTable, ErrorBox, FilterBar, Header, HostStatusBadge, Pager, Panel, SearchInput, Select, SeverityCounts } from "@/components/common"
import { ClearFilters, KevToggle, SeverityChips } from "@/components/filters"
import { FindingTable } from "@/pages/Vulnerabilities"
import { KindTag } from "@/components/KindTag"
import { FIX_OPTIONS, STATUS_OPTIONS } from "@/lib/options"
import { EventTable, ScanTable } from "@/components/tables"
import { SeverityDonut } from "@/components/charts"
import { toaster } from "@/components/ui/toaster"

interface HostResponse {
  host: HostRow
  targets: TargetRow[]
}

const DEFAULTS = { tab: "findings", sort: "severity", order: "desc", status: "active", size: "25" }

export function HostDetailPage() {
  const { id = "" } = useParams()
  const ps = useParamsState(DEFAULTS)
  const tab = ps.get("tab")
  const q = useQuery({ queryKey: ["host", id], queryFn: () => api.get<HostResponse>(`/hosts/${id}`) })

  if (q.error) return <ErrorBox error={q.error} />
  if (!q.data) return <Skeleton h="96" rounded="lg" />
  const { host: h, targets } = q.data
  const active = targets.filter((t) => !t.retired_at)

  return (
    <>
      <Breadcrumb.Root mb="3" size="sm">
        <Breadcrumb.List>
          <Breadcrumb.Item>
            <Breadcrumb.Link asChild>
              <Link to="/hosts">Hosts</Link>
            </Breadcrumb.Link>
          </Breadcrumb.Item>
          <Breadcrumb.Separator />
          <Breadcrumb.Item>
            <Breadcrumb.CurrentLink>{h.name}</Breadcrumb.CurrentLink>
          </Breadcrumb.Item>
        </Breadcrumb.List>
      </Breadcrumb.Root>

      <Flex justify="space-between" align="start" gap="4" mb="6" wrap="wrap">
        <Stack gap="2">
          <HStack gap="3" wrap="wrap">
            <Heading size="2xl" letterSpacing="-0.02em">
              {h.name}
            </Heading>
            <HostStatusBadge status={h.status} />
            <Badge variant="outline">{h.group}</Badge>
          </HStack>
          <HStack gap="4" color="fg.muted" textStyle="sm" wrap="wrap">
            <KindTag kind={h.kind} />
            {h.os && <Text>{h.os}</Text>}
            {h.ip && <Text>{h.ip}</Text>}
            <Text title={dateTime(h.last_seen)}>Last seen {ago(h.last_seen)}</Text>
          </HStack>
        </Stack>
        <HStack>
          <EditHost host={h} />
          {h.kind !== "central" && <ResetCredential host={h} />}
          <DeleteHost host={h} />
        </HStack>
      </Flex>

      <SimpleGrid columns={{ base: 1, lg: 3 }} gap="4" mb="6">
        <Panel title="Active vulnerabilities" subtitle="Findings across all current targets">
          <SeverityDonut counts={h} caption="findings" />
        </Panel>
        <Panel title="Agent">
          <DataList.Root orientation="horizontal" size="sm">
            <DataList.Item>
              <DataList.ItemLabel>Agent</DataList.ItemLabel>
              <DataList.ItemValue>{h.agent_version || "—"}</DataList.ItemValue>
            </DataList.Item>
            <DataList.Item>
              <DataList.ItemLabel>Schedule</DataList.ItemLabel>
              <DataList.ItemValue>{h.interval_sec ? `every ${interval(h.interval_sec)}` : "unknown"}</DataList.ItemValue>
            </DataList.Item>
            <DataList.Item>
              <DataList.ItemLabel>Last run</DataList.ItemLabel>
              <DataList.ItemValue>
                <Badge colorPalette={h.last_run_status === "error" ? "red" : h.last_run_status === "ok" ? "green" : "gray"} variant="subtle" size="sm">
                  {h.last_run_status || "unknown"}
                </Badge>
              </DataList.ItemValue>
            </DataList.Item>
            <DataList.Item>
              <DataList.ItemLabel>Architecture</DataList.ItemLabel>
              <DataList.ItemValue>{h.arch || "—"}</DataList.ItemValue>
            </DataList.Item>
            <DataList.Item>
              <DataList.ItemLabel>First seen</DataList.ItemLabel>
              <DataList.ItemValue title={dateTime(h.first_seen)}>{ago(h.first_seen)}</DataList.ItemValue>
            </DataList.Item>
          </DataList.Root>
        </Panel>
        <Panel title="Notes">
          <Text textStyle="sm" whiteSpace="pre-wrap" color={h.notes ? "fg" : "fg.muted"}>
            {h.notes || "No notes. Use Edit to record the owner, purpose or patch window."}
          </Text>
          <Text textStyle="xs" color="fg.muted" mt="3">
            {active.length} active target{active.length === 1 ? "" : "s"}
            {targets.length > active.length && `, ${targets.length - active.length} retired`}
          </Text>
        </Panel>
      </SimpleGrid>

      <Tabs.Root value={tab} onValueChange={(e) => ps.set({ tab: e.value, sort: null, order: null, q: null, severity: null, fix: null, kev: null, status: null })} variant="line" lazyMount>
        <Tabs.List mb="4">
          <Tabs.Trigger value="findings">Findings ({num(h.total)})</Tabs.Trigger>
          <Tabs.Trigger value="targets">Targets ({active.length})</Tabs.Trigger>
          <Tabs.Trigger value="scans">Scan history</Tabs.Trigger>
          <Tabs.Trigger value="logs">Logs</Tabs.Trigger>
        </Tabs.List>
        <Tabs.Content value="findings">
          <HostFindings hostId={h.id} ps={ps} />
        </Tabs.Content>
        <Tabs.Content value="targets">
          <TargetsTable targets={targets} hostId={h.id} />
        </Tabs.Content>
        <Tabs.Content value="scans">
          <HostScans hostId={h.id} ps={ps} />
        </Tabs.Content>
        <Tabs.Content value="logs">
          <HostLogs host={h.name} ps={ps} />
        </Tabs.Content>
      </Tabs.Root>
    </>
  )
}

type PS = ReturnType<typeof useParamsState>

function HostFindings({ hostId, ps }: { hostId: number; ps: PS }) {
  const filters = { q: ps.get("q"), severity: ps.getList("severity"), fix: ps.get("fix"), kev: ps.get("kev") === "true", status: ps.get("status") }
  const params = { ...filters, host_id: hostId, page: ps.page, size: ps.size, sort: ps.sort, order: ps.order }
  const q = useQuery({ queryKey: ["findings", params], queryFn: () => api.get<List<FindingRow>>("/findings", params), placeholderData: keepPreviousData })
  const keys = ["q", "severity", "fix", "kev", "status"]
  return (
    <>
      <FilterBar>
        <SearchInput value={filters.q} onChange={(v) => ps.set({ q: v })} placeholder="CVE, package, target…" />
        <SeverityChips value={filters.severity} onChange={(v) => ps.set({ severity: v })} />
        <KevToggle value={filters.kev} onChange={(v) => ps.set({ kev: v ? "true" : null })} />
        <Select label="Fix state" value={filters.fix} onChange={(v) => ps.set({ fix: v })} options={FIX_OPTIONS} placeholder="Any fix state" w="36" />
        <Select label="Triage status" value={filters.status} onChange={(v) => ps.set({ status: v })} options={STATUS_OPTIONS} w="52" />
        <ClearFilters show={keys.some((k) => ps.sp.has(k))} onClear={() => ps.set(Object.fromEntries(keys.map((k) => [k, null])))} />
      </FilterBar>
      {q.error && <ErrorBox error={q.error} />}
      <FindingTable ps={ps} data={q.data} loading={q.isPending} hideHost />
      <Pager total={q.data?.total ?? 0} page={ps.page} size={ps.size} onPage={(p) => ps.set({ page: p })} onSize={(s) => ps.set({ size: s })} />
    </>
  )
}

function TargetsTable({ targets, hostId }: { targets: TargetRow[]; hostId: number }) {
  return (
    <DataTable minW="4xl">
      <Table.Header>
        <Table.Row>
          <Header>Target</Header>
          <Header>Type</Header>
          <Header>Distro</Header>
          <Header>Findings</Header>
          <Header textAlign="end">Total</Header>
          <Header>Last scanned</Header>
          <Header>State</Header>
        </Table.Row>
      </Table.Header>
      <Table.Body>
        {targets.map((t) => (
          <Table.Row key={t.id} opacity={t.retired_at ? 0.6 : 1}>
            <Table.Cell maxW="80">
              <Link to={`/vulnerabilities?view=findings&host_id=${hostId}&q=${encodeURIComponent(t.name)}`}>
                <Text truncate fontWeight="medium" title={t.name} _hover={{ textDecoration: "underline" }}>
                  {t.name}
                </Text>
              </Link>
            </Table.Cell>
            <Table.Cell color="fg.muted">{t.type}</Table.Cell>
            <Table.Cell color="fg.muted">{t.distro || "—"}</Table.Cell>
            <Table.Cell>{t.retired_at ? <Text color="fg.subtle">—</Text> : <SeverityCounts counts={t} />}</Table.Cell>
            <Table.Cell textAlign="end" fontVariantNumeric="tabular-nums">
              {t.retired_at ? "—" : num(t.total)}
            </Table.Cell>
            <Table.Cell color="fg.muted" title={dateTime(t.last_scanned)}>
              {ago(t.last_scanned)}
            </Table.Cell>
            <Table.Cell>
              {t.retired_at ? (
                <Badge variant="outline" size="sm" title={`No longer present since ${dateTime(t.retired_at)}`}>
                  Retired {ago(t.retired_at)}
                </Badge>
              ) : (
                <Badge colorPalette="green" variant="subtle" size="sm">
                  Active
                </Badge>
              )}
            </Table.Cell>
          </Table.Row>
        ))}
      </Table.Body>
    </DataTable>
  )
}

function HostScans({ hostId, ps }: { hostId: number; ps: PS }) {
  const params = { host_id: hostId, page: ps.page, size: ps.size }
  const q = useQuery({ queryKey: ["scans", params], queryFn: () => api.get<List<ScanRow>>("/scans", params), placeholderData: keepPreviousData })
  return (
    <>
      {q.error && <ErrorBox error={q.error} />}
      <ScanTable data={q.data} loading={q.isPending} hideHost />
      <Pager total={q.data?.total ?? 0} page={ps.page} size={ps.size} onPage={(p) => ps.set({ page: p })} onSize={(s) => ps.set({ size: s })} />
    </>
  )
}

function HostLogs({ host, ps }: { host: string; ps: PS }) {
  const params = { host, page: ps.page, size: ps.size, level: ps.getList("level") }
  const q = useQuery({ queryKey: ["events", params], queryFn: () => api.get<List<EventRow>>("/events", params), placeholderData: keepPreviousData, refetchInterval: 15_000 })
  return (
    <>
      {q.error && <ErrorBox error={q.error} />}
      <EventTable data={q.data} loading={q.isPending} hideHost />
      <Pager total={q.data?.total ?? 0} page={ps.page} size={ps.size} onPage={(p) => ps.set({ page: p })} onSize={(s) => ps.set({ size: s })} />
    </>
  )
}

function EditHost({ host }: { host: HostRow }) {
  const qc = useQueryClient()
  const [open, setOpen] = useState(false)
  const [group, setGroup] = useState(host.group)
  const [notes, setNotes] = useState(host.notes)
  const save = useMutation({
    mutationFn: () => api.patch(`/hosts/${host.id}`, { group, notes }),
    onSuccess: () => {
      toaster.create({ type: "success", title: "Host updated" })
      qc.invalidateQueries()
      setOpen(false)
    },
    onError: (e) => toaster.create({ type: "error", title: "Update failed", description: (e as Error).message }),
  })
  return (
    <Dialog.Root
      open={open}
      onOpenChange={(e) => {
        setOpen(e.open)
        if (e.open) {
          setGroup(host.group)
          setNotes(host.notes)
        }
      }}
    >
      <Dialog.Trigger asChild>
        <Button size="sm" variant="outline" bg="surface">
          <LuPencil /> Edit
        </Button>
      </Dialog.Trigger>
      <Portal>
        <Dialog.Backdrop />
        <Dialog.Positioner>
          <Dialog.Content>
            <Dialog.Header>
              <Dialog.Title>Edit {host.name}</Dialog.Title>
            </Dialog.Header>
            <Dialog.Body>
              <Stack gap="4">
                <Field.Root>
                  <Field.Label>Group</Field.Label>
                  <Input value={group} maxLength={64} onChange={(e) => setGroup(e.currentTarget.value)} />
                  <Field.HelperText>Overrides the group the agent reported on first contact.</Field.HelperText>
                </Field.Root>
                <Field.Root>
                  <Field.Label>Notes</Field.Label>
                  <Textarea rows={4} value={notes} maxLength={2000} onChange={(e) => setNotes(e.currentTarget.value)} />
                </Field.Root>
              </Stack>
            </Dialog.Body>
            <Dialog.Footer>
              <Dialog.ActionTrigger asChild>
                <Button variant="outline">Cancel</Button>
              </Dialog.ActionTrigger>
              <Button onClick={() => save.mutate()} loading={save.isPending} disabled={!group.trim()}>
                Save
              </Button>
            </Dialog.Footer>
            <Dialog.CloseTrigger asChild>
              <CloseButton size="sm" />
            </Dialog.CloseTrigger>
          </Dialog.Content>
        </Dialog.Positioner>
      </Portal>
    </Dialog.Root>
  )
}

function ResetCredential({ host }: { host: HostRow }) {
  const reset = useMutation({
    mutationFn: () => api.del(`/hosts/${host.id}/credential`),
    onSuccess: () => toaster.create({ type: "success", title: `Agent credential of ${host.name} reset` }),
    onError: (e) => toaster.create({ type: "error", title: "Reset failed", description: (e as Error).message }),
  })
  return (
    <Dialog.Root role="alertdialog">
      <Dialog.Trigger asChild>
        <Button size="sm" variant="outline" bg="surface">
          <LuKeyRound /> Reset credential
        </Button>
      </Dialog.Trigger>
      <Portal>
        <Dialog.Backdrop />
        <Dialog.Positioner>
          <Dialog.Content>
            <Dialog.Header>
              <Dialog.Title>Reset the agent credential of {host.name}?</Dialog.Title>
            </Dialog.Header>
            <Dialog.Body>
              <Card.Root variant="subtle" size="sm">
                <Card.Body textStyle="sm">
                  The agent's current credential stops working at once. Its next run enrolls again with the enrollment token in its
                  configuration, if that token is still valid; otherwise re-run install.sh with a new token. Use this when a host was rebuilt,
                  renamed or may have been compromised. Findings and history are kept.
                </Card.Body>
              </Card.Root>
            </Dialog.Body>
            <Dialog.Footer>
              <Dialog.ActionTrigger asChild>
                <Button variant="outline">Cancel</Button>
              </Dialog.ActionTrigger>
              <Dialog.ActionTrigger asChild>
                <Button colorPalette="red" onClick={() => reset.mutate()} loading={reset.isPending}>
                  Reset credential
                </Button>
              </Dialog.ActionTrigger>
            </Dialog.Footer>
          </Dialog.Content>
        </Dialog.Positioner>
      </Portal>
    </Dialog.Root>
  )
}

function DeleteHost({ host }: { host: HostRow }) {
  const qc = useQueryClient()
  const navigate = useNavigate()
  const del = useMutation({
    mutationFn: () => api.del(`/hosts/${host.id}`),
    onSuccess: () => {
      toaster.create({ type: "success", title: `${host.name} removed` })
      qc.invalidateQueries()
      navigate("/hosts")
    },
    onError: (e) => toaster.create({ type: "error", title: "Delete failed", description: (e as Error).message }),
  })
  return (
    <Dialog.Root role="alertdialog">
      <Dialog.Trigger asChild>
        <Button size="sm" variant="outline" colorPalette="red" bg="surface">
          <LuTrash2 /> Remove
        </Button>
      </Dialog.Trigger>
      <Portal>
        <Dialog.Backdrop />
        <Dialog.Positioner>
          <Dialog.Content>
            <Dialog.Header>
              <Dialog.Title>Remove {host.name}?</Dialog.Title>
            </Dialog.Header>
            <Dialog.Body>
              <Card.Root variant="subtle" size="sm">
                <Card.Body textStyle="sm">
                  This deletes the host with its targets, scan history and host-specific triage. It also ends the host's agent credential. If the agent is
                  still installed and its enrollment token is still valid, the host enrolls again and reappears on its next scan. Uninstall the
                  agent first to remove it permanently.
                </Card.Body>
              </Card.Root>
            </Dialog.Body>
            <Dialog.Footer>
              <Dialog.ActionTrigger asChild>
                <Button variant="outline">Cancel</Button>
              </Dialog.ActionTrigger>
              <Button colorPalette="red" onClick={() => del.mutate()} loading={del.isPending}>
                Remove host
              </Button>
            </Dialog.Footer>
          </Dialog.Content>
        </Dialog.Positioner>
      </Portal>
    </Dialog.Root>
  )
}
