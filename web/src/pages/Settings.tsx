import { useState, type ReactNode } from "react"
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query"
import {
  Alert,
  Badge,
  Box,
  Button,
  Clipboard,
  CloseButton,
  Code,
  DataList,
  Dialog,
  Field,
  Grid,
  HStack,
  IconButton,
  Input,
  Link as CLink,
  Portal,
  Stack,
  Switch,
  Table,
  Tabs,
  Text,
} from "@chakra-ui/react"
import { LuBell, LuDownload, LuKeyRound, LuLogOut, LuPlay, LuPlus, LuRefreshCw, LuTrash2 } from "react-icons/lu"
import { api, type AgentCredential, type CentralTarget, type SystemInfo, type Token } from "@/lib/api"
import { ago, dateTime } from "@/lib/format"
import { DataTable, Empty, ErrorBox, Header, Mono, PageHeader, Panel, Select } from "@/components/common"
import { toaster } from "@/components/ui/toaster"
import { Tooltip } from "@/components/ui/tooltip"

const onError = (title: string) => (e: unknown) => toaster.create({ type: "error", title, description: (e as Error).message })

// Plain http to anything but this machine: passwords, enrollment tokens and
// host credentials cross the network readable by anyone on the path.
const plainHTTP = window.location.protocol === "http:" && !["localhost", "127.0.0.1", "[::1]"].includes(window.location.hostname)

// Release tag + multi-arch index digest (docker buildx imagetools inspect).
const agentImage = "ghcr.io/amanahlab/labwarden-agent:0.1.0@sha256:3eb0eb6aadb06e85b6b40b8edd42dc665f9ec508cc68be09fed1229c9ba22726"

export function SettingsPage() {
  return (
    <>
      <PageHeader title="Settings" description="Connect hosts, manage enrollment tokens and schedule central registry scans." />
      <Stack gap="6">
        {plainHTTP && (
          <Alert.Root status="warning">
            <Alert.Indicator />
            <Alert.Content>
              <Alert.Title>This dashboard is served over plain HTTP</Alert.Title>
              <Alert.Description>
                Your password, enrollment tokens and the agents' credentials cross the network unencrypted. Set <Code size="sm">LABWARDEN_TLS_CERT</Code>{" "}
                and <Code size="sm">LABWARDEN_TLS_KEY</Code>, or put the dashboard behind an HTTPS reverse proxy.
              </Alert.Description>
            </Alert.Content>
          </Alert.Root>
        )}
        <AgentSetup />
        <Grid templateColumns={{ base: "1fr", xl: "3fr 2fr" }} gap="6" alignItems="start">
          <Stack gap="6">
            <Tokens />
            <EnrolledHosts />
          </Stack>
          <SystemPanel />
        </Grid>
        <CentralTargets />
      </Stack>
    </>
  )
}

function CodeBlock({ code }: { code: string }) {
  return (
    <Box position="relative" bg={{ _light: "gray.900", _dark: "gray.900" }} color="gray.100" rounded="md" p="4" pe="12" overflowX="auto">
      <Text as="pre" fontFamily="mono" textStyle="xs" whiteSpace="pre">
        {code}
      </Text>
      <Clipboard.Root value={code} position="absolute" top="2" right="2">
        <Clipboard.Trigger asChild>
          <IconButton size="xs" variant="ghost" color="gray.300" _hover={{ bg: "gray.700" }} aria-label="Copy">
            <Clipboard.Indicator />
          </IconButton>
        </Clipboard.Trigger>
      </Clipboard.Root>
    </Box>
  )
}

function Step({ n, title, children }: { n: number; title: string; children: ReactNode }) {
  return (
    <HStack align="start" gap="3">
      <Badge variant="solid" rounded="full" size="sm" mt="0.5">
        {n}
      </Badge>
      <Stack gap="2" flex="1" minW="0">
        <Text fontWeight="medium" textStyle="sm">
          {title}
        </Text>
        {children}
      </Stack>
    </HStack>
  )
}

function AgentSetup() {
  const url = window.location.origin
  const sys = useQuery({ queryKey: ["system"], queryFn: () => api.get<SystemInfo>("/system") })
  const vm = `curl -fsSL -o lw-install.sh ${url}/install.sh
echo "${sys.data?.install_sha256 || "<sha256>"}  lw-install.sh" | sha256sum -c
sudo LABWARDEN_URL=${url} LABWARDEN_TOKEN=<token> LABWARDEN_GROUP=homelab sh lw-install.sh`
  const docker = `docker run -d --name labwarden-agent --restart unless-stopped \\
  --read-only --tmpfs /tmp --cap-drop ALL --cap-add DAC_OVERRIDE \\
  --security-opt no-new-privileges:true \\
  -v /var/run/docker.sock:/var/run/docker.sock:ro \\
  -v labwarden-agent-db:/var/lib/labwarden \\
  -e LABWARDEN_URL=${url} -e LABWARDEN_TOKEN=<token> \\
  -e LABWARDEN_HOST=$(hostname) -e LABWARDEN_GROUP=homelab \\
  ${agentImage}`
  const compose = `services:
  # Read-only Docker API: the agent never holds the socket itself.
  docker-proxy:
    image: tecnativa/docker-socket-proxy:v0.5.0@sha256:1f5038b54f06c3e18422902cf00ba21803d1c97805aae032e5e6673d532d3459
    restart: unless-stopped
    environment: { CONTAINERS: "1", IMAGES: "1", POST: "0" }
    volumes:
      - /var/run/docker.sock:/var/run/docker.sock:ro
  labwarden-agent:
    image: ${agentImage}
    restart: unless-stopped
    depends_on: [docker-proxy]
    read_only: true
    tmpfs: [/tmp]
    cap_drop: [ALL]
    cap_add: [DAC_OVERRIDE]         # unpack container filesystems
    security_opt: [no-new-privileges:true]
    environment:
      LABWARDEN_URL: ${url}
      LABWARDEN_TOKEN: <token>
      LABWARDEN_HOST: <host-name>      # name shown in the dashboard
      LABWARDEN_GROUP: homelab
      LABWARDEN_INTERVAL: "21600"    # seconds between scans
      LABWARDEN_DOCKER_URL: tcp://docker-proxy:2375
    volumes:
      - labwarden-agent-db:/var/lib/labwarden
volumes:
  labwarden-agent-db: {}`
  return (
    <Panel title="Connect a host" subtitle="The agent catalogs packages with Syft and pushes compressed SBOMs, run status and logs to this dashboard, which matches them against its vulnerability DB.">
      <Tabs.Root defaultValue="vm" variant="enclosed" size="sm">
        <Tabs.List>
          <Tabs.Trigger value="vm">Linux VM</Tabs.Trigger>
          <Tabs.Trigger value="docker">Docker host</Tabs.Trigger>
          <Tabs.Trigger value="compose">Docker Compose</Tabs.Trigger>
          <Tabs.Trigger value="how">How it works</Tabs.Trigger>
        </Tabs.List>
        <Tabs.Content value="vm">
          <Stack gap="4">
            <Step n={1} title="Create an enrollment token below and replace <token>">
              <Text textStyle="sm" color="fg.muted">
                The agent uses it once to enroll and then keeps its own credential in <Code size="sm">/var/lib/labwarden</Code>. One token can enroll
                many hosts; give it a short expiry or a host limit.
              </Text>
            </Step>
            <Step n={2} title="Download the installer, check it and run it as root">
              <CodeBlock code={vm} />
              <Text textStyle="xs" color="fg.muted">
                The checksum is of this dashboard's installer; the installer in turn checks Syft and the agent script before installing them.
                It installs Syft, the agent script and a sandboxed systemd timer (every 6 hours, randomized by 15 minutes, catches up after downtime). Without
                systemd it uses cron. The first scan starts right away. Options: <Code size="sm">LABWARDEN_SCAN_PATHS</Code>,{" "}
                <Code size="sm">LABWARDEN_SCHEDULE</Code>, <Code size="sm">LABWARDEN_SCAN_DOCKER</Code>, <Code size="sm">LABWARDEN_CA_FILE</Code> (CA of a
                self-signed dashboard certificate; pass <Code size="sm">--cacert</Code> to the download too). Uninstall with{" "}
                <Code size="sm">sudo sh lw-install.sh --uninstall</Code>.
              </Text>
            </Step>
            <Step n={3} title="Check progress">
              <CodeBlock code={"journalctl -u labwarden-agent -f      # systemd\ntail -f /var/log/labwarden-agent.log  # cron"} />
            </Step>
          </Stack>
        </Tabs.Content>
        <Tabs.Content value="docker">
          <Stack gap="3">
            <Text textStyle="sm" color="fg.muted">
              Scans the image of every running container through the Docker socket. The socket is root-equivalent even when mounted{" "}
              <Code size="sm">:ro</Code>; the Compose tab puts a read-only socket proxy in between.
            </Text>
            <CodeBlock code={docker} />
            <Text textStyle="xs" color="fg.muted">
              Images that disappear from the host are retired from the dashboard after the next successful run.
            </Text>
          </Stack>
        </Tabs.Content>
        <Tabs.Content value="compose">
          <CodeBlock code={compose} />
        </Tabs.Content>
        <Tabs.Content value="how">
          <Stack gap="2" textStyle="sm" color="fg.muted" maxW="3xl">
            <Text>
              <b>Schedule.</b> VMs use a systemd timer (cron fallback). The Docker agent loops with a sleep of <Code size="sm">LABWARDEN_INTERVAL</Code>. Each run
              reports its interval, so hosts that stay silent for more than 2.5 intervals are flagged as <i>stale</i>.
            </Text>
            <Text>
              <b>SBOMs.</b> Syft JSON is gzipped and POSTed to <Code size="sm">/api/v1/ingest/sbom</Code> with the host's own credential, which it got by enrolling once with an
              enrollment token. The dashboard queues it
              and matches it within seconds. If the dashboard is unreachable or busy, the SBOM is kept in a local spool and re-sent on the next run.
            </Text>
            <Text>
              <b>Logs.</b> The run start and end go to <Code size="sm">/api/v1/ingest/run</Code>. Warnings and errors (Syft failures,
              upload failures) go to <Code size="sm">/api/v1/ingest/event</Code> and appear under Logs. A run that ends in error marks the host as{" "}
              <i>failing</i>.
            </Text>
            <Text>
              <b>One vulnerability DB.</b> Only the dashboard downloads the Grype DB, once a day. After each new DB it matches every stored SBOM again, so
              new CVEs show up without waiting for the agents. Registry images listed below are scanned by the dashboard itself.
            </Text>
          </Stack>
        </Tabs.Content>
      </Tabs.Root>
    </Panel>
  )
}

const TTL_OPTIONS: [string, string][] = [
  ["1", "Expires in 1 hour"],
  ["24", "Expires in 24 hours"],
  ["168", "Expires in 7 days"],
  ["0", "Never expires"],
]

function tokenState(t: Token): { label: string; palette: string } {
  if (t.revoked_at) return { label: "revoked", palette: "red" }
  if (t.expires_at && new Date(t.expires_at) <= new Date()) return { label: "expired", palette: "gray" }
  if (t.max_uses > 0 && t.uses >= t.max_uses) return { label: "used up", palette: "gray" }
  return { label: "active", palette: "green" }
}

function Tokens() {
  const qc = useQueryClient()
  const [name, setName] = useState("")
  const [ttl, setTTL] = useState("24")
  const [maxUses, setMaxUses] = useState("")
  const [created, setCreated] = useState<{ name: string; value: string } | null>(null)
  const tokens = useQuery({ queryKey: ["tokens"], queryFn: () => api.get<Token[]>("/tokens") })
  const create = useMutation({
    mutationFn: () =>
      api.post<{ token: Token; value: string }>("/tokens", { name: name.trim(), ttl_hours: Number(ttl), max_uses: Number(maxUses) || 0 }),
    onSuccess: (r) => {
      setCreated({ name: r.token.name, value: r.value })
      setName("")
      setMaxUses("")
      qc.invalidateQueries({ queryKey: ["tokens"] })
    },
    onError: onError("Could not create token"),
  })
  const revoke = useMutation({
    mutationFn: (id: number) => api.del(`/tokens/${id}`),
    onSuccess: () => {
      toaster.create({ type: "success", title: "Token revoked" })
      qc.invalidateQueries({ queryKey: ["tokens"] })
    },
    onError: onError("Could not revoke token"),
  })

  return (
    <Panel
      title="Enrollment tokens"
      subtitle="An agent uses a token once, to enroll its host and get its own credential. Revoking a token stops new enrollments only. Only a SHA-256 hash is stored."
    >
      <Stack gap="4">
        <HStack
          as="form"
          flexWrap="wrap"
          onSubmit={(e) => {
            e.preventDefault()
            create.mutate()
          }}
        >
          <Input size="sm" flex="1" minW="40" placeholder="Token name, e.g. homelab VMs" value={name} maxLength={64} onChange={(e) => setName(e.currentTarget.value)} />
          <Select label="Expiry" value={ttl} onChange={setTTL} options={TTL_OPTIONS} w="44" />
          <Input
            size="sm"
            w="28"
            type="number"
            min={0}
            max={10000}
            placeholder="Max hosts"
            aria-label="Maximum number of hosts (empty: no limit)"
            value={maxUses}
            onChange={(e) => setMaxUses(e.currentTarget.value)}
          />
          <Button size="sm" type="submit" loading={create.isPending} disabled={!name.trim()}>
            <LuPlus /> Create
          </Button>
        </HStack>
        {tokens.error && <ErrorBox error={tokens.error} />}
        {tokens.data && tokens.data.length === 0 ? (
          <Empty icon={<LuKeyRound />} title="No tokens" description="Create one to connect your first agent." />
        ) : (
          <Table.Root size="sm">
            <Table.Header>
              <Table.Row>
                <Header>Name</Header>
                <Header>Token</Header>
                <Header>State</Header>
                <Header>Hosts</Header>
                <Header>Expires</Header>
                <Header>Last used</Header>
                <Header />
              </Table.Row>
            </Table.Header>
            <Table.Body>
              {tokens.data?.map((t) => {
                const st = tokenState(t)
                return (
                  <Table.Row key={t.id}>
                    <Table.Cell fontWeight="medium">{t.name}</Table.Cell>
                    <Table.Cell>
                      <Mono color="fg.muted">{t.prefix}…</Mono>
                    </Table.Cell>
                    <Table.Cell>
                      <Badge size="sm" colorPalette={st.palette}>
                        {st.label}
                      </Badge>
                    </Table.Cell>
                    <Table.Cell color="fg.muted">
                      {t.uses}
                      {t.max_uses > 0 && ` / ${t.max_uses}`}
                    </Table.Cell>
                    <Table.Cell color="fg.muted" title={dateTime(t.expires_at)}>
                      {t.expires_at ? dateTime(t.expires_at) : "never"}
                    </Table.Cell>
                    <Table.Cell color="fg.muted" title={dateTime(t.last_used)}>
                      {ago(t.last_used)}
                    </Table.Cell>
                    <Table.Cell textAlign="end">
                      {!t.revoked_at && (
                        <ConfirmButton
                          label={`Revoke ${t.name}?`}
                          body="No new host can enroll with this token. Hosts that already enrolled keep their own credentials."
                          action="Revoke"
                          onConfirm={() => revoke.mutate(t.id)}
                        />
                      )}
                    </Table.Cell>
                  </Table.Row>
                )
              })}
            </Table.Body>
          </Table.Root>
        )}
      </Stack>
      <Dialog.Root open={!!created} onOpenChange={(e) => !e.open && setCreated(null)}>
        <Portal>
          <Dialog.Backdrop />
          <Dialog.Positioner>
            <Dialog.Content>
              <Dialog.Header>
                <Dialog.Title>Token “{created?.name}” created</Dialog.Title>
              </Dialog.Header>
              <Dialog.Body>
                <Stack gap="3">
                  <Alert.Root status="warning" size="sm">
                    <Alert.Indicator />
                    <Alert.Title>Copy it now. It will not be shown again.</Alert.Title>
                  </Alert.Root>
                  <Clipboard.Root value={created?.value ?? ""}>
                    <HStack>
                      <Input readOnly value={created?.value ?? ""} fontFamily="mono" size="sm" onFocus={(e) => e.currentTarget.select()} />
                      <Clipboard.Trigger asChild>
                        <Button size="sm" variant="outline">
                          <Clipboard.Indicator />
                          <Clipboard.CopyText />
                        </Button>
                      </Clipboard.Trigger>
                    </HStack>
                  </Clipboard.Root>
                </Stack>
              </Dialog.Body>
              <Dialog.Footer>
                <Button onClick={() => setCreated(null)}>Done</Button>
              </Dialog.Footer>
              <Dialog.CloseTrigger asChild>
                <CloseButton size="sm" />
              </Dialog.CloseTrigger>
            </Dialog.Content>
          </Dialog.Positioner>
        </Portal>
      </Dialog.Root>
    </Panel>
  )
}

function EnrolledHosts() {
  const creds = useQuery({ queryKey: ["agent-credentials"], queryFn: () => api.get<AgentCredential[]>("/agent-credentials") })
  return (
    <Panel title="Enrolled hosts" subtitle="Each host has its own credential and may only report for itself. Reset one on the host's page.">
      {creds.error && <ErrorBox error={creds.error} />}
      {creds.data && creds.data.length === 0 ? (
        <Empty icon={<LuKeyRound />} title="No enrolled hosts" description="Hosts appear here after their agent's first run." />
      ) : (
        <Table.Root size="sm">
          <Table.Header>
            <Table.Row>
              <Header>Host</Header>
              <Header>Credential</Header>
              <Header>Enrolled</Header>
              <Header>Token</Header>
              <Header>Last used</Header>
              <Header>From</Header>
            </Table.Row>
          </Table.Header>
          <Table.Body>
            {creds.data?.map((c) => (
              <Table.Row key={c.id}>
                <Table.Cell fontWeight="medium">{c.host}</Table.Cell>
                <Table.Cell>
                  <Mono color="fg.muted">{c.prefix}…</Mono>
                </Table.Cell>
                <Table.Cell color="fg.muted" title={dateTime(c.created_at)}>
                  {ago(c.created_at)}
                </Table.Cell>
                <Table.Cell color="fg.muted">{c.enrolled_by || "—"}</Table.Cell>
                <Table.Cell color="fg.muted" title={dateTime(c.last_used)}>
                  {ago(c.last_used)}
                </Table.Cell>
                <Table.Cell>
                  <Mono color="fg.muted">{c.last_ip || "—"}</Mono>
                </Table.Cell>
              </Table.Row>
            ))}
          </Table.Body>
        </Table.Root>
      )}
    </Panel>
  )
}

function ConfirmButton({ label, body, action, onConfirm }: { label: string; body: string; action: string; onConfirm: () => void }) {
  return (
    <Dialog.Root role="alertdialog" size="sm">
      <Dialog.Trigger asChild>
        <IconButton size="xs" variant="ghost" colorPalette="red" aria-label={action}>
          <LuTrash2 />
        </IconButton>
      </Dialog.Trigger>
      <Portal>
        <Dialog.Backdrop />
        <Dialog.Positioner>
          <Dialog.Content>
            <Dialog.Header>
              <Dialog.Title>{label}</Dialog.Title>
            </Dialog.Header>
            <Dialog.Body>
              <Text textStyle="sm">{body}</Text>
            </Dialog.Body>
            <Dialog.Footer>
              <Dialog.ActionTrigger asChild>
                <Button variant="outline" size="sm">
                  Cancel
                </Button>
              </Dialog.ActionTrigger>
              <Dialog.ActionTrigger asChild>
                <Button colorPalette="red" size="sm" onClick={onConfirm}>
                  {action}
                </Button>
              </Dialog.ActionTrigger>
            </Dialog.Footer>
          </Dialog.Content>
        </Dialog.Positioner>
      </Portal>
    </Dialog.Root>
  )
}

function NotifyStatus({ n }: { n: SystemInfo["notify"] }) {
  const test = useMutation({
    mutationFn: () => api.post("/notify/test"),
    onSuccess: () => toaster.create({ type: "success", title: "Test notification sent" }),
    onError: onError("Test notification failed"),
  })
  if (!n.enabled)
    return (
      <Text color="fg.muted">
        Off. Set <Code size="sm">LABWARDEN_NOTIFY_URL</Code> to get alerts about new findings.
      </Text>
    )
  return (
    <HStack gap="3" wrap="wrap">
      <Text>
        {n.format} webhook · new {n.min_severity}+{n.kev ? " or known exploited" : ""}
      </Text>
      <Button size="xs" variant="outline" loading={test.isPending} onClick={() => test.mutate()}>
        <LuBell /> Send test
      </Button>
    </HStack>
  )
}

function DBActions() {
  const qc = useQueryClient()
  const refresh = () => qc.invalidateQueries({ queryKey: ["system"] })
  const update = useMutation({
    mutationFn: () => api.post("/db/update"),
    onSuccess: () => {
      toaster.create({ type: "info", title: "DB update queued", description: "A newer DB re-matches every target." })
      refresh()
    },
    onError: onError("Could not queue the DB update"),
  })
  const rematch = useMutation({
    mutationFn: () => api.post("/rematch"),
    onSuccess: () => {
      toaster.create({ type: "info", title: "Re-match of all targets queued" })
      refresh()
    },
    onError: onError("Could not queue the re-match"),
  })
  return (
    <HStack gap="2" wrap="wrap" mt="1">
      <Button size="xs" variant="outline" loading={update.isPending} onClick={() => update.mutate()}>
        <LuDownload /> Update DB now
      </Button>
      <Button size="xs" variant="outline" loading={rematch.isPending} onClick={() => rematch.mutate()}>
        <LuRefreshCw /> Re-match all now
      </Button>
    </HStack>
  )
}

function SystemPanel() {
  const q = useQuery({ queryKey: ["system"], queryFn: () => api.get<SystemInfo>("/system"), refetchInterval: 15_000 })
  const s = q.data
  const logoutAll = useMutation({
    mutationFn: () => api.post("/auth/logout-all"),
    onSuccess: () => window.location.assign("/"),
    onError: onError("Could not sign out all sessions"),
  })
  return (
    <Panel title="System">
      {q.error && <ErrorBox error={q.error} />}
      {s && (
        <DataList.Root orientation="horizontal" size="sm">
          <DataList.Item>
            <DataList.ItemLabel>LabWarden</DataList.ItemLabel>
            <DataList.ItemValue>{s.version}</DataList.ItemValue>
          </DataList.Item>
          <DataList.Item>
            <DataList.ItemLabel>Authentication</DataList.ItemLabel>
            <DataList.ItemValue>
              {s.auth_enabled ? (
                <HStack gap="2" wrap="wrap">
                  <Badge colorPalette="green" variant="subtle" size="sm">
                    Password required
                  </Badge>
                  <Tooltip content="Ends every admin session, this one included">
                    <Button size="xs" variant="outline" loading={logoutAll.isPending} onClick={() => logoutAll.mutate()}>
                      <LuLogOut /> Sign out all sessions
                    </Button>
                  </Tooltip>
                </HStack>
              ) : (
                <Badge colorPalette="red" variant="subtle" size="sm">
                  Disabled: LABWARDEN_AUTH_DISABLED is set
                </Badge>
              )}
            </DataList.ItemValue>
          </DataList.Item>
          <DataList.Item>
            <DataList.ItemLabel>Central scanner</DataList.ItemLabel>
            <DataList.ItemValue>
              {s.scanner.available ? `grype ${s.scanner.grype_version}` : <Badge colorPalette="red">grype not found</Badge>}
            </DataList.ItemValue>
          </DataList.Item>
          <DataList.Item>
            <DataList.ItemLabel>Vulnerability DB</DataList.ItemLabel>
            <DataList.ItemValue>
              <Stack gap="0">
                <Text>{s.scanner.db_built ? `built ${ago(s.scanner.db_built)}` : "not downloaded yet"}</Text>
                {s.scanner.db_checked && (
                  <Text textStyle="xs" color="fg.muted">
                    schema {s.scanner.db_schema} · checked {ago(s.scanner.db_checked)}
                  </Text>
                )}
                <Text textStyle="xs" color="fg.muted">
                  next update {dateTime(s.queue.next_db_update)} · last re-match {ago(s.queue.last_rematch)}
                </Text>
                {s.scanner.db_error && (
                  <Text textStyle="xs" color="fg.error">
                    {s.scanner.db_error}
                  </Text>
                )}
                <DBActions />
              </Stack>
            </DataList.ItemValue>
          </DataList.Item>
          <DataList.Item>
            <DataList.ItemLabel>Queue</DataList.ItemLabel>
            <DataList.ItemValue>
              <Stack gap="0">
                <Text>
                  {s.queue.running || s.queue.queued
                    ? `${s.queue.running} running, ${s.queue.queued} queued`
                    : "idle"}
                  {s.scanner.running && ` · scanning ${s.scanner.running}`}
                </Text>
                {s.queue.rematching > 0 && (
                  <Text textStyle="xs" color="fg.muted">
                    {s.queue.rematching} re-matches against the current DB pending
                  </Text>
                )}
                {s.queue.failed_24h > 0 && (
                  <Text textStyle="xs" color="fg.error">
                    {s.queue.failed_24h} failed in the last 24 hours (see Logs)
                  </Text>
                )}
              </Stack>
            </DataList.ItemValue>
          </DataList.Item>
          <DataList.Item>
            <DataList.ItemLabel>Max report size</DataList.ItemLabel>
            <DataList.ItemValue>{s.max_report_mb} MB</DataList.ItemValue>
          </DataList.Item>
          <DataList.Item>
            <DataList.ItemLabel>Notifications</DataList.ItemLabel>
            <DataList.ItemValue>
              <NotifyStatus n={s.notify} />
            </DataList.ItemValue>
          </DataList.Item>
        </DataList.Root>
      )}
    </Panel>
  )
}

function CentralTargets() {
  const qc = useQueryClient()
  const [form, setForm] = useState({ ref: "", host_name: "registry", group: "images", interval_min: 1440 })
  const list = useQuery({ queryKey: ["central"], queryFn: () => api.get<CentralTarget[]>("/central-targets"), refetchInterval: 15_000 })
  const invalidate = () => qc.invalidateQueries({ queryKey: ["central"] })
  const add = useMutation({
    mutationFn: () => api.post("/central-targets", { ...form, ref: form.ref.trim(), interval_min: Number(form.interval_min) }),
    onSuccess: () => {
      toaster.create({ type: "success", title: "Image added; first scan queued" })
      setForm((f) => ({ ...f, ref: "" }))
      invalidate()
    },
    onError: onError("Could not add image"),
  })
  const toggle = useMutation({
    mutationFn: (t: CentralTarget) => api.patch(`/central-targets/${t.id}`, { enabled: !t.enabled }),
    onSuccess: invalidate,
    onError: onError("Update failed"),
  })
  const scan = useMutation({
    mutationFn: (id: number) => api.post(`/central-targets/${id}/scan`),
    onSuccess: () => {
      toaster.create({ type: "info", title: "Scan queued" })
      invalidate()
    },
    onError: onError("Could not queue scan"),
  })
  const del = useMutation({ mutationFn: (id: number) => api.del(`/central-targets/${id}`), onSuccess: invalidate, onError: onError("Delete failed") })

  return (
    <Panel title="Central registry scans" subtitle="Images the dashboard pulls from a registry and scans on a schedule. No agent needed.">
      <Stack gap="4">
        <HStack
          as="form"
          gap="2"
          align="end"
          wrap="wrap"
          onSubmit={(e) => {
            e.preventDefault()
            add.mutate()
          }}
        >
          <Field.Root flex="2" minW="64">
            <Field.Label textStyle="xs">Image reference</Field.Label>
            <Input size="sm" placeholder="nginx:1.25 or ghcr.io/org/app:tag" value={form.ref} onChange={(e) => setForm({ ...form, ref: e.currentTarget.value })} />
          </Field.Root>
          <Field.Root flex="1" minW="32">
            <Field.Label textStyle="xs">Shown under host</Field.Label>
            <Input size="sm" value={form.host_name} onChange={(e) => setForm({ ...form, host_name: e.currentTarget.value })} />
          </Field.Root>
          <Field.Root flex="1" minW="28">
            <Field.Label textStyle="xs">Group</Field.Label>
            <Input size="sm" value={form.group} onChange={(e) => setForm({ ...form, group: e.currentTarget.value })} />
          </Field.Root>
          <Field.Root w="28">
            <Field.Label textStyle="xs">Every (min)</Field.Label>
            <Input size="sm" type="number" min={15} value={form.interval_min} onChange={(e) => setForm({ ...form, interval_min: Number(e.currentTarget.value) })} />
          </Field.Root>
          <Button size="sm" type="submit" loading={add.isPending} disabled={!form.ref.trim()}>
            <LuPlus /> Add image
          </Button>
        </HStack>
        {list.error && <ErrorBox error={list.error} />}
        {list.data && list.data.length > 0 && (
          <DataTable minW="4xl">
            <Table.Header>
              <Table.Row>
                <Header>Image</Header>
                <Header>Host / group</Header>
                <Header>Interval</Header>
                <Header>Last run</Header>
                <Header>Enabled</Header>
                <Header />
              </Table.Row>
            </Table.Header>
            <Table.Body>
              {list.data.map((t) => (
                <Table.Row key={t.id}>
                  <Table.Cell>
                    <Mono>{t.ref}</Mono>
                  </Table.Cell>
                  <Table.Cell color="fg.muted">
                    {t.host_name} / {t.group}
                  </Table.Cell>
                  <Table.Cell color="fg.muted">{t.interval_min >= 60 && t.interval_min % 60 === 0 ? `${t.interval_min / 60}h` : `${t.interval_min}m`}</Table.Cell>
                  <Table.Cell>
                    <Stack gap="0">
                      <Text textStyle="sm">{ago(t.last_run)}</Text>
                      {t.last_status && (
                        <Tooltip content={t.last_status} disabled={t.last_status === "ok"}>
                          <Text textStyle="xs" color={t.last_status === "ok" ? "fg.success" : "fg.error"} truncate maxW="64">
                            {t.last_status}
                          </Text>
                        </Tooltip>
                      )}
                    </Stack>
                  </Table.Cell>
                  <Table.Cell>
                    <Switch.Root size="sm" checked={t.enabled} onCheckedChange={() => toggle.mutate(t)}>
                      <Switch.HiddenInput />
                      <Switch.Control />
                    </Switch.Root>
                  </Table.Cell>
                  <Table.Cell textAlign="end" whiteSpace="nowrap">
                    <Tooltip content="Scan now">
                      <IconButton size="xs" variant="ghost" aria-label="Scan now" onClick={() => scan.mutate(t.id)}>
                        <LuPlay />
                      </IconButton>
                    </Tooltip>
                    <ConfirmButton label={`Remove ${t.ref}?`} body="Already reported findings stay until you remove the host." action="Remove" onConfirm={() => del.mutate(t.id)} />
                  </Table.Cell>
                </Table.Row>
              ))}
            </Table.Body>
          </DataTable>
        )}
        <Text textStyle="xs" color="fg.muted">
          Private registries: mount Docker credentials into the dashboard container (see{" "}
          <CLink href="https://github.com/anchore/grype#private-registry-authentication" target="_blank" rel="noopener noreferrer">
            Grype registry auth
          </CLink>
          ).
        </Text>
      </Stack>
    </Panel>
  )
}
