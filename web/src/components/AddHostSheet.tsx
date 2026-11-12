import { useState } from "react"
import { Link } from "react-router"
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query"
import { Alert, Box, Button, Center, Clipboard, Code, Field, HStack, Input, Link as CLink, RadioCard, SimpleGrid, Spinner, Stack, Steps, Text } from "@chakra-ui/react"
import { LuArrowLeft, LuArrowRight, LuBox, LuCircleCheck, LuLayers, LuMonitor } from "react-icons/lu"
import { api, type AgentCredential, type SystemInfo, type Token } from "@/lib/api"
import { agentSnippets, TTL_OPTIONS, type AgentKind } from "@/lib/agent"
import { useSheet } from "@/lib/useSheet"
import { CodeBlock, Select, Step } from "@/components/common"
import { Sheet, SheetBody, SheetFooter } from "@/components/Sheet"
import { toaster } from "@/components/ui/toaster"

const KINDS: { value: AgentKind; label: string; description: string; icon: typeof LuMonitor }[] = [
  { value: "vm", label: "Linux VM or server", description: "An installer sets up Syft, the agent and a systemd timer. Scans the packages on the machine.", icon: LuMonitor },
  { value: "docker", label: "Docker host", description: "One container. Scans the image of every running container through the Docker socket.", icon: LuBox },
  { value: "compose", label: "Docker Compose", description: "The same agent behind a read-only socket proxy, so it never holds the socket itself.", icon: LuLayers },
]

const STEPS = ["Kind", "Token", "Install"]

// Opens from ?sheet=add-host on any page (mounted once, in Layout).
export function AddHostSheet() {
  const sheet = useSheet("add-host")
  return (
    <Sheet open={sheet.open} onClose={sheet.hide} title="Add a host" description="The agent reports what is installed on a machine. This dashboard finds the vulnerabilities in it.">
      <Wizard onDone={sheet.hide} />
    </Sheet>
  )
}

function Wizard({ onDone }: { onDone: () => void }) {
  const qc = useQueryClient()
  const [step, setStep] = useState(0)
  const [kind, setKind] = useState<AgentKind>("vm")
  const [name, setName] = useState("")
  const [ttl, setTTL] = useState("24")
  const [maxUses, setMaxUses] = useState("1")
  // The token value is held here only: it is gone once the sheet closes.
  const [token, setToken] = useState<{ name: string; value: string } | null>(null)
  const sys = useQuery({ queryKey: ["system"], queryFn: () => api.get<SystemInfo>("/system") })
  const create = useMutation({
    mutationFn: () => api.post<{ token: Token; value: string }>("/tokens", { name: name.trim(), ttl_hours: Number(ttl), max_uses: Number(maxUses) || 0 }),
    onSuccess: (r) => {
      setToken({ name: r.token.name, value: r.value })
      qc.invalidateQueries({ queryKey: ["tokens"] })
    },
    onError: (e) => toaster.create({ type: "error", title: "Could not create token", description: (e as Error).message }),
  })

  // A host that enrolls while the sheet is open has a credential that was not
  // there when it opened.
  const before = useQuery({ queryKey: ["agent-credentials", "before-add-host"], queryFn: () => api.get<AgentCredential[]>("/agent-credentials"), staleTime: Infinity, gcTime: 0 })
  const current = useQuery({
    queryKey: ["agent-credentials"],
    queryFn: () => api.get<AgentCredential[]>("/agent-credentials"),
    refetchInterval: 5000,
    enabled: step === 2 && !!before.data,
  })
  const known = new Set(before.data?.map((c) => c.id))
  const enrolled = before.data && current.data ? current.data.filter((c) => !known.has(c.id)) : []

  const chosen = KINDS.find((k) => k.value === kind) ?? KINDS[0]
  const snippet = agentSnippets({ sha256: sys.data?.install_sha256, token: token?.value })[kind]

  return (
    <>
      <SheetBody>
        <Steps.Root step={step} onStepChange={(e) => setStep(e.step)} count={STEPS.length} size="sm" gap="6">
          <Steps.List>
            {STEPS.map((label, i) => (
              <Steps.Item key={label} index={i} title={label}>
                <Steps.Trigger>
                  <Steps.Indicator />
                  <Steps.Title>{label}</Steps.Title>
                </Steps.Trigger>
                <Steps.Separator />
              </Steps.Item>
            ))}
          </Steps.List>

          <Steps.Content index={0}>
            <Stack gap="4">
              <RadioCard.Root value={kind} onValueChange={(e) => e.value && setKind(e.value as AgentKind)} variant="outline" size="sm">
                <RadioCard.Label>What are you connecting?</RadioCard.Label>
                <Stack gap="2">
                  {KINDS.map((k) => (
                    <RadioCard.Item key={k.value} value={k.value} _checked={{ bg: "bg.muted" }}>
                      <RadioCard.ItemHiddenInput />
                      <RadioCard.ItemControl alignItems="center">
                        <Center boxSize="9" rounded="l2" bg="bg.emphasized" color="fg.muted" flexShrink={0} aria-hidden="true">
                          <k.icon size={18} />
                        </Center>
                        <RadioCard.ItemContent>
                          <RadioCard.ItemText>{k.label}</RadioCard.ItemText>
                          <RadioCard.ItemDescription>{k.description}</RadioCard.ItemDescription>
                        </RadioCard.ItemContent>
                        <RadioCard.ItemIndicator />
                      </RadioCard.ItemControl>
                    </RadioCard.Item>
                  ))}
                </Stack>
              </RadioCard.Root>
              <Text textStyle="sm" color="fg.muted">
                No machine to install on? The dashboard can pull an image from a registry and scan it itself:{" "}
                <CLink asChild>
                  <Link to="/settings?sheet=add-image">add a registry image</Link>
                </CLink>
                .
              </Text>
            </Stack>
          </Steps.Content>

          <Steps.Content index={1}>
            {token ? (
              <Stack gap="4">
                <Alert.Root status="success" size="sm">
                  <Alert.Indicator />
                  <Alert.Content>
                    <Alert.Title>Token “{token.name}” created</Alert.Title>
                    <Alert.Description>It is filled into the commands of the next step. It will not be shown again once this panel closes.</Alert.Description>
                  </Alert.Content>
                </Alert.Root>
                <Clipboard.Root value={token.value}>
                  <HStack>
                    <Input readOnly value={token.value} fontFamily="mono" size="sm" aria-label="Enrollment token" onFocus={(e) => e.currentTarget.select()} />
                    <Clipboard.Trigger asChild>
                      <Button size="sm" variant="outline">
                        <Clipboard.Indicator />
                        <Clipboard.CopyText />
                      </Button>
                    </Clipboard.Trigger>
                  </HStack>
                </Clipboard.Root>
              </Stack>
            ) : (
              <Stack
                as="form"
                id="add-host-token"
                gap="4"
                onSubmit={(e) => {
                  e.preventDefault()
                  if (name.trim()) create.mutate()
                }}
              >
                <Text textStyle="sm" color="fg.muted">
                  The agent uses an enrollment token once, to get a credential of its own for this host. Keep the token short-lived: only its SHA-256 hash
                  is stored here.
                </Text>
                <Field.Root required>
                  <Field.Label>Token name</Field.Label>
                  <Input size="sm" placeholder="e.g. nas-01 enrollment" value={name} maxLength={64} onChange={(e) => setName(e.currentTarget.value)} />
                </Field.Root>
                <SimpleGrid columns={2} gap="3">
                  <Field.Root>
                    <Field.Label>Expiry</Field.Label>
                    <Select label="Expiry" value={ttl} onChange={setTTL} options={TTL_OPTIONS} w="full" />
                  </Field.Root>
                  <Field.Root>
                    <Field.Label>Hosts it may enroll</Field.Label>
                    <Input size="sm" type="number" min={0} max={10000} placeholder="No limit" value={maxUses} onChange={(e) => setMaxUses(e.currentTarget.value)} />
                  </Field.Root>
                </SimpleGrid>
                <Text textStyle="sm" color="fg.muted">
                  Already have a token?{" "}
                  <CLink asChild>
                    <button type="button" onClick={() => setStep(2)}>
                      Skip this step
                    </button>
                  </CLink>{" "}
                  and paste it into the commands yourself.
                </Text>
              </Stack>
            )}
          </Steps.Content>

          <Steps.Content index={2}>
            <Stack gap="4">
              {!token && (
                <Alert.Root status="info" size="sm">
                  <Alert.Indicator />
                  <Alert.Title>
                    Replace <Code size="sm">&lt;token&gt;</Code> with your enrollment token.
                  </Alert.Title>
                </Alert.Root>
              )}
              {kind === "vm" && (
                <>
                  <Step n={1} title="Download the installer, check it and run it as root">
                    <CodeBlock code={snippet} />
                    <Text textStyle="xs" color="fg.muted">
                      The checksum is of this dashboard's installer, which in turn checks Syft and the agent script. The timer runs every 6 hours (cron
                      without systemd) and the first scan starts right away.
                    </Text>
                  </Step>
                  <Step n={2} title="Check progress">
                    <CodeBlock code={"journalctl -u labwarden-agent -f      # systemd\ntail -f /var/log/labwarden-agent.log  # cron"} />
                  </Step>
                </>
              )}
              {kind === "docker" && (
                <>
                  <Text textStyle="sm" color="fg.muted">
                    Run this on the Docker host. The socket is root-equivalent even when mounted <Code size="sm">:ro</Code>; the Docker Compose kind puts a
                    read-only proxy in between.
                  </Text>
                  <CodeBlock code={snippet} />
                </>
              )}
              {kind === "compose" && (
                <>
                  <Text textStyle="sm" color="fg.muted">
                    Add these services to a Compose file on the Docker host, set <Code size="sm">LABWARDEN_HOST</Code> and run{" "}
                    <Code size="sm">docker compose up -d</Code>.
                  </Text>
                  <CodeBlock code={snippet} />
                </>
              )}
              {/* Steps keeps every panel mounted: the spinner belongs to this step only. */}
              {step === 2 && (
                <HStack gap="3" p="3" borderWidth="1px" rounded="l2" role="status">
                  {enrolled.length > 0 ? (
                    <Box color="fg.success" flexShrink={0}>
                      <LuCircleCheck size={18} />
                    </Box>
                  ) : (
                    <Spinner size="sm" color="fg.muted" flexShrink={0} />
                  )}
                  {enrolled.length > 0 ? (
                    <Text textStyle="sm">
                      <b>{enrolled.map((c) => c.host).join(", ")}</b> enrolled. Findings arrive after the first scan.{" "}
                      <CLink asChild>
                        <Link to={`/hosts?q=${encodeURIComponent(enrolled[0].host)}`}>Show host</Link>
                      </CLink>
                    </Text>
                  ) : (
                    <Text textStyle="sm" color="fg.muted">
                      Waiting for the host to enroll. This panel notices on its own.
                    </Text>
                  )}
                </HStack>
              )}
              <Text textStyle="xs" color="fg.muted">
                All agent options and how it works:{" "}
                <CLink asChild>
                  <Link to="/settings">Settings</Link>
                </CLink>
                .
              </Text>
            </Stack>
          </Steps.Content>
        </Steps.Root>
      </SheetBody>
      <SheetFooter
        summary={
          <Text truncate>
            {chosen.label}
            {token && ` · token “${token.name}”`}
          </Text>
        }
      >
        {step > 0 && (
          <Button size="sm" variant="outline" onClick={() => setStep(step - 1)}>
            <LuArrowLeft /> Back
          </Button>
        )}
        {step === 1 && !token ? (
          <Button size="sm" type="submit" form="add-host-token" loading={create.isPending} disabled={!name.trim()}>
            Create token
          </Button>
        ) : step < 2 ? (
          <Button size="sm" onClick={() => setStep(step + 1)}>
            Next <LuArrowRight />
          </Button>
        ) : (
          <Button size="sm" onClick={onDone}>
            Done
          </Button>
        )}
      </SheetFooter>
    </>
  )
}
