import type { ReactNode } from "react"
import { Link } from "react-router"
import { keepPreviousData, useMutation, useQuery, useQueryClient } from "@tanstack/react-query"
import { Badge, Button, Clipboard, HStack, IconButton, Link as CLink, Stack, Table, Text } from "@chakra-ui/react"
import { LuCircleAlert, LuCircleArrowUp, LuCircleCheck, LuCircleDashed, LuContainer, LuHammer, LuPin, LuRefreshCw, LuSearchX } from "react-icons/lu"
import { api, ApiError, type ImageRow, type ImageStatus, type List, type SystemInfo } from "@/lib/api"
import { ago, dateTime, num } from "@/lib/format"
import { useParamsState } from "@/lib/useParamsState"
import { DataTable, Empty, ErrorBox, FilterBar, Header, LoadingRows, Mono, PageHeader, Pager, SearchInput, Select, SortHeader, Toolbar } from "@/components/common"
import { ClearFilters } from "@/components/filters"
import { toaster } from "@/components/ui/toaster"
import { Tooltip } from "@/components/ui/tooltip"

const DEFAULTS = { sort: "name", order: "asc", size: "25" }
const FILTER_KEYS = ["q", "host", "registry", "status"]
const COLS = 8

// Yellow, not orange, for "needs a look": orange on screen is the KEV
// diamond only. The palette-less statuses are quiet outlines.
const STATUS: Record<ImageStatus, { icon: ReactNode; label: string; hint: string; palette?: string }> = {
  outdated: { icon: <LuCircleArrowUp />, label: "Outdated", hint: "The tag points at a newer build upstream, or a newer version tag exists", palette: "yellow" },
  current: { icon: <LuCircleCheck />, label: "Up to date", hint: "The tag still points at this build upstream, and no newer version tag exists", palette: "green" },
  unchecked: {
    icon: <LuCircleDashed />,
    label: "Not checked",
    hint: "Not compared with upstream yet, or its registry is not on the allowlist (LABWARDEN_IMAGE_REGISTRIES)",
  },
  not_found: { icon: <LuSearchX />, label: "Not found upstream", hint: "The registry does not know this image, or it needs credentials" },
  error: { icon: <LuCircleAlert />, label: "Check failed", hint: "The registry could not be asked; the next check tries again", palette: "red" },
  pinned: { icon: <LuPin />, label: "Pinned", hint: "Started from a digest with no tag: it runs exactly that build" },
  local: { icon: <LuHammer />, label: "Local build", hint: "No registry digest: built on the host, or started from an image ID. There is no upstream to compare with" },
}

export function ImagesPage() {
  const ps = useParamsState(DEFAULTS)
  const filters = { q: ps.get("q"), host: ps.get("host"), registry: ps.get("registry"), status: ps.get("status") }
  const params = { ...filters, page: ps.page, size: ps.size, sort: ps.sort, order: ps.order }
  const system = useQuery({
    queryKey: ["system"],
    queryFn: () => api.get<SystemInfo>("/system"),
    refetchInterval: (q) => (q.state.data?.queue.image_checks ? 5_000 : 60_000),
  })
  const checking = (system.data?.queue.image_checks ?? 0) > 0
  const images = useQuery({
    // checking is in the key so the list is fetched once more when the last
    // check finishes, not left at the poll before it.
    queryKey: ["images", params, checking],
    queryFn: () => api.get<List<ImageRow>>("/images", params),
    placeholderData: keepPreviousData,
    // While checks run, their results arrive repository by repository.
    refetchInterval: checking ? 5_000 : false,
  })
  const hosts = useQuery({
    // Hosts that report containers, whatever their kind.
    queryKey: ["images", "hosts"],
    queryFn: () => api.get<{ id: number; name: string }[]>("/images/hosts"),
  })
  const registries = useQuery({ queryKey: ["images", "registries"], queryFn: () => api.get<string[]>("/images/registries") })
  const hasFilters = FILTER_KEYS.some((k) => ps.sp.has(k))
  const sh = { sort: ps.sort, order: ps.order, onSort: ps.toggleSort }
  const rows = images.data?.items

  return (
    <>
      <PageHeader
        description="The images your containers run, across every Docker host, and whether upstream has a newer build or version."
        actions={<CheckNow system={system.data} checking={checking} />}
      />
      <Toolbar>
        <SearchInput value={filters.q} onChange={(v) => ps.set({ q: v })} placeholder="Image, tag, container, host…" />
      </Toolbar>
      <FilterBar>
        <Select
          label="Host"
          value={filters.host}
          onChange={(v) => ps.set({ host: v })}
          options={(hosts.data ?? []).map((h): [string, string] => [String(h.id), h.name])}
          placeholder="All hosts"
        />
        <Select label="Registry" value={filters.registry} onChange={(v) => ps.set({ registry: v })} options={registries.data ?? []} placeholder="All registries" />
        <Select
          label="Status"
          value={filters.status}
          onChange={(v) => ps.set({ status: v })}
          options={Object.entries(STATUS).map(([k, s]): [string, string] => [k, s.label])}
          placeholder="Any status"
        />
        <ClearFilters show={hasFilters} onClear={() => ps.set(Object.fromEntries(FILTER_KEYS.map((k) => [k, null])))} />
      </FilterBar>

      {images.error && <ErrorBox error={images.error} />}
      <DataTable minW="6xl">
        <Table.Header>
          <Table.Row>
            <SortHeader label="Image" k="name" {...sh} />
            <SortHeader label="Tag" k="tag" {...sh} />
            <Header>Digest</Header>
            <SortHeader label="Hosts" k="hosts" {...sh} />
            <SortHeader label="Status" k="status" {...sh} />
            <Header>Newest</Header>
            <SortHeader label="Built" k="created" {...sh} />
            <SortHeader label="First seen" k="first_seen" {...sh} />
          </Table.Row>
        </Table.Header>
        <Table.Body>
          {images.isPending && <LoadingRows cols={COLS} />}
          {rows?.map((r) => (
            <Table.Row key={`${r.repository}|${r.tag}|${r.pinned_digest}|${r.digest || r.image_id}`}>
              <Table.Cell>
                <Stack gap="0" minW="0">
                  <Tooltip content={r.repository || r.name}>
                    <Text fontWeight="semibold" truncate maxW="60">
                      {r.name}
                    </Text>
                  </Tooltip>
                  <Text textStyle="xs" color="fg.muted">
                    {num(r.containers)} container{r.containers === 1 ? "" : "s"}
                  </Text>
                </Stack>
              </Table.Cell>
              <Table.Cell>{r.tag ? <Mono>{r.tag}</Mono> : <Text color="fg.muted">—</Text>}</Table.Cell>
              <Table.Cell>
                <DigestCell row={r} />
              </Table.Cell>
              <Table.Cell>
                <Stack gap="1">
                  {r.hosts.map((h) => (
                    <Tooltip key={h.id} content={`${h.name} · ${h.containers.join(", ")}`}>
                      <Text textStyle="sm" truncate maxW="56">
                        <CLink asChild fontWeight="medium">
                          <Link to={`/hosts/${h.id}`}>{h.name}</Link>
                        </CLink>
                        <Text as="span" color="fg.muted">
                          {" · "}
                          {h.containers.join(", ")}
                        </Text>
                      </Text>
                    </Tooltip>
                  ))}
                </Stack>
              </Table.Cell>
              <Table.Cell>
                <StatusCell row={r} />
              </Table.Cell>
              <Table.Cell>
                <NewestCell row={r} />
              </Table.Cell>
              <Table.Cell color="fg.muted" whiteSpace="nowrap">
                {r.image_created ? (
                  <Tooltip content={dateTime(r.image_created)}>
                    <span>{ago(r.image_created)}</span>
                  </Tooltip>
                ) : (
                  <Tooltip content="The image carries no build date (reproducible builds stamp 1970)">
                    <span>unknown</span>
                  </Tooltip>
                )}
              </Table.Cell>
              <Table.Cell color="fg.muted" whiteSpace="nowrap">
                <Tooltip content={dateTime(r.first_seen)}>
                  <span>{ago(r.first_seen)}</span>
                </Tooltip>
              </Table.Cell>
            </Table.Row>
          ))}
          {rows && rows.length === 0 && (
            <Table.Row>
              <Table.Cell colSpan={COLS}>
                {hasFilters ? (
                  <Empty icon={<LuContainer />} title="No images match" description="Loosen the filters." />
                ) : (
                  <Empty
                    icon={<LuContainer />}
                    title="No running containers reported yet"
                    description="Docker agents from version 3.1 list their running containers at the end of each run."
                  />
                )}
              </Table.Cell>
            </Table.Row>
          )}
        </Table.Body>
      </DataTable>
      <Pager total={images.data?.total ?? 0} page={ps.page} size={ps.size} onPage={(p) => ps.set({ page: p })} onSize={(s) => ps.set({ size: s })} />
    </>
  )
}

function ImageStatusBadge({ status, checked }: { status: ImageStatus; checked?: string }) {
  const s = STATUS[status] ?? STATUS.unchecked
  return (
    <Tooltip content={checked ? `${s.hint}. Checked ${ago(checked)}.` : s.hint}>
      {s.palette ? (
        <Badge colorPalette={s.palette} variant="subtle" size="sm" gap="1">
          {s.icon}
          {s.label}
        </Badge>
      ) : (
        <Badge variant="outline" size="sm" gap="1" color="fg.muted">
          {s.icon}
          {s.label}
        </Badge>
      )}
    </Tooltip>
  )
}

const DAY = 86_400_000

// Whole days from iso until now; undefined when unknown.
function daysSince(iso?: string): number | undefined {
  const t = iso ? Date.parse(iso) : NaN
  return Number.isNaN(t) ? undefined : Math.max(0, Math.floor((Date.now() - t) / DAY))
}

const plural = (n: number, word: string) => `${n} ${word}${n === 1 ? "" : "s"}`

// The badge, what kind of update is upstream, how old the running build is,
// and why the last check did not finish.
function StatusCell({ row }: { row: ImageRow }) {
  const built = row.status === "outdated" ? daysSince(row.image_created) : undefined
  const waiting = row.status === "outdated" ? daysSince(row.update_since) : undefined
  const age = [
    built !== undefined && `running build ${plural(built, "day")} old`,
    // Under a day old it says nothing the badge does not: every row looks like that right after the first check.
    !!waiting && `update available for ${plural(waiting, "day")}`,
  ]
    .filter(Boolean)
    .join(" · ")
  return (
    <Stack gap="1" align="start" w="48">
      <HStack gap="1" wrap="wrap">
        <ImageStatusBadge status={row.status} checked={row.checked_at} />
        {row.drift && (
          <Tooltip content={`The tag ${row.tag} now points at ${row.upstream_digest}`}>
            <Badge variant="outline" size="sm">
              New build
            </Badge>
          </Tooltip>
        )}
      </HStack>
      {age && (
        <Tooltip content={[row.image_created && `Built ${dateTime(row.image_created)}`, row.update_since && `Update seen ${dateTime(row.update_since)}`].filter(Boolean).join(" · ")}>
          <Text textStyle="xs" color="fg.muted" whiteSpace="normal">
            {age[0].toUpperCase() + age.slice(1)}
          </Text>
        </Tooltip>
      )}
      {row.check_error && (
        <Tooltip content={row.check_error}>
          <Text textStyle="xs" color="fg.muted" truncate maxW="60">
            Last check: {row.check_error}
          </Text>
        </Tooltip>
      )}
    </Stack>
  )
}

// The newest version tag in the running major first: usually the safe
// update. A newer major is named apart.
function NewestCell({ row }: { row: ImageRow }) {
  const major = row.newest_tag && row.newest_tag !== row.newest_in_major ? row.newest_tag : ""
  if (!row.newest_in_major && !major)
    return (
      <Text as="span" color="fg.subtle">
        —
      </Text>
    )
  return (
    <Stack gap="0">
      {row.newest_in_major && <Mono>{row.newest_in_major}</Mono>}
      {major && (
        <Text textStyle="xs" color="fg.muted" whiteSpace="nowrap">
          <Mono>{major}</Mono> new major
        </Text>
      )}
    </Stack>
  )
}

// Queues a check of every running image. Each repository is one tag list and
// one HEAD per running tag; Docker Hub does not count HEADs as pulls.
function CheckNow({ system, checking }: { system?: SystemInfo; checking: boolean }) {
  const qc = useQueryClient()
  const ic = system?.image_check
  const check = useMutation({
    mutationFn: () => api.post("/images/check"),
    onSuccess: () => toaster.create({ type: "info", title: "Image check queued", description: "Results arrive image by image." }),
    onError: (e) =>
      e instanceof ApiError && e.status === 409
        ? toaster.create({ type: "info", title: "An image check is already queued" })
        : toaster.create({ type: "error", title: "Could not queue the image check", description: (e as Error).message }),
    onSettled: () => qc.invalidateQueries({ queryKey: ["system"] }),
  })
  if (!ic) return null
  if (!ic.enabled)
    return (
      <Text textStyle="xs" color="fg.muted">
        Update checks are off (LABWARDEN_IMAGE_CHECK=false)
      </Text>
    )
  return (
    <>
      <Text textStyle="xs" color="fg.muted" whiteSpace="nowrap">
        {checking ? "Checking…" : `Last check ${ago(ic.last_checked)}`}
      </Text>
      <Button size="xs" variant="outline" loading={check.isPending} disabled={checking} onClick={() => check.mutate()}>
        <LuRefreshCw /> Check now
      </Button>
    </>
  )
}

const short = (d: string) => d.replace(/^sha256:/, "").slice(0, 12)

// The registry digest the image was pulled at, or, for a local build, its
// image ID (muted: it means nothing outside that host).
function DigestCell({ row }: { row: ImageRow }) {
  const value = row.digest || row.image_id
  const hint = row.digest ? value : `Image ID ${value}: not pulled from a registry`
  return (
    <HStack gap="1">
      <Tooltip content={hint}>
        <span>
          <Mono color={row.digest ? undefined : "fg.muted"}>{short(value)}</Mono>
        </span>
      </Tooltip>
      <Clipboard.Root value={value}>
        <Clipboard.Trigger asChild>
          <IconButton size="2xs" variant="ghost" color="fg.muted" aria-label={row.digest ? "Copy digest" : "Copy image ID"}>
            <Clipboard.Indicator />
          </IconButton>
        </Clipboard.Trigger>
      </Clipboard.Root>
    </HStack>
  )
}
