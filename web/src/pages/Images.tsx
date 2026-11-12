import type { ReactNode } from "react"
import { Link } from "react-router"
import { keepPreviousData, useQuery } from "@tanstack/react-query"
import { Badge, Clipboard, HStack, IconButton, Link as CLink, Stack, Table, Text } from "@chakra-ui/react"
import { LuCircleDashed, LuContainer, LuHammer, LuPin } from "react-icons/lu"
import { api, type ImageRow, type ImageStatus, type List } from "@/lib/api"
import { ago, dateTime, num } from "@/lib/format"
import { useParamsState } from "@/lib/useParamsState"
import { DataTable, Empty, ErrorBox, FilterBar, Header, LoadingRows, Mono, PageHeader, Pager, SearchInput, Select, SortHeader, Toolbar } from "@/components/common"
import { ClearFilters } from "@/components/filters"
import { Tooltip } from "@/components/ui/tooltip"

const DEFAULTS = { sort: "name", order: "asc", size: "25" }
const FILTER_KEYS = ["q", "host", "registry", "status"]
const COLS = 7

const STATUS: Record<ImageStatus, { icon: ReactNode; label: string; hint: string }> = {
  unchecked: { icon: <LuCircleDashed />, label: "Not checked", hint: "Pulled from a registry; not compared with upstream yet" },
  pinned: { icon: <LuPin />, label: "Pinned", hint: "Started from a digest with no tag: it runs exactly that build" },
  local: { icon: <LuHammer />, label: "Local build", hint: "No registry digest: built on the host, or started from an image ID. There is no upstream to compare with" },
}

export function ImagesPage() {
  const ps = useParamsState(DEFAULTS)
  const filters = { q: ps.get("q"), host: ps.get("host"), registry: ps.get("registry"), status: ps.get("status") }
  const params = { ...filters, page: ps.page, size: ps.size, sort: ps.sort, order: ps.order }
  const images = useQuery({
    queryKey: ["images", params],
    queryFn: () => api.get<List<ImageRow>>("/images", params),
    placeholderData: keepPreviousData,
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
      <PageHeader description="The images your containers run, across every Docker host, with the digest each one was pulled at." />
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
      <DataTable minW="5xl">
        <Table.Header>
          <Table.Row>
            <SortHeader label="Image" k="name" {...sh} />
            <SortHeader label="Tag" k="tag" {...sh} />
            <Header>Digest</Header>
            <SortHeader label="Hosts" k="hosts" {...sh} />
            <SortHeader label="Status" k="status" {...sh} />
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
                    <Text fontWeight="semibold" truncate maxW="72">
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
                      <Text textStyle="sm" truncate maxW="72">
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
                <ImageStatusBadge status={r.status} />
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

function ImageStatusBadge({ status }: { status: ImageStatus }) {
  const s = STATUS[status] ?? STATUS.unchecked
  return (
    <Tooltip content={s.hint}>
      <Badge variant="outline" size="sm" gap="1" color="fg.muted">
        {s.icon}
        {s.label}
      </Badge>
    </Tooltip>
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
