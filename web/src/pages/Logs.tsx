import { keepPreviousData, useQuery } from "@tanstack/react-query"
import { Button, HStack, Switch, Text } from "@chakra-ui/react"
import { api, type EventRow, type List } from "@/lib/api"
import { useParamsState } from "@/lib/useParamsState"
import { ErrorBox, FilterBar, PageHeader, Pager, SearchInput, Select } from "@/components/common"
import { ClearFilters } from "@/components/filters"
import { EventTable, LevelBadge } from "@/components/tables"

const DEFAULTS = { sort: "ts", order: "desc", size: "50", live: "1" }
const LEVELS = ["error", "warn", "info", "debug"]
const FILTER_KEYS = ["q", "level", "source", "host", "run_id"]

export function LogsPage() {
  const ps = useParamsState(DEFAULTS)
  const levels = ps.getList("level")
  const live = ps.get("live") === "1"
  const params = {
    q: ps.get("q"),
    level: levels,
    source: ps.get("source"),
    host: ps.get("host"),
    run_id: ps.get("run_id"),
    page: ps.page,
    size: ps.size,
    sort: ps.sort,
    order: ps.order,
  }
  const q = useQuery({
    queryKey: ["events", params],
    queryFn: () => api.get<List<EventRow>>("/events", params),
    placeholderData: keepPreviousData,
    refetchInterval: live && ps.page === 1 ? 5_000 : false,
  })
  const toggle = (l: string) => ps.set({ level: levels.includes(l) ? levels.filter((x) => x !== l) : [...levels, l] })

  return (
    <>
      <PageHeader
        title="Logs"
        description="Agent runs, ingest results, central scans, triage changes and authentication events."
        actions={
          <Switch.Root size="sm" checked={live} onCheckedChange={(e) => ps.set({ live: e.checked ? "1" : "0", page: ps.page })}>
            <Switch.HiddenInput />
            <Switch.Control />
            <Switch.Label>Live</Switch.Label>
          </Switch.Root>
        }
      />
      <FilterBar>
        <SearchInput value={params.q} onChange={(v) => ps.set({ q: v })} placeholder="Search messages and hosts…" />
        <HStack gap="1" role="group" aria-label="Level filter">
          {LEVELS.map((l) => (
            <Button key={l} size="xs" variant={levels.includes(l) ? "subtle" : "ghost"} aria-pressed={levels.includes(l)} onClick={() => toggle(l)} px="1">
              <LevelBadge level={l} />
            </Button>
          ))}
        </HStack>
        <Select
          label="Source"
          value={params.source}
          onChange={(v) => ps.set({ source: v })}
          options={["agent", "ingest", "scanner", "triage", "auth", "system"]}
          placeholder="All sources"
          w="36"
        />
        {params.host && (
          <Button size="xs" variant="subtle" onClick={() => ps.set({ host: null })}>
            Host {params.host} ✕
          </Button>
        )}
        {params.run_id && (
          <Text textStyle="xs" color="fg.muted">
            Run <b>{params.run_id}</b>
          </Text>
        )}
        <ClearFilters show={FILTER_KEYS.some((k) => ps.sp.has(k))} onClear={() => ps.set(Object.fromEntries(FILTER_KEYS.map((k) => [k, null])))} />
      </FilterBar>
      {q.error && <ErrorBox error={q.error} />}
      <EventTable data={q.data} loading={q.isPending} ps={ps} onRun={(r) => ps.set({ run_id: r })} />
      <Pager total={q.data?.total ?? 0} page={ps.page} size={ps.size} onPage={(p) => ps.set({ page: p })} onSize={(s) => ps.set({ size: s })} />
    </>
  )
}
