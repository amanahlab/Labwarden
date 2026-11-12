import { keepPreviousData, useQuery } from "@tanstack/react-query"
import { api, type List, type ScanRow } from "@/lib/api"
import { useParamsState } from "@/lib/useParamsState"
import { ErrorBox, FilterBar, PageHeader, Pager, SearchInput, Select } from "@/components/common"
import { ScanTable } from "@/components/tables"

const DEFAULTS = { size: "25" }

export function ScansPage() {
  const ps = useParamsState(DEFAULTS)
  const params = { q: ps.get("q"), source: ps.get("source"), page: ps.page, size: ps.size }
  const q = useQuery({ queryKey: ["scans", params], queryFn: () => api.get<List<ScanRow>>("/scans", params), placeholderData: keepPreviousData, refetchInterval: 30_000 })
  return (
    <>
      <PageHeader description="Every Grype report received, newest first, with the change against the previous scan of the same target." />
      <FilterBar>
        <SearchInput value={params.q} onChange={(v) => ps.set({ q: v })} placeholder="Host or target…" />
        <Select
          label="Source"
          value={params.source}
          onChange={(v) => ps.set({ source: v })}
          options={[
            ["agent", "Agent"],
            ["server", "Central scanner"],
          ]}
          placeholder="All sources"
        />
      </FilterBar>
      {q.error && <ErrorBox error={q.error} />}
      <ScanTable data={q.data} loading={q.isPending} />
      <Pager total={q.data?.total ?? 0} page={ps.page} size={ps.size} onPage={(p) => ps.set({ page: p })} onSize={(s) => ps.set({ size: s })} />
    </>
  )
}
