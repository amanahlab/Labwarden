import { useEffect, useState, type ReactNode } from "react"
import {
  Alert,
  Badge,
  Box,
  ButtonGroup,
  Card,
  EmptyState,
  Flex,
  HStack,
  Heading,
  IconButton,
  Input,
  InputGroup,
  NativeSelect,
  Pagination,
  Skeleton,
  Stack,
  Table,
  Text,
} from "@chakra-ui/react"
import {
  LuArrowDown,
  LuArrowUp,
  LuArrowUpDown,
  LuChevronLeft,
  LuChevronRight,
  LuCircleCheck,
  LuCircleAlert,
  LuClock,
  LuEyeOff,
  LuFlame,
  LuInbox,
  LuSearch,
  LuShieldCheck,
  LuEye,
  LuBan,
} from "react-icons/lu"
import { Tooltip } from "@/components/ui/tooltip"
import { SEVERITY_COLORS } from "@/theme"
import type { Counts, HostStatus, Severity, TriageStatus } from "@/lib/api"
import { num, statusLabel } from "@/lib/format"

export function PageHeader(props: { title: string; description?: ReactNode; actions?: ReactNode }) {
  return (
    <Flex align={{ base: "start", md: "center" }} justify="space-between" gap="4" mb="6" direction={{ base: "column", md: "row" }}>
      <Box>
        <Heading size="xl" letterSpacing="-0.01em">
          {props.title}
        </Heading>
        {props.description && (
          <Text color="fg.muted" textStyle="sm" mt="1">
            {props.description}
          </Text>
        )}
      </Box>
      {props.actions && <HStack gap="2">{props.actions}</HStack>}
    </Flex>
  )
}

export function Panel(props: { title?: ReactNode; subtitle?: ReactNode; actions?: ReactNode; children: ReactNode; p?: string; minH?: string }) {
  return (
    <Card.Root variant="outline" bg="surface" size="sm" minH={props.minH}>
      {(props.title || props.actions) && (
        <Card.Header pb="0">
          <Flex justify="space-between" align="start" gap="3">
            <Box>
              <Card.Title textStyle="sm" fontWeight="semibold">
                {props.title}
              </Card.Title>
              {props.subtitle && (
                <Text textStyle="xs" color="fg.muted" mt="0.5">
                  {props.subtitle}
                </Text>
              )}
            </Box>
            {props.actions}
          </Flex>
        </Card.Header>
      )}
      <Card.Body p={props.p}>{props.children}</Card.Body>
    </Card.Root>
  )
}

export function SevDot({ severity, size = "2.5" }: { severity: Severity; size?: string }) {
  return <Box w={size} h={size} rounded="full" flexShrink={0} bg={SEVERITY_COLORS[severity] ?? SEVERITY_COLORS.Unknown} />
}

// Severity is never color-only: dot + text label.
export function SeverityBadge({ severity }: { severity: Severity }) {
  return (
    <HStack gap="1.5" display="inline-flex" whiteSpace="nowrap">
      <SevDot severity={severity} />
      <Text as="span" textStyle="sm" fontWeight={severity === "Critical" || severity === "High" ? "semibold" : "normal"}>
        {severity}
      </Text>
    </HStack>
  )
}

export function KevBadge() {
  return (
    <Tooltip content="Listed in CISA Known Exploited Vulnerabilities">
      <Badge colorPalette="red" variant="solid" size="sm" gap="1">
        <LuFlame /> KEV
      </Badge>
    </Tooltip>
  )
}

const SEV_KEYS: [keyof Counts, Severity][] = [
  ["critical", "Critical"],
  ["high", "High"],
  ["medium", "Medium"],
  ["low", "Low"],
]

// Compact per-severity counts: a stacked bar (2px gaps) plus labelled numbers.
export function SeverityCounts({ counts, showBar = true }: { counts: Counts; showBar?: boolean }) {
  const total = SEV_KEYS.reduce((a, [k]) => a + (counts[k] as number), 0)
  return (
    <Stack gap="1" minW="40">
      <HStack gap="3" textStyle="xs" fontVariantNumeric="tabular-nums">
        {SEV_KEYS.map(([k, s]) => (
          <Tooltip key={k} content={`${num(counts[k] as number)} ${s}`}>
            <HStack gap="1" color={(counts[k] as number) ? "fg" : "fg.subtle"}>
              <SevDot severity={s} size="2" />
              <Text as="span">{num(counts[k] as number)}</Text>
              <Text as="span" color="fg.muted" srOnly>
                {s}
              </Text>
            </HStack>
          </Tooltip>
        ))}
      </HStack>
      {showBar && total > 0 && (
        <HStack gap="2px" h="1.5" w="full">
          {SEV_KEYS.filter(([k]) => (counts[k] as number) > 0).map(([k, s]) => (
            <Box key={k} h="full" rounded="sm" bg={SEVERITY_COLORS[s]} flexGrow={counts[k] as number} flexBasis="0" minW="2px" />
          ))}
        </HStack>
      )}
    </Stack>
  )
}

const TRIAGE: Record<TriageStatus, { palette: string; icon: ReactNode }> = {
  open: { palette: "orange", icon: <LuCircleAlert /> },
  acknowledged: { palette: "blue", icon: <LuEye /> },
  ignored: { palette: "gray", icon: <LuEyeOff /> },
  false_positive: { palette: "gray", icon: <LuBan /> },
}

export function TriageBadge({ status }: { status: TriageStatus }) {
  const t = TRIAGE[status] ?? TRIAGE.open
  return (
    <Badge colorPalette={t.palette} variant="subtle" size="sm" gap="1">
      {t.icon}
      {statusLabel(status)}
    </Badge>
  )
}

const HOST_STATUS: Record<HostStatus, { palette: string; icon: ReactNode; label: string; hint: string }> = {
  ok: { palette: "green", icon: <LuCircleCheck />, label: "Healthy", hint: "Reporting on schedule" },
  stale: { palette: "yellow", icon: <LuClock />, label: "Stale", hint: "No report within 2.5× its scan interval" },
  failing: { palette: "red", icon: <LuCircleAlert />, label: "Failing", hint: "Last scan run reported an error" },
}

export function HostStatusBadge({ status }: { status: HostStatus }) {
  const s = HOST_STATUS[status] ?? HOST_STATUS.ok
  return (
    <Tooltip content={s.hint}>
      <Badge colorPalette={s.palette} variant="subtle" size="sm" gap="1">
        {s.icon}
        {s.label}
      </Badge>
    </Tooltip>
  )
}

export function FixBadge({ state, versions }: { state: string; versions?: string }) {
  if (state === "fixed")
    return (
      <Tooltip content={versions ? `Fixed in ${versions}` : "A fix is available"} disabled={!versions}>
        <Badge colorPalette="green" variant="subtle" size="sm" gap="1">
          <LuShieldCheck />
          {versions ? versions.split(",")[0] : "Fix available"}
        </Badge>
      </Tooltip>
    )
  const label = state === "not-fixed" ? "No fix" : state === "wont-fix" ? "Won't fix" : "Unknown"
  return (
    <Badge variant="outline" size="sm" color="fg.muted">
      {label}
    </Badge>
  )
}

export function SortHeader(props: {
  label: ReactNode
  k: string
  sort: string
  order: string
  onSort: (k: string) => void
  textAlign?: "start" | "end"
  w?: string
}) {
  const active = props.sort === props.k
  const Icon = !active ? LuArrowUpDown : props.order === "asc" ? LuArrowUp : LuArrowDown
  return (
    <Table.ColumnHeader
      w={props.w}
      textAlign={props.textAlign}
      cursor="pointer"
      userSelect="none"
      onClick={() => props.onSort(props.k)}
      aria-sort={active ? (props.order === "asc" ? "ascending" : "descending") : "none"}
      _hover={{ color: "fg" }}
      color={active ? "fg" : "fg.muted"}
      whiteSpace="nowrap"
    >
      <HStack gap="1" display="inline-flex">
        {props.label}
        <Box as={Icon} opacity={active ? 1 : 0.4} boxSize="3" />
      </HStack>
    </Table.ColumnHeader>
  )
}

export function Header({ children, ...rest }: { children?: ReactNode; textAlign?: "start" | "end"; w?: string }) {
  return (
    <Table.ColumnHeader color="fg.muted" whiteSpace="nowrap" {...rest}>
      {children}
    </Table.ColumnHeader>
  )
}

export function Pager(props: { total: number; page: number; size: number; onPage: (p: number) => void; onSize?: (s: number) => void }) {
  const { total, page, size } = props
  const from = total === 0 ? 0 : (page - 1) * size + 1
  const to = Math.min(total, page * size)
  return (
    <Flex justify="space-between" align="center" gap="3" pt="3" wrap="wrap">
      <HStack gap="3">
        <Text textStyle="sm" color="fg.muted" fontVariantNumeric="tabular-nums">
          {num(from)}–{num(to)} of {num(total)}
        </Text>
        {props.onSize && (
          <NativeSelect.Root size="xs" w="24">
            <NativeSelect.Field value={size} onChange={(e) => props.onSize!(Number(e.currentTarget.value))} aria-label="Rows per page">
              {[10, 25, 50, 100].map((n) => (
                <option key={n} value={n}>
                  {n} / page
                </option>
              ))}
            </NativeSelect.Field>
            <NativeSelect.Indicator />
          </NativeSelect.Root>
        )}
      </HStack>
      {total > size && (
        <Pagination.Root count={total} pageSize={size} page={page} siblingCount={1} onPageChange={(e) => props.onPage(e.page)}>
          <ButtonGroup variant="ghost" size="xs" attached={false}>
            <Pagination.PrevTrigger asChild>
              <IconButton aria-label="Previous page">
                <LuChevronLeft />
              </IconButton>
            </Pagination.PrevTrigger>
            <Pagination.Items
              render={(p) => (
                <IconButton variant={{ base: "ghost", _selected: "outline" }} aria-label={`Page ${p.value}`}>
                  {p.value}
                </IconButton>
              )}
            />
            <Pagination.NextTrigger asChild>
              <IconButton aria-label="Next page">
                <LuChevronRight />
              </IconButton>
            </Pagination.NextTrigger>
          </ButtonGroup>
        </Pagination.Root>
      )}
    </Flex>
  )
}

// Search box that commits after the user pauses typing.
export function SearchInput(props: { value: string; onChange: (v: string) => void; placeholder?: string; w?: object | string }) {
  const [v, setV] = useState(props.value)
  useEffect(() => setV(props.value), [props.value])
  useEffect(() => {
    if (v === props.value) return
    const t = setTimeout(() => props.onChange(v), 300)
    return () => clearTimeout(t)
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [v])
  return (
    <InputGroup startElement={<LuSearch />} w={props.w ?? { base: "full", md: "72" }}>
      <Input size="sm" bg="surface" value={v} placeholder={props.placeholder ?? "Search…"} onChange={(e) => setV(e.currentTarget.value)} />
    </InputGroup>
  )
}

export function Select(props: {
  value: string
  onChange: (v: string) => void
  options: (string | [string, string])[]
  placeholder?: string
  label: string
  w?: string
}) {
  return (
    <NativeSelect.Root size="sm" w={props.w ?? "40"}>
      <NativeSelect.Field
        bg="surface"
        aria-label={props.label}
        value={props.value}
        onChange={(e) => props.onChange(e.currentTarget.value)}
      >
        {props.placeholder !== undefined && <option value="">{props.placeholder}</option>}
        {props.options.map((o) => {
          const [val, lab] = Array.isArray(o) ? o : [o, o]
          return (
            <option key={val} value={val}>
              {lab}
            </option>
          )
        })}
      </NativeSelect.Field>
      <NativeSelect.Indicator />
    </NativeSelect.Root>
  )
}

export function FilterBar({ children }: { children: ReactNode }) {
  return (
    <Flex gap="2" wrap="wrap" align="center" mb="4">
      {children}
    </Flex>
  )
}

export function Empty(props: { title: string; description?: ReactNode; icon?: ReactNode; action?: ReactNode }) {
  return (
    <EmptyState.Root size="sm">
      <EmptyState.Content>
        <EmptyState.Indicator>{props.icon ?? <LuInbox />}</EmptyState.Indicator>
        <Stack textAlign="center" gap="1">
          <EmptyState.Title>{props.title}</EmptyState.Title>
          {props.description && <EmptyState.Description>{props.description}</EmptyState.Description>}
        </Stack>
        {props.action}
      </EmptyState.Content>
    </EmptyState.Root>
  )
}

export function ErrorBox({ error }: { error: unknown }) {
  return (
    <Alert.Root status="error" variant="subtle" my="3">
      <Alert.Indicator />
      <Alert.Content>
        <Alert.Title>Request failed</Alert.Title>
        <Alert.Description>{error instanceof Error ? error.message : String(error)}</Alert.Description>
      </Alert.Content>
    </Alert.Root>
  )
}

export function LoadingRows({ cols, rows = 6 }: { cols: number; rows?: number }) {
  return (
    <>
      {Array.from({ length: rows }, (_, i) => (
        <Table.Row key={i}>
          {Array.from({ length: cols }, (_, j) => (
            <Table.Cell key={j}>
              <Skeleton h="4" />
            </Table.Cell>
          ))}
        </Table.Row>
      ))}
    </>
  )
}

export function Mono({ children, ...rest }: { children: ReactNode; color?: string; truncate?: boolean; maxW?: string }) {
  return (
    <Text as="span" fontFamily="mono" textStyle="xs" {...rest}>
      {children}
    </Text>
  )
}

// Table shell: horizontal scroll on small screens, sticky header.
export function DataTable({ children, minW = "4xl" }: { children: ReactNode; minW?: string }) {
  return (
    <Card.Root variant="outline" bg="surface" overflow="hidden">
      <Table.ScrollArea>
        <Table.Root size="sm" interactive stickyHeader minW={minW}>
          {children}
        </Table.Root>
      </Table.ScrollArea>
    </Card.Root>
  )
}
