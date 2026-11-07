import { BarList, Chart, useChart, type BarListData } from "@chakra-ui/charts"
import { Box, Flex, HStack, Stack, Text } from "@chakra-ui/react"
import { Area, AreaChart, CartesianGrid, Cell, Legend, Pie, PieChart, Tooltip, XAxis, YAxis } from "recharts"
import { SEVERITY_COLORS } from "@/theme"
import { SEVERITIES, type Counts, type DailyStat, type NameCount, type Severity } from "@/lib/api"
import { num, shortDate } from "@/lib/format"
import { Empty, SevDot } from "@/components/common"

const TREND_SERIES: { name: keyof Counts; sev: Severity }[] = [
  { name: "critical", sev: "Critical" },
  { name: "high", sev: "High" },
  { name: "medium", sev: "Medium" },
  { name: "low", sev: "Low" },
]

// Stacked area of active findings by severity per day.
export function SeverityTrend({ data }: { data: DailyStat[] }) {
  const chart = useChart({
    data,
    series: TREND_SERIES.map((s) => ({ name: s.name, color: SEVERITY_COLORS[s.sev], label: s.sev, stackId: "a" })),
  })
  if (data.length === 0) return <Empty title="No history yet" description="Daily totals appear after the first scans." />
  return (
    <Chart.Root maxH="72" chart={chart}>
      <AreaChart data={chart.data} margin={{ left: 0, right: 8, top: 8 }} responsive>
        <CartesianGrid stroke={chart.color("border.muted")} vertical={false} />
        <XAxis
          dataKey={chart.key("day")}
          tickFormatter={shortDate}
          stroke={chart.color("border")}
          tick={{ fill: chart.color("fg.muted"), fontSize: 11 }}
          tickLine={false}
          minTickGap={24}
        />
        <YAxis
          stroke={chart.color("border")}
          tick={{ fill: chart.color("fg.muted"), fontSize: 11 }}
          tickLine={false}
          axisLine={false}
          width={44}
          tickFormatter={chart.formatNumber({ notation: "compact" })}
        />
        <Tooltip
          cursor={{ stroke: chart.color("border.emphasized"), strokeWidth: 1 }}
          animationDuration={100}
          labelFormatter={(d) => shortDate(String(d))}
          content={<Chart.Tooltip />}
        />
        <Legend content={<Chart.Legend />} verticalAlign="top" align="right" itemSorter={(item) => TREND_SERIES.findIndex((s) => s.name === item.dataKey)} />
        {chart.series.map((s) => (
          <Area
            key={s.name}
            type="monotone"
            isAnimationActive={false}
            dataKey={chart.key(s.name)}
            name={String(s.label)}
            stackId={s.stackId}
            fill={chart.color(s.color)}
            fillOpacity={0.35}
            stroke={chart.color(s.color)}
            strokeWidth={2}
          />
        ))}
      </AreaChart>
    </Chart.Root>
  )
}

// Donut of unique vulnerabilities by severity with a labelled legend.
export function SeverityDonut({ counts, caption }: { counts: Counts; caption: string }) {
  const data = SEVERITIES.map((s) => ({ name: s, value: counts[s.toLowerCase() as keyof Counts] as number, color: SEVERITY_COLORS[s] })).filter(
    (d) => d.value > 0,
  )
  const chart = useChart({ data })
  const total = data.reduce((a, d) => a + d.value, 0)
  if (total === 0) return <Empty title="No open vulnerabilities" description="Nothing to show yet." />
  return (
    <Flex align="center" gap="6" direction={{ base: "column", sm: "row" }}>
      <Box position="relative" w="44" h="44" flexShrink={0}>
        <Chart.Root chart={chart} w="44" h="44">
          <PieChart responsive>
            <Tooltip cursor={false} animationDuration={100} content={<Chart.Tooltip hideLabel />} />
            <Pie
              isAnimationActive={false}
              data={chart.data}
              dataKey={chart.key("value")}
              nameKey="name"
              innerRadius="68%"
              outerRadius="100%"
              stroke={chart.color("surface")}
              strokeWidth={2}
            >
              {chart.data.map((d) => (
                <Cell key={d.name} fill={d.color} />
              ))}
            </Pie>
          </PieChart>
        </Chart.Root>
        <Stack position="absolute" inset="0" align="center" justify="center" gap="0" pointerEvents="none">
          <Text textStyle="2xl" fontWeight="semibold" lineHeight="1">
            {num(total)}
          </Text>
          <Text textStyle="xs" color="fg.muted">
            {caption}
          </Text>
        </Stack>
      </Box>
      <Stack gap="2" flex="1" w="full">
        {data.map((d) => (
          <HStack key={d.name} justify="space-between" textStyle="sm">
            <HStack gap="2">
              <SevDot severity={d.name} />
              <Text>{d.name}</Text>
            </HStack>
            <HStack gap="3" fontVariantNumeric="tabular-nums">
              <Text fontWeight="medium">{num(d.value)}</Text>
              <Text color="fg.muted" w="10" textAlign="end">
                {Math.round((d.value / total) * 100)}%
              </Text>
            </HStack>
          </HStack>
        ))}
      </Stack>
    </Flex>
  )
}

// Ranked horizontal bars (single series: one hue, value labels, no legend).
export function RankedBars({ data, color = "blue.muted", hrefFor }: { data: NameCount[]; color?: string; hrefFor?: (name: string) => string }) {
  const chart = useChart<BarListData>({
    sort: { by: "value", direction: "desc" },
    data: data.map((d) => ({ name: d.name || "(none)", value: d.count, href: hrefFor?.(d.name) })),
    series: [{ name: "name", color }],
  })
  if (data.length === 0) return <Empty title="No data" />
  return (
    <BarList.Root chart={chart} barSize="7">
      <BarList.Content>
        <BarList.Bar tooltip />
        <BarList.Value valueFormatter={(v) => num(v)} />
      </BarList.Content>
    </BarList.Root>
  )
}
