import { Button, HStack, Text } from "@chakra-ui/react"
import { LuX } from "react-icons/lu"
import { SEVERITIES, type Severity } from "@/lib/api"
import { KevMark, SevDot } from "@/components/common"

// Toggle chips for multi-select severity filtering (dot + label, never color alone).
export function SeverityChips({ value, onChange }: { value: string[]; onChange: (v: string[]) => void }) {
  const toggle = (s: Severity) => onChange(value.includes(s) ? value.filter((x) => x !== s) : [...value, s])
  return (
    <HStack gap="1" wrap="wrap" role="group" aria-label="Severity filter">
      {SEVERITIES.slice(0, 5).map((s) => {
        const on = value.includes(s)
        return (
          <Button
            key={s}
            size="xs"
            variant={on ? "subtle" : "outline"}
            colorPalette={on ? "blue" : "gray"}
            bg={on ? undefined : "surface"}
            aria-pressed={on}
            onClick={() => toggle(s)}
          >
            <SevDot severity={s} size="2" />
            <Text as="span">{s}</Text>
          </Button>
        )
      })}
    </HStack>
  )
}

export function KevToggle({ value, onChange }: { value: boolean; onChange: (v: boolean) => void }) {
  return (
    <Button size="xs" variant={value ? "solid" : "outline"} colorPalette="gray" bg={value ? undefined : "surface"} aria-pressed={value} onClick={() => onChange(!value)}>
      <KevMark /> Known exploited
    </Button>
  )
}

export function ClearFilters({ show, onClear }: { show: boolean; onClear: () => void }) {
  if (!show) return null
  return (
    <Button size="xs" variant="ghost" onClick={onClear}>
      <LuX /> Clear filters
    </Button>
  )
}
