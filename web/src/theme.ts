import { createSystem, defaultConfig, defineConfig } from "@chakra-ui/react"

// Severity is a status encoding: one fixed set of colors in both modes,
// always rendered next to its text label (validated with the dataviz
// palette checker: adjacent CVD ΔE ≥ 11, normal-vision ΔE ≥ 16 on light).
export const SEVERITY_COLORS = {
  Critical: "#b0242c",
  High: "#e8613a",
  Medium: "#e9a400",
  Low: "#2a78d6",
  Negligible: "#8a8984",
  Unknown: "#b5b3ad",
} as const

// Categorical series slots (reference palette, fixed order, light/dark steps).
const SERIES = [
  ["#2a78d6", "#3987e5"],
  ["#eb6834", "#d95926"],
  ["#1baf7a", "#199e70"],
  ["#eda100", "#c98500"],
  ["#e87ba4", "#d55181"],
  ["#008300", "#008300"],
  ["#6250d6", "#9085e9"],
  ["#e34948", "#e66767"],
]

const config = defineConfig({
  globalCss: {
    html: { colorPalette: "blue" },
    body: { bg: "bg.subtle" },
  },
  theme: {
    tokens: {
      fonts: {
        heading: { value: "'Inter Variable', Inter, ui-sans-serif, system-ui, -apple-system, 'Segoe UI', Roboto, sans-serif" },
        body: { value: "'Inter Variable', Inter, ui-sans-serif, system-ui, -apple-system, 'Segoe UI', Roboto, sans-serif" },
        mono: { value: "'JetBrains Mono Variable', ui-monospace, SFMono-Regular, Menlo, Consolas, monospace" },
      },
    },
    semanticTokens: {
      colors: {
        sev: Object.fromEntries(
          Object.entries(SEVERITY_COLORS).map(([k, v]) => [k.toLowerCase(), { value: v }]),
        ),
        series: Object.fromEntries(
          SERIES.map(([light, dark], i) => [String(i + 1), { value: { _light: light, _dark: dark } }]),
        ),
        surface: { value: { _light: "white", _dark: "{colors.gray.950}" } },
      },
    },
  },
})

export const system = createSystem(defaultConfig, config)
