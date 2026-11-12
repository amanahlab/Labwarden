import { createSystem, defaultConfig, defineConfig, defineRecipe, defineSlotRecipe } from "@chakra-ui/react"
import { tableAnatomy } from "@chakra-ui/react/anatomy"

// Brand palette (docs/brand/GUIDELINES.md). Signal is reserved for the alert
// light: the logo's diamond and the KEV marker. Never use it as a UI accent.
export const BRAND = {
  ink: "#111418",
  signal: "#FF5A1F",
  slate: "#5B6573",
  paper: "#F4F2EE",
} as const

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
    // Neutral accent: Chakra's gray solid (gray.900 / white) sits next to Ink.
    html: { colorPalette: "gray" },
    body: { bg: "canvas" },
    // Thin scrollbars on a clear track, so a classic (always shown) scrollbar
    // does not paint a grey bar with arrows down the edge of the sheet.
    "*": { scrollbarWidth: "thin", scrollbarColor: "{colors.border.emphasized} transparent" },
  },
  theme: {
    recipes: {
      // Links keep blue so they still read as links next to the neutral accent.
      link: defineRecipe({ base: { colorPalette: "blue" } }),
    },
    slotRecipes: {
      // Quiet tables: small uppercase headers, rows on whatever they sit on
      // (the sheet or a card). "sm" is the dense size for findings, scans and
      // logs; "md" is the comfortable one for short lists.
      table: defineSlotRecipe({
        slots: tableAnatomy.keys(),
        base: {
          columnHeader: { textStyle: "xs", fontWeight: "medium", textTransform: "uppercase", letterSpacing: "wider", color: "fg.muted", whiteSpace: "nowrap" },
        },
        variants: {
          variant: { line: { row: { bg: "transparent" } } },
          stickyHeader: { true: { header: { "& :where(tr)": { bg: "surface" } } } },
          size: {
            sm: { columnHeader: { py: "2.5" }, cell: { py: "2.5" } },
            md: { columnHeader: { px: "4", py: "3" }, cell: { px: "4", py: "3.5" } },
          },
        },
      }),
    },
    tokens: {
      colors: {
        brand: Object.fromEntries(Object.entries(BRAND).map(([k, v]) => [k, { value: v }])),
      },
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
        // The ground under the sidebar, the top bar and the content sheet:
        // Paper, or a shade below Ink in dark mode so the sheet still reads.
        canvas: { value: { _light: "{colors.brand.paper}", _dark: "#0A0C0F" } },
        // The content sheet, cards and overlays: white, or Ink in dark mode.
        surface: { value: { _light: "white", _dark: "{colors.brand.ink}" } },
        bg: { panel: { value: { _light: "white", _dark: "{colors.brand.ink}" } } },
        fg: { muted: { value: { _light: "{colors.brand.slate}", _dark: "{colors.gray.400}" } } },
        // Primary buttons and other solid neutrals are Ink, not Chakra's gray.900.
        gray: { solid: { value: { _light: "{colors.brand.ink}", _dark: "{colors.white}" } } },
      },
      // Softer corners than Chakra's defaults: controls 8 px, cards 12 px,
      // the content sheet and side sheets 16 px.
      radii: {
        l1: { value: "{radii.sm}" },
        l2: { value: "{radii.lg}" },
        l3: { value: "{radii.xl}" },
        sheet: { value: "{radii.2xl}" },
      },
      // Shadows are for things that float (side sheets). Cards stay flat.
      shadows: {
        overlay: {
          value: {
            _light: "0 24px 48px -12px {colors.gray.900/20}, 0 0 1px {colors.gray.900/30}",
            _dark: "0 24px 48px -12px {black/70}, 0 0 1px inset {colors.gray.300/30}",
          },
        },
      },
    },
  },
})

export const system = createSystem(defaultConfig, config)
