import { chakra } from "@chakra-ui/react"
import horizontalColor from "@/assets/brand/labwarden-horizontal-color.svg"
import horizontalReversed from "@/assets/brand/labwarden-horizontal-reversed.svg"
import symbolColor from "@/assets/brand/labwarden-symbol-color.svg"
import symbolReversed from "@/assets/brand/labwarden-symbol-reversed.svg"

// Logo artwork from docs/brand (see GUIDELINES.md). The reversed masters have
// thinned geometry for light-on-dark, so dark mode swaps the whole file
// instead of recolouring. The aspect ratio is fixed by the SVG viewBox.
function BrandImage({ light, dark, width }: { light: string; dark: string; width: number }) {
  return (
    <>
      <chakra.img src={light} alt="LabWarden" width={`${width}px`} height="auto" flexShrink={0} display="block" _dark={{ display: "none" }} />
      <chakra.img src={dark} alt="LabWarden" width={`${width}px`} height="auto" flexShrink={0} display="none" _dark={{ display: "block" }} />
    </>
  )
}

// Horizontal lockup: 120 px wide at minimum.
export function BrandLockup({ width = 160 }: { width?: number }) {
  return <BrandImage light={horizontalColor} dark={horizontalReversed} width={Math.max(width, 120)} />
}

// Detailed symbol: 48 px at minimum (below that the guidelines call for the small cut).
export function BrandSymbol({ size = 56 }: { size?: number }) {
  return <BrandImage light={symbolColor} dark={symbolReversed} width={Math.max(size, 48)} />
}
