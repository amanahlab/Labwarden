import { chakra } from "@chakra-ui/react"
import { BRAND } from "@/theme"
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

// Small cut for 16 to 32 px (the collapsed sidebar). Same geometry as
// docs/brand/masters/labwarden-symbol-small-color.svg; like the favicon, the
// tower turns white on dark grounds and the light stays Signal.
export function BrandMark({ size = 28 }: { size?: number }) {
  return (
    <chakra.svg viewBox="0 0 256 256" width={`${size}px`} height={`${size}px`} flexShrink={0} role="img" aria-label="LabWarden" color={{ _light: "brand.ink", _dark: "white" }}>
      <path fill="currentColor" d="M32 16H64V64H32ZM112 16H144V64H112ZM192 16H224V64H192Z" />
      <path
        fill="currentColor"
        fillRule="evenodd"
        d="M32 48H224V96H32ZM32 112H224V160H32ZM32 176H224V224H32ZM64 64H80V80H64ZM64 192H80V208H64ZM64 128H96V144H64Z"
      />
      <path fill={BRAND.signal} d="M64 128H96V144H64Z" />
    </chakra.svg>
  )
}
