#!/usr/bin/env python3
"""Hand-built app icon and favicon SVGs that keep the signal-orange alert LED
(the generic exporter forces the mark to one colour). Writes into ../masters."""
import build as b

TILE_RX = 57.6  # 22.5 % corner radius, iOS-like


def app_icon():
    # reversed symbol on an ink tile; symbol bbox 144×184 scaled to ~64 % of the tile height
    sx0, sy0, sx1, sy1 = b.symbol_bbox()
    s = 0.84
    w, h = (sx1 - sx0) * s, (sy1 - sy0) * s
    tx = (256 - w) / 2 - sx0 * s
    ty = (256 - h) / 2 - sy0 * s - 4          # optical lift
    return b.wrap(f'<rect width="256" height="256" rx="{TILE_RX}" fill="{b.INK}"/>'
                  f'<g transform="translate({b.f(tx)} {b.f(ty)}) scale({s})">{b.symbol_svg("reversed")}</g>')


def favicon_svg():
    # pixel-fitted small cut; ink on light tabs, white on dark tabs, LED always signal orange
    body = b.small_svg("color").replace(f'fill="{b.INK}"', 'class="t" fill="#111418"')
    style = ('<style>@media (prefers-color-scheme: dark){.t{fill:#FFFFFF}}</style>')
    return b.wrap(style + body)


if __name__ == "__main__":
    b.write("labwarden-app-icon.svg", app_icon())
    b.write("labwarden-favicon.svg", favicon_svg())
