#!/usr/bin/env python3
"""Generate the LabWarden master artwork (symbol, small cut, wordmark, lockups) as clean SVG paths.

Everything is built from rectangles, circles and a few polygons on a fixed grid, so the geometry
stays exact and re-buildable. Run: python3 build.py  (writes into ../masters)
"""
import math
import os

OUT = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "masters")
os.makedirs(OUT, exist_ok=True)

INK = "#111418"
SIGNAL = "#FF5A1F"
WHITE = "#FFFFFF"


def f(v):
    return f"{round(v, 2):g}"


def rect(x0, y0, x1, y1):
    """Clockwise rectangle."""
    return f"M{f(x0)} {f(y0)}H{f(x1)}V{f(y1)}H{f(x0)}Z"


def poly(pts):
    # force clockwise (screen coords) so overlapping parts union under nonzero fill
    area = sum(x0 * y1 - x1 * y0 for (x0, y0), (x1, y1) in zip(pts, pts[1:] + pts[:1]))
    if area < 0:
        pts = pts[::-1]
    return "M" + "L".join(f"{f(x)} {f(y)}" for x, y in pts) + "Z"


def circle(cx, cy, r):
    return (f"M{f(cx)} {f(cy - r)}a{f(r)} {f(r)} 0 1 1 0 {f(2 * r)}"
            f"a{f(r)} {f(r)} 0 1 1 0 {f(-2 * r)}Z")


def diamond(cx, cy, h):
    return poly([(cx, cy - h), (cx + h, cy), (cx, cy + h), (cx - h, cy)])


# ---------------------------------------------------------------- symbol (256 grid)
# Tower 144 wide (x 56..200), split into 5 crenel units of 28.8.
# Three server units, each 40 tall, 12 gaps; merlons 40 tall on top.
X0, X1 = 56, 200
U = (X1 - X0) / 5
MERLON_TOP = 34
UNITS = [(74, 114), (126, 166), (178, 218)]          # y ranges of the three server units
LED_X = 82
DIAMOND_H = 13.5
LED_R = 8.5                                          # circle optically matched to the diamond
VENT = (132, 176, 10)                                # x0, x1, height


def symbol_parts():
    """Returns (outer_with_holes_path, diamond_hole_path)."""
    d = []
    # merlons (part of the top unit's solid)
    for i in (0, 2, 4):
        d.append(rect(X0 + i * U, MERLON_TOP, X0 + (i + 1) * U, UNITS[0][0] + 1))
    solids, holes = [], []
    for k, (y0, y1) in enumerate(UNITS):
        cy = (y0 + y1) / 2
        solids.append(rect(X0, y0, X1, y1))
        if k == 1:
            holes.append(diamond(LED_X, cy, DIAMOND_H))
        else:
            holes.append(circle(LED_X, cy, LED_R))
        holes.append(rect(VENT[0], cy - VENT[2] / 2, VENT[1], cy + VENT[2] / 2))
    return d, solids, holes


def symbol_svg(mode="black"):
    merlons, solids, holes = symbol_parts()
    # merlons drawn as a separate nonzero path; units with evenodd holes
    if mode == "black":
        body = (f'<path fill="{INK if False else "#000"}" d="{"".join(merlons)}"/>'
                f'<path fill="#000" fill-rule="evenodd" d="{"".join(solids + holes)}"/>')
    elif mode == "color":
        body = (f'<path fill="{INK}" d="{"".join(merlons)}"/>'
                f'<path fill="{INK}" fill-rule="evenodd" d="{"".join(solids + holes)}"/>'
                f'<path fill="{SIGNAL}" d="{diamond(LED_X, sum(UNITS[1]) / 2, DIAMOND_H)}"/>')
    elif mode == "reversed":
        # for dark backgrounds: white tower, holes show the background, signal diamond.
        # Irradiation: white looks heavier, so open the gaps/holes slightly.
        merlons, solids, holes = symbol_parts_thin()
        body = (f'<path fill="{WHITE}" d="{"".join(merlons)}"/>'
                f'<path fill="{WHITE}" fill-rule="evenodd" d="{"".join(solids + holes)}"/>'
                f'<path fill="{SIGNAL}" d="{diamond(LED_X, sum(UNITS[1]) / 2, DIAMOND_H + 1.5)}"/>')
    return body


def symbol_parts_thin(t=1.5):
    """Reversed cut: every solid shrinks by t on each edge, every hole grows by t."""
    merlons = [rect(X0 + i * U + t, MERLON_TOP + t, X0 + (i + 1) * U - t, UNITS[0][0] + 1)
               for i in (0, 2, 4)]
    solids, holes = [], []
    for k, (y0, y1) in enumerate(UNITS):
        cy = (y0 + y1) / 2
        top = y0 if k == 0 else y0 + t
        solids.append(rect(X0 + t, top, X1 - t, y1 - t))
        holes.append(diamond(LED_X, cy, DIAMOND_H + t) if k == 1 else circle(LED_X, cy, LED_R + t))
        holes.append(rect(VENT[0] - t, cy - VENT[2] / 2 - t, VENT[1] + t, cy + VENT[2] / 2 + t))
    return merlons, solids, holes


def wrap(body, vb="0 0 256 256", title="LabWarden"):
    return (f'<svg xmlns="http://www.w3.org/2000/svg" viewBox="{vb}">'
            f'<title>{title}</title>{body}</svg>\n')


# ---------------------------------------------------------------- small cut (16 px grid ×16)
def small_svg(mode="black"):
    """Pixel-fitted drawing for 16-32 px: 3 merlons, 3 units, 1 px gaps, one LED per unit."""
    s = 16
    merl = [rect(2 * s, 1 * s, 4 * s, 4 * s), rect(7 * s, 1 * s, 9 * s, 4 * s), rect(12 * s, 1 * s, 14 * s, 4 * s)]
    units = [(3, 6), (7, 10), (11, 14)]
    solids, holes = [], []
    for k, (a, b) in enumerate(units):
        solids.append(rect(2 * s, (a + (0 if k == 0 else 0)) * s, 14 * s, b * s))
        if k != 1:
            holes.append(rect(4 * s, (a + 1) * s, 5 * s, (a + 2) * s))
    led = rect(4 * s, 8 * s, 6 * s, 9 * s)   # alert LED: wider, so it survives
    holes.append(led)
    fg = "#000" if mode == "black" else INK
    body = (f'<path fill="{fg}" d="{"".join(merl)}"/>'
            f'<path fill="{fg}" fill-rule="evenodd" d="{"".join(solids + holes)}"/>')
    if mode == "color":
        body += f'<path fill="{SIGNAL}" d="{led}"/>'
    return body


# ---------------------------------------------------------------- wordmark
# Custom squared capitals, drawn to match the tower: square corners, rectilinear,
# one diagonal (N) and two chamfers (D). "LAB" is set lighter than "WARDEN" so the
# compound reads in one colour.
H = 120


def glyph(ch, w):
    """Return (list of path strings, advance width)."""
    m = H * 0.5
    if ch == "L":
        W = 66
        return [rect(0, 0, w, H), rect(0, H - w, W, H)], W
    if ch == "A":
        W = 84
        c = w * 0.9  # chamfer on the top-left corner gives the A its point
        return [poly([(0, c), (c, 0), (W, 0), (W, w), (w, w), (w, H), (0, H)]),
                rect(W - w, 0, W, H), rect(0, m - w / 2 + 6, W, m + w / 2 + 6)], W
    if ch == "B":
        W, d = 84, 10
        mm = H * 0.46
        return [rect(0, 0, w, H), rect(0, 0, W - d, w), rect(W - d - w, 0, W - d, mm + w / 2),
                rect(0, mm - w / 2, W, mm + w / 2), rect(W - w, mm - w / 2, W, H), rect(0, H - w, W, H)], W
    if ch == "W":
        W = 112
        return [rect(0, 0, w, H), rect(W - w, 0, W, H), rect(0, H - w, W, H),
                rect(W / 2 - w / 2, H * 0.34, W / 2 + w / 2, H)], W
    if ch == "R":
        W, d = 84, 10
        mm = H * 0.5
        return [rect(0, 0, w, H), rect(0, 0, W - d, w), rect(W - d - w, 0, W - d, mm + w / 2),
                rect(0, mm - w / 2, W, mm + w / 2), rect(W - w, mm - w / 2, W, H)], W
    if ch == "D":
        W = 86
        c = w * 1.25
        k = w * (math.sqrt(2) - 1)
        tr = poly([(W - c, 0), (W, c), (W, c + k + 1), (W - w, c + k + 1), (W - c - k - 1, w), (W - c - k - 1, 0)])
        br = poly([(W - c, H), (W, H - c), (W, H - c - k - 1), (W - w, H - c - k - 1), (W - c - k - 1, H - w), (W - c - k - 1, H)])
        return [rect(0, 0, w, H), rect(0, 0, W - c, w), rect(0, H - w, W - c, H),
                rect(W - w, c, W, H - c), tr, br], W
    if ch == "E":
        W = 72
        return [rect(0, 0, w, H), rect(0, 0, W, w), rect(0, m - w / 2, W * 0.86, m + w / 2), rect(0, H - w, W, H)], W
    if ch == "N":
        W = 88
        dx = w * 1.25
        return [rect(0, 0, w, H), rect(W - w, 0, W, H),
                poly([(0, 0), (dx, 0), (W, H), (W - dx, H)])], W
    raise ValueError(ch)


def translate(path, dx, dy):
    """Shift absolute path coords (only M/H/V/L used with absolute coords, 'a' is relative)."""
    out, i, tokens = [], 0, []
    import re
    for cmd, args in re.findall(r"([MHVLZa])([^MHVLZa]*)", path):
        nums = [float(n) for n in re.findall(r"-?\d+(?:\.\d+)?", args)]
        if cmd in "ML":
            nums = [n + (dx if j % 2 == 0 else dy) for j, n in enumerate(nums)]
        elif cmd == "H":
            nums = [n + dx for n in nums]
        elif cmd == "V":
            nums = [n + dy for n in nums]
        out.append(cmd + " ".join(f(n) for n in nums))
    return "".join(out)


# letter spacing, tuned optically per pair (L and A are open on one side)
WEIGHT_LAB, WEIGHT_WARDEN = 16, 26
TRACK = 14
PAIR = {("L", "A"): -8, ("A", "B"): 0, ("B", "W"): 10, ("W", "A"): 0, ("A", "R"): 0,
        ("R", "D"): 0, ("D", "E"): 0, ("E", "N"): 0}


def wordmark_paths(x=0.0, y=0.0, scale=1.0):
    word = "LABWARDEN"
    paths, cx = [], 0.0
    for i, ch in enumerate(word):
        w = WEIGHT_LAB if i < 3 else WEIGHT_WARDEN
        parts, adv = glyph(ch, w)
        for p in parts:
            paths.append((p, cx))
        if i < len(word) - 1:
            cx += adv + TRACK + PAIR.get((ch, word[i + 1]), 0)
        else:
            cx += adv
    total = cx
    d = "".join(translate(p, ox, 0) for p, ox in paths)
    return d, total


def scaled_group(d, x, y, s):
    return f'<g transform="translate({f(x)} {f(y)}) scale({f(s)})">{d}</g>'


def symbol_bbox():
    return X0, MERLON_TOP, X1, UNITS[-1][1]


def wordmark_svg(color="#000"):
    d, total = wordmark_paths()
    return wrap(f'<path fill="{color}" d="{d}"/>', vb=f"0 0 {f(total)} {H}")


def lockup_horizontal(mode="black"):
    """Symbol height = 184 (tower), wordmark cap height = tower unit-span ... centred on the tower body."""
    sx0, sy0, sx1, sy1 = symbol_bbox()
    sym_h = sy1 - sy0                     # 184
    d, total = wordmark_paths()
    cap = sym_h * 0.5                     # cap height = half the tower height
    s = cap / H
    gap = (UNITS[0][1] - UNITS[0][0]) * 1.2   # 1.2 unit heights between symbol and wordmark
    sym_w = sx1 - sx0
    tx = sym_w + gap
    ty = (sym_h - cap) / 2 + 6            # sits slightly low: aligns with the body under the merlons
    fg = {"black": "#000", "color": INK, "reversed": WHITE}[mode]
    sym = f'<g transform="translate({-sx0} {-sy0})">{symbol_svg(mode)}</g>'
    word = f'<g transform="translate({f(tx)} {f(ty)}) scale({f(s)})"><path fill="{fg}" d="{d}"/></g>'
    W = tx + total * s
    pad = 0
    return wrap(sym + word, vb=f"{-pad} {-pad} {f(W + 2 * pad)} {f(sym_h + 2 * pad)}")


def lockup_stacked(mode="black"):
    sx0, sy0, sx1, sy1 = symbol_bbox()
    sym_w, sym_h = sx1 - sx0, sy1 - sy0
    d, total = wordmark_paths()
    s = (sym_w * 2.4) / total             # wordmark 2.4 × tower width
    cap = H * s
    gap = (UNITS[0][1] - UNITS[0][0]) * 0.9
    W = total * s
    fg = {"black": "#000", "color": INK, "reversed": WHITE}[mode]
    sym = f'<g transform="translate({f((W - sym_w) / 2 - sx0)} {-sy0})">{symbol_svg(mode)}</g>'
    word = f'<g transform="translate(0 {f(sym_h + gap)}) scale({f(s)})"><path fill="{fg}" d="{d}"/></g>'
    return wrap(sym + word, vb=f"0 0 {f(W)} {f(sym_h + gap + cap)}")


def write(name, content):
    with open(os.path.join(OUT, name), "w") as fh:
        fh.write(content)
    print("wrote", name)


if __name__ == "__main__":
    write("labwarden-symbol.svg", wrap(symbol_svg("black")))
    write("labwarden-symbol-color.svg", wrap(symbol_svg("color")))
    write("labwarden-symbol-reversed.svg", wrap(symbol_svg("reversed")))
    write("labwarden-symbol-small.svg", wrap(small_svg("black")))
    write("labwarden-symbol-small-color.svg", wrap(small_svg("color")))
    write("labwarden-wordmark.svg", wordmark_svg("#000"))
    write("labwarden-wordmark-color.svg", wordmark_svg(INK))
    write("labwarden-wordmark-reversed.svg", wordmark_svg(WHITE))
    for m in ("black", "color", "reversed"):
        sfx = "" if m == "black" else f"-{m}"
        write(f"labwarden-horizontal{sfx}.svg", lockup_horizontal(m))
        write(f"labwarden-stacked{sfx}.svg", lockup_stacked(m))
