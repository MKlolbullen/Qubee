#!/usr/bin/env python3
"""Render the launcher icon layers and the transparent mark from the logo.

Input:  docs/branding/qubee_logo.png (the full lockup on its navy field)
Output: docs/branding/qubee_mark.png (mark only, transparent, source size)
        app/src/main/res/mipmap-*/ic_launcher_foreground.png
        app/src/main/res/mipmap-*/ic_launcher_monochrome.png

The lockup has no alpha channel, so the mark is lifted off the navy by
colour distance and un-premultiplied against the per-row background.
Composited back over the same navy (the adaptive icon background) the
result is pixel-faithful; the ribbons' soft glow survives as partial
alpha. Needs Pillow: `python3 -m pip install pillow`.
"""
from pathlib import Path

from PIL import Image

ROOT = Path(__file__).resolve().parents[1]
LOGO = ROOT / "docs/branding/qubee_logo.png"
MARK = ROOT / "docs/branding/qubee_mark.png"
RES = ROOT / "app/src/main/res"

# Adaptive icon canvas is 108dp; launchers mask the central 72dp and
# the safe zone is a 66dp circle. The mark is wide (about 1.6:1) and
# its lateral tips sit on the equator, so 64dp of width keeps every
# tip inside the circle with a 1dp margin.
CANVAS_DP = 108
MARK_WIDTH_DP = 64
DENSITIES = {"mdpi": 1, "hdpi": 1.5, "xhdpi": 2, "xxhdpi": 3, "xxxhdpi": 4}

# Band detection needs a high bar so the glow between the mark and the
# wordmark does not fuse the two bands; alpha uses a lower one so the
# soft outer glow survives, but below CLEAR_DISTANCE a pixel is sensor
# noise on the navy and is dropped outright rather than amplified.
CONTENT_THRESHOLD = 40
OPAQUE_DISTANCE = 110
CLEAR_DISTANCE = 10
PAD = 8


def row_background(px, width, y):
    cols = [px[x, y] for x in range(8, 56)]
    return tuple(sorted(c[i] for c in cols)[len(cols) // 2] for i in range(3))


def distance(p, bg):
    return max(abs(p[i] - bg[i]) for i in range(3))


def mark_box(px, width, height):
    """Bounding box of the first content band from the top: the mark.

    The wordmark is a second band further down and is ignored.
    """
    first = last = None
    for y in range(height):
        bg = row_background(px, width, y)
        has = any(distance(px[x, y], bg) > CONTENT_THRESHOLD for x in range(0, width, 2))
        if has and first is None:
            first = y
        if not has and first is not None:
            last = y - 1
            break
    xs = [
        x
        for y in range(first, last + 1)
        for x in range(width)
        if distance(px[x, y], row_background(px, width, y)) > CONTENT_THRESHOLD
    ]
    return (
        max(min(xs) - PAD, 0),
        max(first - PAD, 0),
        min(max(xs) + PAD + 1, width),
        min(last + PAD + 1, height),
    )


def lift_mark(logo):
    px = logo.load()
    width, height = logo.size
    x0, y0, x1, y1 = mark_box(px, width, height)
    mark = Image.new("RGBA", (x1 - x0, y1 - y0))
    out = mark.load()
    for y in range(y0, y1):
        bg = row_background(px, width, y)
        for x in range(x0, x1):
            p = px[x, y]
            d = distance(p, bg)
            if d < CLEAR_DISTANCE:
                out[x - x0, y - y0] = (*bg, 0)
                continue
            a = min(d / OPAQUE_DISTANCE, 1.0)
            if a < 0.3:
                # Faint glow: keep the observed colour. Solving for the
                # true foreground here only amplifies noise.
                out[x - x0, y - y0] = (*p, int(round(a * 255)))
                continue
            # Observed = a*F + (1-a)*B, solve for the foreground colour F.
            f = tuple(int(max(0, min(255, round((p[i] - (1 - a) * bg[i]) / a)))) for i in range(3))
            out[x - x0, y - y0] = (*f, int(round(a * 255)))
    return mark


def monochrome(layer):
    """White silhouette of the solid ribbons and node only.

    Themed icons render this at 48dp or less; the thin inner rings and
    the glow turn into speckle there, so the alpha ramp starts well
    above their opacity.
    """
    alpha = layer.getchannel("A").point(lambda v: 0 if v < 150 else 255 if v > 215 else int((v - 150) * 255 / 65))
    mono = Image.new("RGBA", layer.size, (255, 255, 255, 0))
    mono.putalpha(alpha)
    return mono


def render_layers(mark):
    for density, scale in DENSITIES.items():
        canvas_px = int(CANVAS_DP * scale)
        target_w = int(MARK_WIDTH_DP * scale)
        target_h = round(mark.height * target_w / mark.width)
        scaled = mark.resize((target_w, target_h), Image.LANCZOS)
        layer = Image.new("RGBA", (canvas_px, canvas_px), (0, 0, 0, 0))
        layer.alpha_composite(scaled, ((canvas_px - target_w) // 2, (canvas_px - target_h) // 2))
        folder = RES / f"mipmap-{density}"
        folder.mkdir(exist_ok=True)
        layer.save(folder / "ic_launcher_foreground.png", optimize=True)
        monochrome(layer).save(folder / "ic_launcher_monochrome.png", optimize=True)


def main():
    logo = Image.open(LOGO).convert("RGB")
    mark = lift_mark(logo)
    mark.save(MARK, optimize=True)
    render_layers(mark)
    print(f"mark {mark.size[0]}x{mark.size[1]} -> {MARK.relative_to(ROOT)}; layers for {', '.join(DENSITIES)}")


if __name__ == "__main__":
    main()
