#!/usr/bin/env python3
"""Build hero-16x9.png (clean) and hero-with-title-16x9.png from the chosen raw render.
Raw 2752x1536 is center-cropped to exact 16:9 (2730x1536) and resized to 2560x1440."""
import sys
from PIL import Image, ImageDraw, ImageFont
V = "/Users/mike/hackathon-intel-2026-10-17/run6h/builds/extension-watch/visuals"
SRC = sys.argv[1] if len(sys.argv) > 1 else f"{V}/raw/hero-t1.png"
W, H = 2560, 1440
# Palette (same values as bin/diagram.py and ART-REPORT.md)
BG, INK, MUTED, ACCENT = (10, 13, 20), (232, 236, 245), (154, 164, 186), (110, 139, 255)
HN = "/System/Library/Fonts/HelveticaNeue.ttc"

im = Image.open(SRC).convert("RGB")
cw = round(im.height * 16 / 9)                      # 2731 -> use even crop
cw -= cw % 2
x0 = (im.width - cw) // 2
im = im.crop((x0, 0, x0 + cw, im.height)).resize((W, H), Image.LANCZOS)
im.save(f"{V}/final/hero-16x9.png", optimize=True)

# Gentle left scrim in the background colour so the type never fights the render
scrim = Image.new("L", (W, H), 0)
d = ImageDraw.Draw(scrim)
for x in range(0, 1280):
    a = int(110 * (1 - x / 1280) ** 1.6)
    d.line([(x, 0), (x, H)], fill=a)
im = Image.composite(Image.new("RGB", (W, H), BG), im, scrim)

d = ImageDraw.Draw(im)
title_f = ImageFont.truetype(HN, 120, index=1)      # Bold
sub_f = ImageFont.truetype(HN, 48, index=0)         # Regular
LEFT = 160                                          # 8 px grid
TITLE_BASE, SUB_BASE = 600, 674                     # block sits above the beam (amber ring starts at x ~ 1245)
# Accent bar: 96x8, radius 4, 48 px above the title cap height
cap = title_f.getbbox("E", anchor="ls")[1]          # negative: cap top relative to baseline
bar_y = TITLE_BASE + cap - 48 - 8
d.rounded_rectangle((LEFT, bar_y, LEFT + 96, bar_y + 8), radius=4, fill=ACCENT)
d.text((LEFT - 4, TITLE_BASE), "Extension Watch", font=title_f, fill=INK, anchor="ls")   # -4: optical side bearing of E
d.text((LEFT, SUB_BASE), "Know the day an extension asks for more", font=sub_f, fill=(180, 190, 211), anchor="ls")
tw = d.textlength("Extension Watch", font=title_f); sw = d.textlength("Know the day an extension asks for more", font=sub_f)
print(f"title width {tw:.0f} -> right edge {LEFT-4+tw:.0f}; subtitle right edge {LEFT+sw:.0f}; bar y {bar_y}")
im.save(f"{V}/final/hero-with-title-16x9.png", optimize=True)

# Contrast check against the darkest/lightest pixels actually behind the text
def lum(c):
    def ch(v):
        v /= 255
        return v / 12.92 if v <= 0.03928 else ((v + 0.055) / 1.055) ** 2.4
    r, g, b = c
    return 0.2126 * ch(r) + 0.7152 * ch(g) + 0.0722 * ch(b)
def ratio(a, b):
    la, lb = sorted((lum(a), lum(b)), reverse=True)
    return (la + 0.05) / (lb + 0.05)
base = Image.open(f"{V}/final/hero-16x9.png").convert("RGB")
base = Image.composite(Image.new("RGB", (W, H), BG), base, scrim)
for name, box, col in (("title", (LEFT, TITLE_BASE - 110, int(LEFT + tw), TITLE_BASE + 30), INK),
                       ("subtitle", (LEFT, SUB_BASE - 45, int(LEFT + sw), SUB_BASE + 14), (180, 190, 211))):
    reg = base.crop(box)
    brightest = max(reg.getdata(), key=lum)
    print(f"{name}: worst-case contrast {ratio(col, brightest):.1f}:1 (brightest bg pixel {brightest})")
