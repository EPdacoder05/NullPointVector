#!/usr/bin/env python3
"""Generate a complete AppIcon.appiconset for App Store / TestFlight upload."""
from __future__ import annotations

from pathlib import Path

from PIL import Image, ImageDraw, ImageFont

ROOT = Path(__file__).resolve().parent
OUT = ROOT / "Assets.xcassets" / "AppIcon.appiconset"
BASE = ROOT / "Assets.xcassets" / "AppIcon.appiconset" / "icon-1024.png"

# (filename, idiom, size_pt, scale, role optional)
# ASC needs at least iPhone 120 (60@2x) and iPad 152 (76@2x).
ICONS = [
    ("Icon-20.png", "iphone", "20x20", "1x"),
    ("Icon-20@2x.png", "iphone", "20x20", "2x"),
    ("Icon-20@3x.png", "iphone", "20x20", "3x"),
    ("Icon-29.png", "iphone", "29x29", "1x"),
    ("Icon-29@2x.png", "iphone", "29x29", "2x"),
    ("Icon-29@3x.png", "iphone", "29x29", "3x"),
    ("Icon-40.png", "iphone", "40x40", "1x"),
    ("Icon-40@2x.png", "iphone", "40x40", "2x"),
    ("Icon-40@3x.png", "iphone", "40x40", "3x"),
    ("Icon-60@2x.png", "iphone", "60x60", "2x"),  # 120 — ASC 90022
    ("Icon-60@3x.png", "iphone", "60x60", "3x"),  # 180
    ("Icon-20-ipad.png", "ipad", "20x20", "1x"),
    ("Icon-20@2x-ipad.png", "ipad", "20x20", "2x"),
    ("Icon-29-ipad.png", "ipad", "29x29", "1x"),
    ("Icon-29@2x-ipad.png", "ipad", "29x29", "2x"),
    ("Icon-40-ipad.png", "ipad", "40x40", "1x"),
    ("Icon-40@2x-ipad.png", "ipad", "40x40", "2x"),
    ("Icon-76.png", "ipad", "76x76", "1x"),
    ("Icon-76@2x.png", "ipad", "76x76", "2x"),  # 152 — ASC 90023
    ("Icon-83.5@2x.png", "ipad", "83.5x83.5", "2x"),
    ("Icon-1024.png", "ios-marketing", "1024x1024", "1x"),
]


def _px(size: str, scale: str) -> int:
    pt = float(size.split("x")[0])
    s = int(scale.replace("x", ""))
    return int(round(pt * s))


def make_base(size: int = 1024) -> Image.Image:
    if BASE.exists():
        img = Image.open(BASE).convert("RGB")
        return img.resize((size, size), Image.Resampling.LANCZOS)
    # Forest + brass brand colors
    img = Image.new("RGB", (size, size), color=(18, 48, 36))
    draw = ImageDraw.Draw(img)
    margin = size // 8
    draw.rounded_rectangle(
        [margin, margin, size - margin, size - margin],
        radius=size // 8,
        outline=(196, 163, 90),
        width=max(4, size // 48),
    )
    try:
        font = ImageFont.truetype("/System/Library/Fonts/Supplemental/Arial Bold.ttf", size // 3)
    except Exception:
        font = ImageFont.load_default()
    draw.text((size // 2, size // 2), "N", fill=(196, 163, 90), font=font, anchor="mm")
    return img


def main() -> None:
    OUT.mkdir(parents=True, exist_ok=True)
    base = make_base(1024)
    images = []
    for filename, idiom, size, scale in ICONS:
        px = _px(size, scale)
        resized = base.resize((px, px), Image.Resampling.LANCZOS)
        path = OUT / filename
        resized.save(path, format="PNG")
        print(f"wrote {path.name} ({px}x{px})")
        images.append({
            "filename": filename,
            "idiom": idiom,
            "scale": scale,
            "size": size,
        })
    contents = {
        "images": images,
        "info": {"author": "xcode", "version": 1},
    }
    import json
    (OUT / "Contents.json").write_text(json.dumps(contents, indent=2) + "\n")
    print(f"updated {OUT / 'Contents.json'}")


if __name__ == "__main__":
    main()
