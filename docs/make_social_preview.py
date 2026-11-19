#!/usr/bin/env python3
"""Generate docs/social-preview.png (1280x640). Run from the repository root or this directory."""
from pathlib import Path
from PIL import Image, ImageDraw, ImageFont

CREAM = (246, 245, 241)
INK = (28, 32, 36)
TEAL = (26, 122, 116)
MUTED = (90, 98, 104)

INTER = "/usr/share/fonts/truetype/sand-box/google/Inter/Inter-VariableFont_opsz,wght.ttf"
CJK_BOLD = "/usr/share/fonts/opentype/noto/NotoSansCJK-Bold.ttc"
CJK_REG = "/usr/share/fonts/opentype/noto/NotoSansCJK-Regular.ttc"

W, H = 1280, 640
OUT = Path(__file__).resolve().parent / "social-preview.png"


def inter(size, weight=700, opsz=14):
    font = ImageFont.truetype(INTER, size)
    font.set_variation_by_axes([opsz, weight])
    return font


def cjk(path, size):
    return ImageFont.truetype(path, size, index=0)


def main():
    img = Image.new("RGB", (W, H), CREAM)
    d = ImageDraw.Draw(img)

    # Left accent bar
    d.rectangle((0, 0, 16, H), fill=TEAL)

    title = inter(92, weight=650, opsz=32)
    d.text((88, 150), "aratame", font=title, fill=INK)

    # Small Japanese name, not a heavy seal
    jp = cjk(CJK_BOLD, 36)
    d.text((88, 262), "改め", font=jp, fill=TEAL)

    tag_en = inter(28, weight=450, opsz=18)
    tag_jp = cjk(CJK_REG, 26)
    d.text((88, 330), "A pre-publish gate for Git repositories.", font=tag_en, fill=INK)
    d.text((88, 372), "公開前に、秘密・拒否リスト・author 方針を同じコマンドで見る。", font=tag_jp, fill=MUTED)

    # Three checks as simple labels
    labels = ["Secrets (gitleaks)", "Deny list", "Author policy"]
    labelf = inter(22, weight=550, opsz=14)
    x = 88
    y = 460
    for i, lab in enumerate(labels):
        box = d.textbbox((0, 0), lab, font=labelf)
        tw, th = box[2] - box[0], box[3] - box[1]
        pad_x, pad_y = 18, 10
        d.rounded_rectangle((x, y, x + tw + pad_x * 2, y + th + pad_y * 2), radius=8, outline=TEAL, width=2)
        d.text((x + pad_x, y + pad_y - 2), lab, font=labelf, fill=TEAL)
        x += tw + pad_x * 2 + 20

    foot = inter(18, weight=500, opsz=14)
    d.text((88, 560), "MIT  ·  Go CLI  ·  name is provisional", font=foot, fill=MUTED)

    img.save(OUT, "PNG")
    print("wrote", OUT, img.size)


if __name__ == "__main__":
    main()
