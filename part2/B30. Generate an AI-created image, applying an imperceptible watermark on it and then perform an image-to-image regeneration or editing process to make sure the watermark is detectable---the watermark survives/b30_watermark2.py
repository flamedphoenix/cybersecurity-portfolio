import os
import numpy as np
from PIL import Image, ImageEnhance
from imwatermark import WatermarkEncoder, WatermarkDecoder

SOURCE = os.path.expanduser("~/original.png")
WATERMARK_BITS = [1,0,1,1,0,0,1,0,1,1,0,0,0,1,1,0,1,0,1,1,0,0,1,0,1,1,0,0,0,1,1,0,
                  1,1,0,0,1,0,1,1,0,0,0,1,1,0,1,0]
METHOD = "dwtDctSvd"

print("\n" + "="*60)
print("B30: Watermark Test 2 — DWT-DCT-SVD Method")
print("="*60)

img = Image.open(SOURCE).convert("RGB")
img_np = np.array(img)

encoder = WatermarkEncoder()
encoder.set_watermark('bits', WATERMARK_BITS)
watermarked_np = encoder.encode(img_np, METHOD)
watermarked = Image.fromarray(watermarked_np)
watermarked.save(os.path.expanduser("~/watermarked_svd.png"))

diff = np.abs(img_np.astype(int) - watermarked_np.astype(int))
print(f"[+] Max pixel difference: {diff.max()}")
print(f"[+] Mean pixel difference: {diff.mean():.4f}")

def decode(img_np):
    decoder = WatermarkDecoder('bits', len(WATERMARK_BITS))
    bits = decoder.decode(img_np, METHOD)
    match = sum(1 for a, b in zip(bits, WATERMARK_BITS) if a == b)
    return match / len(WATERMARK_BITS) * 100

def test(label, img_pil):
    pct = decode(np.array(img_pil.convert("RGB")))
    status = "SURVIVED" if pct >= 75 else "FAILED"
    print(f"  {'✓' if pct >= 75 else '✗'} {label:<35} {pct:5.1f}% — {status}")

wm = Image.open(os.path.expanduser("~/watermarked_svd.png"))
print(f"\n── Baseline: {decode(np.array(wm.convert('RGB'))):.1f}% match")
print("\n── Survival tests ────────────────────────────────────")

p = os.path.expanduser("~/wm2_jpeg85.jpg")
wm.save(p, "JPEG", quality=85)
test("JPEG compression (q=85)", Image.open(p))

p = os.path.expanduser("~/wm2_jpeg50.jpg")
wm.save(p, "JPEG", quality=50)
test("JPEG compression (q=50)", Image.open(p))

test("Brightness +30%", ImageEnhance.Brightness(wm).enhance(1.3))
test("Contrast +50%", ImageEnhance.Contrast(wm).enhance(1.5))

small = wm.resize((wm.width//2, wm.height//2), Image.LANCZOS)
test("Resize 50% down then back up", small.resize((wm.width, wm.height), Image.LANCZOS))

cw, ch = wm.width, wm.height
mx, my = int(cw*0.1), int(ch*0.1)
cropped = wm.crop((mx, my, cw-mx, ch-my)).resize((cw, ch), Image.LANCZOS)
test("Crop 10% edges + resize back", cropped)

test("Colour saturation +40%", ImageEnhance.Color(wm).enhance(1.4))
test("Sharpness +60%", ImageEnhance.Sharpness(wm).enhance(1.6))
print()
