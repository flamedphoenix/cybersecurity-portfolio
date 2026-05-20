import os
import numpy as np
from PIL import Image, ImageEnhance
from imwatermark import WatermarkEncoder, WatermarkDecoder

SOURCE = os.path.expanduser("~/original.png")
WATERMARK_BITS = [1,0,1,1,0,0,1,0,1,1,0,0,0,1,1,0,1,0,1,1,0,0,1,0,1,1,0,0,0,1,1,0,
                  1,1,0,0,1,0,1,1,0,0,0,1,1,0,1,0]
METHOD = "dwtDct"

print("\n" + "="*60)
print("B30: Imperceptible Watermark — Embed & Survival Test")
print("="*60)

img = Image.open(SOURCE).convert("RGB")
img_np = np.array(img)
print(f"\n[+] Source image: {img.size[0]}x{img.size[1]} px")
print(f"[+] Method: DWT-DCT (Discrete Wavelet + Cosine Transform)")
print(f"[+] Watermark: {len(WATERMARK_BITS)}-bit sequence (B30 portfolio identifier)")

encoder = WatermarkEncoder()
encoder.set_watermark('bits', WATERMARK_BITS)
watermarked_np = encoder.encode(img_np, METHOD)
watermarked = Image.fromarray(watermarked_np)
watermarked.save(os.path.expanduser("~/watermarked.png"))
print(f"[+] Watermark embedded successfully")

diff = np.abs(img_np.astype(int) - watermarked_np.astype(int))
print(f"[+] Max pixel difference: {diff.max()} (imperceptible threshold: <10)")
print(f"[+] Mean pixel difference: {diff.mean():.4f}")

def decode(img_np):
    decoder = WatermarkDecoder('bits', len(WATERMARK_BITS))
    bits = decoder.decode(img_np, METHOD)
    match = sum(1 for a, b in zip(bits, WATERMARK_BITS) if a == b)
    pct = match / len(WATERMARK_BITS) * 100
    return bits, pct

def test(label, img_pil):
    arr = np.array(img_pil.convert("RGB"))
    _, pct = decode(arr)
    status = "SURVIVED" if pct >= 75 else "FAILED"
    print(f"  {'✓' if pct >= 75 else '✗'} {label:<35} {pct:5.1f}% match — {status}")
    return pct

print("\n── Baseline verification ─────────────────────────────")
wm = Image.open(os.path.expanduser("~/watermarked.png"))
_, baseline = decode(np.array(wm.convert("RGB")))
print(f"  ✓ Watermarked (no edits)              {baseline:5.1f}% match — BASELINE")

print("\n── Survival tests ────────────────────────────────────")

p = os.path.expanduser("~/wm_jpeg85.jpg")
wm.save(p, "JPEG", quality=85)
test("JPEG compression (q=85)", Image.open(p))

p = os.path.expanduser("~/wm_jpeg50.jpg")
wm.save(p, "JPEG", quality=50)
test("JPEG compression (q=50)", Image.open(p))

bright = ImageEnhance.Brightness(wm).enhance(1.3)
bright.save(os.path.expanduser("~/wm_brightness.png"))
test("Brightness +30%", bright)

contrast = ImageEnhance.Contrast(wm).enhance(1.5)
contrast.save(os.path.expanduser("~/wm_contrast.png"))
test("Contrast +50%", contrast)

small = wm.resize((wm.width//2, wm.height//2), Image.LANCZOS)
resized = small.resize((wm.width, wm.height), Image.LANCZOS)
resized.save(os.path.expanduser("~/wm_resized.png"))
test("Resize 50% down then back up", resized)

cw, ch = wm.width, wm.height
margin_x, margin_y = int(cw*0.1), int(ch*0.1)
cropped = wm.crop((margin_x, margin_y, cw-margin_x, ch-margin_y))
cropped = cropped.resize((cw, ch), Image.LANCZOS)
cropped.save(os.path.expanduser("~/wm_cropped.png"))
test("Crop 10% edges + resize back", cropped)

sat = ImageEnhance.Color(wm).enhance(1.4)
sat.save(os.path.expanduser("~/wm_saturation.png"))
test("Colour saturation +40%", sat)

sharp = ImageEnhance.Sharpness(wm).enhance(1.6)
sharp.save(os.path.expanduser("~/wm_sharpness.png"))
test("Sharpness +60%", sharp)

print("\n" + "="*60)
print("All edited images saved to ~/")
print("="*60 + "\n")
