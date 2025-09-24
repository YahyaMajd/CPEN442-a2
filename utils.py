import numpy as np
import matplotlib.pyplot as plt
from PIL import Image
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes


def load_image(path: str) -> bytes:
    img = Image.open(path).convert("L") # Convert to grayscale
    array = np.array(img, dtype=np.uint8)
    img_bytes = array.flatten().tobytes()
    return img_bytes


def encrypt_image(img_bytes: bytes, key: bytes, mode: 'str') -> bytes:
    assert mode in ('ECB', 'CBC', 'CTR')
    assert len(img_bytes) % AES.block_size == 0
    if mode == 'ECB':
        cipher = AES.new(key, AES.MODE_ECB)
        return cipher.encrypt(img_bytes)
    elif mode == 'CBC':
        iv = bytes(16) # All-zero
        cipher = AES.new(key, AES.MODE_CBC, iv=iv)
        return cipher.encrypt(img_bytes)
    elif mode == 'CTR':
        nonce = bytes(8) # All-zero
        cipher = AES.new(key, AES.MODE_CTR, nonce=nonce)
        return cipher.encrypt(img_bytes)


def show_image(img_bytes: bytes):
    img = np.frombuffer(img_bytes, dtype=np.uint8)
    img = img.reshape((48, 48))
    img = Image.fromarray(img, mode='L')
    plt.imshow(np.array(img), cmap='gray')
    plt.show()


def save_img(path: str, img_bytes: bytes):
    img = np.frombuffer(img_bytes, dtype=np.uint8)
    img = img.reshape((48, 48))
    img = Image.fromarray(img, mode='L')
    img.save(path)



# img_bytes = load_image("ciphertext-sprites/0.png")
# key = get_random_bytes(AES.block_size)
# ciphertext_ecb = encrypt_image(img_bytes, key, 'ECB')
# ciphertext_cbc = encrypt_image(img_bytes, key, 'CBC')
# ciphertext_ctr = encrypt_image(img_bytes, key, 'CTR')
# show_image(img_bytes)
# show_image(ciphertext_ecb)
# show_image(ciphertext_cbc)
# show_image(ciphertext_ctr)
# save_img("0_ecb.png", ciphertext_ecb)
# save_img("0_cbc.png", ciphertext_cbc)
# save_img("0_ctr.png", ciphertext_ctr)


# =========================
# Ciphertext-only detectors
# =========================
import os
import numpy as np
from collections import Counter

AES_BLOCK = 16

def load_image_array(path: str) -> np.ndarray:
    """(48,48) uint8 array from a file (ciphertext bytes as pixels)."""
    img = Image.open(path).convert("L")
    arr = np.array(img, dtype=np.uint8)
    if arr.shape != (48, 48):
        raise ValueError(f"Expected 48x48, got {arr.shape} for {path}")
    return arr

def ecb_duplicate_block_count(arr: np.ndarray, block=AES_BLOCK) -> int:
    """Count exact duplicate 16-byte blocks per row (ECB fingerprint)."""
    blocks = []
    for r in range(arr.shape[0]):
        row = arr[r, :]
        for c in range(0, arr.shape[1], block):
            blocks.append(bytes(row[c:c+block]))
    counts = Counter(blocks)
    return sum(cnt - 1 for cnt in counts.values() if cnt > 1)

def boundary_artifact_score(arr: np.ndarray) -> float:
    """
    Mean |diff| across vertical block boundaries (15|16 and 31|32)
    minus mean |diff| just inside the blocks (16|17 and 32|33).
    CBC tends to have +ve (stronger boundary edges); CTR ~ 0.
    """
    diffs_b, diffs_i = [], []
    for r in range(arr.shape[0]):
        row = arr[r, :].astype(int)
        diffs_b.append(abs(row[16] - row[15]))
        diffs_b.append(abs(row[32] - row[31]))
        diffs_i.append(abs(row[17] - row[16]))
        diffs_i.append(abs(row[33] - row[32]) if 33 < arr.shape[1] else 0)
    return float(np.mean(diffs_b) - np.mean(diffs_i))

def periodicity16_score(arr: np.ndarray) -> float:
    """
    Measure 16-column periodicity of neighbor differences.
    Higher => more 16-byte-aligned structure (more CBC-like).
    """
    diffs = np.abs(np.diff(arr.astype(int), axis=1))  # (48,47)
    cols = diffs.shape[1]
    # positions just BEFORE blocks vs others
    boundary_positions = {15, 31}
    at_boundary = [c for c in range(cols) if c in boundary_positions]
    away = [c for c in range(cols) if c not in boundary_positions]
    if not at_boundary: 
        return 0.0
    return float(diffs[:, at_boundary].mean() - diffs[:, away].mean())

def classify_non_ecb(files: list[str], folder: str):
    """
    Among non-ECB images, split into CTR (lower scores) vs CBC (higher scores)
    using two independent features (boundary + periodicity16). Returns dict.
    """
    feats = []
    for fname in files:
        arr = load_image_array(os.path.join(folder, fname))
        b = boundary_artifact_score(arr)
        p = periodicity16_score(arr)
        combo = 0.5 * b + 0.5 * p  # simple ensemble
        feats.append((fname, b, p, combo))

    # Sort by "combo" score: low => CTR, high => CBC.
    feats_sorted = sorted(feats, key=lambda x: x[3])
    half = len(feats_sorted) // 2
    ctr = [f for (f, *_ ) in feats_sorted[:half]]
    cbc = [f for (f, *_ ) in feats_sorted[half:]]

    print("\n--- Non-ECB feature table (file, boundary, periodicity, combo) ---")
    for row in feats_sorted:
        print(row)
    return {"CTR": ctr, "CBC": cbc, "features": feats_sorted}

def classify_folder(folder: str):
    """
    Full pipeline: mark ECB by duplicate blocks; split the rest into CTR/CBC.
    Also prints metrics you can cite in the report.
    """
    files = sorted([f for f in os.listdir(folder) if f.lower().endswith((".png",".bmp",".jpg",".jpeg"))])
    metrics = []
    ecb_files, non_ecb_files = [], []
    for f in files:
        arr = load_image_array(os.path.join(folder, f))
        dup = ecb_duplicate_block_count(arr)
        metrics.append((f, dup))
        if dup > 0:
            ecb_files.append(f)
        else:
            non_ecb_files.append(f)

    print("=== ECB check (filename, duplicate 16B blocks) ===")
    for row in sorted(metrics, key=lambda x: x[1], reverse=True):
        print(row)
    print("ECB:", ecb_files)

    other = classify_non_ecb(non_ecb_files, folder)
    print("\nCTR:", other["CTR"])
    print("CBC:", other["CBC"])
    return {"ECB": ecb_files, "CTR": other["CTR"], "CBC": other["CBC"]}

# ===============
# Optional: calibrate with your own encryption (reference only, not matching)
# ===============
def make_checkerboard() -> bytes:
    """48x48 simple pattern to visualize/calibrate mode artifacts."""
    img = np.indices((48,48)).sum(axis=0) % 2
    img = (img * 255).astype(np.uint8)
    return img.tobytes()

def calibrate_reference_scores():
    """
    Encrypt a checkerboard with your encrypt_image() in CBC and CTR
    to see typical boundary/periodicity scores; use as a sanity check.
    """
    key = get_random_bytes(AES.block_size)
    plain = make_checkerboard()
    ref = {}
    for m in ("CBC", "CTR"):
        ct = encrypt_image(plain, key, m)
        arr = np.frombuffer(ct, dtype=np.uint8).reshape(48,48)
        ref[m] = (boundary_artifact_score(arr), periodicity16_score(arr))
    print("\nReference scores on checkerboard (boundary, periodicity):", ref)
    return ref

# -----------------------
# Example usage (uncomment)
# -----------------------
folder = "ciphertext-sprites"
calibrate_reference_scores()   # optional, just to see typical values
result = classify_folder(folder)

