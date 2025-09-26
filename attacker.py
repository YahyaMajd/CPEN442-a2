# File to complete by the students
from typing import Callable
from Crypto.Cipher import AES
import string
import random


def guess_code_ecb(generate_guest_token: Callable, read_token: Callable) -> str:

    BLOCK = 16
    B64_ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"

    def _blocks(b: bytes) -> list[bytes]:
        return [b[i:i+BLOCK] for i in range(0, len(b), BLOCK)]

    def _last15(s: str) -> str:
        return s[-15:]

    recovered_code = ""

    for i in range(32):  # 24 bytes => 32 Base64 chars

        # Layout: name={name}&pwd= + 'A'*r + dict_stream + 'B'*t + &role=guest&code= + CODE
        name = ""
        prefix_before_pwd = f"name={name}&pwd="
        L0 = len(prefix_before_pwd)
        r = (-L0) % BLOCK

        known_15 = _last15("&role=guest&code=" + recovered_code)

        # Build the 64 plaintext dictionary blocks
        dict_blocks_plain = [known_15 + c for c in B64_ALPHABET]
        dict_stream = "".join(dict_blocks_plain)

        len_role = len("&role=guest&code=")  # 16
        pos_before_code = L0 + r + len(dict_stream) + len_role
        t = (15 - (pos_before_code + i)) % BLOCK

        pwd = ("A" * r) + dict_stream + ("B" * t)

        # Encrypt crafted token
        enc = generate_guest_token(name, pwd)
        cblocks = _blocks(enc)

        # Dictionary start block index in ciphertext
        dict_block_start_idx = (L0 + r) // BLOCK

        # Target block index (the block that ends with code[i])
        target_pos = pos_before_code + i
        target_block_idx = target_pos // BLOCK
        target_block = cblocks[target_block_idx]

        # Match target block against the dictionary blocks
        guess = None
        for k, ch in enumerate(B64_ALPHABET):
            cand_block = cblocks[dict_block_start_idx + k]
            if cand_block == target_block:
                guess = ch
                break

        if guess is None:
            raise RuntimeError("Failed to match target block in dictionary (ECB assumption broken?)")

        recovered_code += guess

    return recovered_code


def forge_admin_token_ecb(generate_guest_token, read_token):

    BLOCK = 16

    def _blocks(b: bytes):
        return [b[i:i+BLOCK] for i in range(0, len(b), BLOCK)]

    # Baseline token with 'role=guest&code=' aligned on a block boundary
    base_name = ""
    base_pwd  = "B" * 5       # 11 + len(pwd) = 16 → aligns 'role' at block start
    ct_base = generate_guest_token(base_name, base_pwd)
    cblocks_base = _blocks(ct_base)

    # Block index where 'role=guest&code=' starts:
    role_block_idx = (len("name=") + len(base_name) + len("&pwd=") + len(base_pwd) + 1) // BLOCK

    # Token containing 'role=admin&code=' block at a boundary
    name_admin = "A" * 11 + "role=admin&code="
    pwd_admin  = ""
    ct_admin = generate_guest_token(name_admin, pwd_admin)
    cblocks_admin = _blocks(ct_admin)

    # The 'role=admin&code=' block starts after "name=" + "A"*11 (5 + 11 = 16) → block 1
    admin_block_idx = (len("name=") + 11) // BLOCK
    admin_block = cblocks_admin[admin_block_idx]

    # Cut-and-paste the admin role block into the baseline ciphertext
    forged_blocks = list(cblocks_base)
    forged_blocks[role_block_idx] = admin_block
    forged_ct = b"".join(forged_blocks)

    # Return forged ciphertext and the baseline
    return forged_ct, base_name, base_pwd

def guess_code_cbc(generate_guest_token: Callable, read_token: Callable) -> str:

    BLOCK = 16
    MAX_TRIES = 5  # how many full re-attempts with different token layouts

    def split_blocks(b: bytes) -> list[bytes]:
        return [b[i:i+BLOCK] for i in range(0, len(b), BLOCK)]

    def pkcs7_strip(data: bytes) -> bytes:
        if not data:
            return data
        pad = data[-1]
        if pad < 1 or pad > BLOCK:
            return data
        if all(x == pad for x in data[-pad:]):
            return data[:-pad]
        return data

    def is_padding_valid(enc: bytes, nm: str, pw: str) -> bool:
        resp = read_token(enc, nm, pw)
        return not str(resp).startswith("incorrect padding")

    def recover_with_ciphertext(enc: bytes, name: str, pwd: str) -> str:
        C = split_blocks(enc)
        n = len(C)

        recovered_P = [b"" for _ in range(n)]

        # Decrypt from last block down to block 1 (P0 would require IV control)
        for t in range(n - 1, 0, -1):
            Cprev_orig = C[t - 1]
            Ct = C[t]
            I = [0] * BLOCK  # intermediate bytes for Ct: I = D(Ct)

            for pad_len in range(1, BLOCK + 1):
                j = BLOCK - pad_len

                # Build a fresh tail that forces P'[k] = pad_len for k>j
                # C_prev'[k] = I[k] XOR pad_len
                tail = bytearray(Cprev_orig)
                for k in range(BLOCK - 1, j, -1):
                    tail[k] = (I[k] ^ pad_len)

                found = False
                ok_hits = 0

                for guess in range(256):
                    trial = bytearray(tail)
                    trial[j] = guess

                    test_ct = bytes().join([*C[:t-1], bytes(trial), Ct])
                    ok = is_padding_valid(test_ct, name, pwd)
                    if not ok:
                        continue
                    ok_hits += 1

                    # I was getting some errors in some more edge cases - this is an attempt to try and remedy those
                    if pad_len == 1:
                        # Flip the SAME byte with ^0x80 to force last byte >16 => must be invalid padding
                        verify = bytearray(trial)
                        verify[j] ^= 0x80
                        verify_ct = bytes().join([*C[:t-1], bytes(verify), Ct])
                        if is_padding_valid(verify_ct, name, pwd):
                            # Still valid, continue searching
                            continue
                    else:
                        # Flip one of the pad-tail bytes (e.g., last) with ^0x80 to break equality with pad_len
                        verify = bytearray(trial)
                        flip_pos = BLOCK - 1  # last byte is always in the pad tail for pad_len>=2
                        verify[flip_pos] ^= 0x80
                        verify_ct = bytes().join([*C[:t-1], bytes(verify), Ct])
                        if is_padding_valid(verify_ct, name, pwd):
                            # Still valid, continue searching
                            continue

                    # Verified candidate
                    I[j] = pad_len ^ trial[j]
                    found = True
                    break

                if not found:
                    raise RuntimeError(f"Unrecoverable byte j={j} in block P{t}")

            # Recover plaintext block: P_t = I XOR Cprev_orig
            Pt = bytes((I[b] ^ Cprev_orig[b]) for b in range(BLOCK))
            recovered_P[t] = Pt

        # clean and decode
        tail = b"".join(recovered_P[1:])
        tail_stripped = pkcs7_strip(tail)
        tail_text = tail_stripped.decode("ascii", errors="replace")

        # Extract code= (32 Base64)
        marker = "code="
        idx = tail_text.find(marker)
        if idx == -1:
            bi = tail_stripped.find(b"code=")
            if bi == -1:
                raise RuntimeError("Could not find 'code=' in recovered plaintext tail.")
            start = bi + 5
            code = tail_stripped[start:start + 32].decode("ascii", errors="strict")
        else:
            start = idx + len(marker)
            code = tail_text[start:start + 32]

        if len(code) != 32:
            raise RuntimeError(f"Extracted code length != 32: '{code}'")

        return code

    # Outer retry loop in case we fail for some reason - we use a fresh layout, I think we might be able to remove this but wanted to be safe
    for attempt in range(1, MAX_TRIES + 1):
        name = ""
        pwd_len = random.randint(0, 7)
        pwd = "X" * pwd_len
        enc = generate_guest_token(name, pwd)

        try:
            return recover_with_ciphertext(enc, name, pwd)
        except RuntimeError as e:
            print(f"[RETRY] Attempt {attempt} failed: {e}")

    raise RuntimeError("CBC padding-oracle attack failed after multiple attempts.")

def forge_admin_token_ctr(generate_guest_token: Callable, read_token: Callable) -> tuple[bytes, str, str]:
    
    name = 'alice'
    pwd = 'wonderland'
    
    guest_token = generate_guest_token(name, pwd)
    
    template_prefix = f"name={name}&pwd=wonde"
    segment_offset = len(template_prefix)  # Offset where "rland" starts
    
    
    old_segment = b"rland&role=guest"  # 17 bytes  
    new_segment = b"&role=superadmin&"  # 17 bytes
    
    
    modified_token = bytearray(guest_token)
    for i in range(len(old_segment)):
        modified_token[segment_offset + i] ^= old_segment[i] ^ new_segment[i]

    modified_pwd = "wonde"
    return bytes(modified_token), name, modified_pwd

