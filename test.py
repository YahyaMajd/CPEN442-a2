from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from Crypto.Random import get_random_bytes
import base64
plaintext11 = b'hello, world!'
# Pad
padded_plaintext = pad(plaintext11, AES.block_size)
plaintextb64 = base64.b64encode(padded_plaintext)
print(padded_plaintext)
print(plaintextb64)
print("------------PADDED-----------------")
# Encrypt
key = get_random_bytes(AES.block_size)
cipher = AES.new(key, AES.MODE_ECB)
ciphertext = cipher.encrypt(padded_plaintext)
print(ciphertext)
# Decrypt
decipher = AES.new(key, AES.MODE_ECB)
decrypted_padded_plaintext = decipher.decrypt(ciphertext)
print(decrypted_padded_plaintext)
# Unpad
decrypted_plaintext = unpad(decrypted_padded_plaintext, AES.block_size)
print(decrypted_plaintext)
print("------------UNPADDED-----------------")
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
plaintext11 = b'hello, world!!!!'
plaintext12 = b'hello, world!!'
print(base64.b64encode(plaintext11))
print(base64.b64encode(plaintext12))
key = get_random_bytes(AES.block_size)
cipher = AES.new(key, AES.MODE_ECB)
ciphertext = cipher.encrypt(plaintext11)
print(ciphertext)
# Decrypt
decipher = AES.new(key, AES.MODE_ECB)
decrypted_padded_plaintext = decipher.decrypt(ciphertext)
print(decrypted_padded_plaintext)




def detect_ecb(cipher_b64: str, block_size=16):
    # Decode from Base64 to raw bytes
    ciphertext = base64.b64decode(cipher_b64)
    # Break into blocks
    blocks = [ciphertext[i:i+block_size] for i in range(0, len(ciphertext), block_size)]
    # Count duplicates
    unique_blocks = set(blocks)
    num_repeats = len(blocks) - len(unique_blocks)
    return num_repeats

# Load ciphertexts
with open("ciphertext1.txt", "r") as f:
    c1 = f.read().strip()
with open("ciphertext2.txt", "r") as f:
    c2 = f.read().strip()
with open("ciphertext3.txt", "r") as f:
    c3 = f.read().strip()

# Detect repetitions
r1 = detect_ecb(c1)
r2 = detect_ecb(c2)
r3 = detect_ecb(c3)

print(f"Ciphertext1 repeats: {r1}")
print(f"Ciphertext2 repeats: {r2}")
print(f"Ciphertext3 repeats: {r3}")

# Decide which one is ECB
ecb_guess = max([(r1, "ciphertext1.txt"),
                 (r2, "ciphertext2.txt"),
                 (r3, "ciphertext3.txt")])
print(f"ECB detected in: {ecb_guess[1]}")


def print_blocks(data: str, block_size=16):
    data = base64.b64decode(data)
    blocks = [data[i:i+block_size] for i in range(0, len(data), block_size)]
    for i, block in enumerate(blocks):
        print(block)

# Example usage

# print_blocks(c1)
# print("-----")
# print_blocks(c2)
# print("-----")
# print_blocks(c3)