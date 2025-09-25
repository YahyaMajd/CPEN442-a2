# File to complete by the students
from typing import Callable
from Crypto.Cipher import AES
import string


def guess_code_ecb(generate_guest_token: Callable, read_token: Callable) -> str:
    alphabet = string.ascii_letters + string.digits + "+/="
    
    # Get reference token to identify target block containing first character
    ref_name = "simon"
    ref_pwd = "password1234567"
    ref_token = generate_guest_token(ref_name, ref_pwd)
    target_block = ref_token[32:48]  # Block 2: "ole=guest&code=" + first_char
    
    # ECB byte-at-a-time attack: try each character
    for ch in alphabet:
        # Attack pattern discovered through systematic testing:
        # Name: 6 A's, Password: "ole=guest&code=" + test_char + padding
        # This creates block 1 with content "ole=guest&code=" + ch
        
        test_name = "A" * 6
        test_pwd = "ole=guest&code=" + ch + "BBBBBBBBB"
        
        test_token = generate_guest_token(test_name, test_pwd)
        test_block = test_token[16:32]  # Block 1
        
        if test_block == target_block:
            return ch  # Found the first character!
    
    return '?'  # Failed to find first character


def forge_admin_token_ecb(generate_guest_token: Callable, read_token: Callable) -> tuple[bytes, str, str]:
    return bytes(0), 'name', 'pwd'

def guess_code_cbc(generate_guest_token: Callable, read_token: Callable) -> str:
    return ''

def forge_admin_token_ctr(generate_guest_token: Callable, read_token: Callable) -> tuple[bytes, str, str]:
    
    name = 'alice'
    pwd = 'wonderland'
    
    
    guest_token = generate_guest_token(name, pwd)
    
    # The token structure is: "name=alice&pwd=wonderland&role=guest&code=XXXXX"
    # We know the exact offset where "guest" starts
    template_prefix = f"name={name}&pwd={pwd}&role="
    guest_offset = len(template_prefix)
       
    role_offset = template_prefix.index("role=")
    old_segment = b"role=guest"  # 10 bytes
    new_segment = b"role=admin"  # 10 bytes
    
    # Apply bit-flipping attack
    modified_token = bytearray(guest_token)
    for i in range(len(old_segment)):
        modified_token[role_offset + i] ^= old_segment[i] ^ new_segment[i]
    
    return bytes(modified_token), name, pwd

