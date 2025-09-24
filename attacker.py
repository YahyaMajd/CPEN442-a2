# File to complete by the students
from typing import Callable
from Crypto.Cipher import AES

def guess_code_ecb(generate_guest_token: Callable, read_token: Callable) -> str:
    return ''

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

