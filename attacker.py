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
    return bytes(0), 'name', 'pwd'

