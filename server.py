from Crypto.Random import get_random_bytes
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
import base64


class Server():

    def __init__(self, mode_of_operation: str = 'ECB'):
        self.key = get_random_bytes(AES.block_size)
        self.iv = get_random_bytes(16) # This is for CBC.
        self.nonce = get_random_bytes(8) # This is for CTR.
        self.code = base64.b64encode(get_random_bytes(24)).decode('ascii')
        self.mode = mode_of_operation

    def _get_fresh_cipher(self):
        match self.mode:
            case 'ECB':
                return AES.new(self.key, AES.MODE_ECB)
            case 'CBC':
                return AES.new(self.key, AES.MODE_CBC, iv=self.iv)
            case 'CTR':
                return AES.new(self.key, AES.MODE_CTR, nonce=self.nonce)
            case _:
                raise ValueError('Unknown mode of operation')

    def generate_guest_token(self, name: str, pwd: str) -> bytes:
        """Receives name and password strings, and returns an encrypted user token."""
        token = f'name={name}&pwd={pwd}&role=guest&code={self.code}' # generate token
        
        self.nonce = get_random_bytes(8) # Fresh nonce
        cipher = self._get_fresh_cipher()
        if self.mode.startswith('CTR'):
            return cipher.encrypt(token.encode('ascii'))
        else:
            padded_token = pad(token.encode('ascii'), AES.block_size)
            return cipher.encrypt(padded_token)

    def read_token(self, enc_token: bytes, name: str, pwd: str) -> str:
        """Process an encrypted token and, if correct, returns the role in the token."""
        cipher = self._get_fresh_cipher()
        try:
            if self.mode.startswith('CTR'):
                token = cipher.decrypt(enc_token).decode('ascii')
            else:
                padded_token = cipher.decrypt(enc_token)
                token = unpad(padded_token, AES.block_size).decode('ascii')
            data = {kv.split('=')[0]: kv.split('=')[1] for kv in token.split('&')}
            assert 'name' in data
            assert 'pwd' in data
            assert 'role' in data
            assert 'code' in data
            if data['name'] != name:
                return 'wrong name'
            if data['pwd'] != pwd:
                return 'wrong pwd' # Incorrect password
            elif data['code'] != self.code:
                return 'wrong code' # Incorrect server code
            else:
                return data['role'] # Returning role
        except Exception as e:
            if "adding is incorrect" in str(e):
                return f'incorrect padding {str(e)}'
            elif "Decrypt error" in str(e):
                return f'decrypt error {str(e)}'
            else:
                return f'other error {str(e)}'