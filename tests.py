import attacker
from server import Server
from time import time


def test_guess_code_ecb():

    server = Server('ECB')
    code = attacker.guess_code_ecb(server.generate_guest_token, server.read_token)
    
    # Grade the result of your attack
    print(f'  Server code={server.code}, recovered code={code}')
    if server.code == code:
        return 1.
    if len(code)>0 and server.code[0] == code[0]:
        return 0.5
    return 0.

def test_forge_token_ecb():

    server = Server('ECB')
    enc_token, name, pwd = attacker.forge_admin_token_ecb(server.generate_guest_token, server.read_token)

    # Grade the result of your attack
    result = server.read_token(enc_token, name, pwd)
    print(f'  Server output from forged token: {result}')
    if result == 'user':
        return 0.
    elif result == 'admin':
        return 1.
    else:
        return 0.

def test_guess_code_cbc():

    server = Server('CBC')
    code = attacker.guess_code_cbc(server.generate_guest_token, server.read_token)
    print(f'  Server code={server.code}, recovered code={code}')
    
    # Grade the result of your attack
    if server.code == code:
        return 1.
    if len(code)>0 and server.code[-1] == code[-1]:
        return 0.5
    return 0.


def test_forge_token_ctr(debug: float = False):

    server = Server('CTR')
    enc_token, name, pwd = attacker.forge_admin_token_ctr(server.generate_guest_token, server.read_token)

    # Grade the result of your attack
    result = server.read_token(enc_token, name, pwd)
    print(f'  Server output from forged token: {result}')
    if result == 'user':
        return 0.
    elif result == 'admin':
        return .8
    elif result == 'superadmin':
        return 1.
    else:
        return 0.



if __name__=="__main__":
    
    t0 = time()
    print(f'ECB code: {test_guess_code_ecb():.1%}, elapsed time {time()-t0:.1}s')
    print(f'ECB forge: {test_forge_token_ecb():.1%}, elapsed time {time()-t0:.1}s')
    print(f'CBC code: {test_guess_code_cbc():.1%}, elapsed time {time()-t0:.1}s')
    print(f'CTR forge: {test_forge_token_ctr():.1%}, elapsed time {time()-t0:.1}s')