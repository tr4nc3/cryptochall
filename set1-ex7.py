#!/usr/bin/python3
from cryptopals import stringprocess as sp
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
import base64

backend = default_backend()
key = b'YELLOW SUBMARINE'
cipher = Cipher(algorithms.AES(key), modes.ECB(), backend=backend)
dec = cipher.decryptor()

f = open('s01ex07.txt','r')
p = b''
for line in f:
    p += dec.update(base64.b64decode(line))
p += dec.finalize()
print(p)
f.close()


f = open('s01ex07.txt','r')
p = b''
lines = f.read()
p = sp.aes_ecb_decrypt(base64.b64decode(lines.rstrip()),key)
print(p)
f.close()
