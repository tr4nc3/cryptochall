#!/usr/bin/python3
from cryptopals import stringprocess as sp
import base64 

BLOCKSIZE = 16

f = open('s02ex10.txt','r')

contentbytes = base64.b64decode(f.read())
#contentbytes = contentbytes.replace(b'\n',b'')
print('Len(ciphertext)={0}'.format(len(contentbytes)))
iv = b'\x00' * BLOCKSIZE
pt = sp.aes_cbc_decrypt(iv, contentbytes,'YELLOW SUBMARINE'.encode('utf-8'))
print('{0}'.format(pt))
f.close()