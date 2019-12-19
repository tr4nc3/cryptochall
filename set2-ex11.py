#!/usr/bin/python3
from cryptopals import stringprocess as sp

import struct
import os

str1 = b'Test input'
str2 = b'Test input #2'
BLOCKLEN = 16

cointoss = struct.unpack('<I',os.urandom(4))[0]

key = os.urandom(16)
iv = os.urandom(16)

prefixlen = 0
suffixlen = 0

while not 5 <= prefixlen <= 10:
    prefixlen = struct.unpack('<I',os.urandom(4))[0] % 10
while not 5 <= suffixlen <= 10:
    suffixlen = struct.unpack('<I',os.urandom(4))[0] % 10

prefix = os.urandom(prefixlen)
suffixlen = os.urandom(suffixlen)

if cointoss % 2 == 0:
    sp.aes_ecb_encrypt(sp.pkcs7pad(prefix+str1+suffix),key)
else:
    sp.aes_cbc_encrypt(iv,sp.pkcs7pad(prefix+str1+suffix),key)
