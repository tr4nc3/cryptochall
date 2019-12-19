#!/usr/bin/python3

from cryptopals import stringprocess as sp

BLOCKLEN = 16

str1 = "YELLOW SUBMARINE"
str2 = "Rajat Swarup"
str3 = "a"
str4 = "a" * 32
print('PKCS padded form of {0} is {1}'.format(str1, sp.pkcs7pad(str1.encode('utf-8'),BLOCKLEN)))
print('PKCS padded form of {0} is {1}'.format(str2, sp.pkcs7pad(str2.encode('utf-8'),BLOCKLEN)))
print('PKCS padded form of {0} is {1}'.format(str3, sp.pkcs7pad(str3.encode('utf-8'),BLOCKLEN)))
print('PKCS padded form of {0} is {1}'.format(str4, sp.pkcs7pad(str4.encode('utf-8'),BLOCKLEN)))

BLOCKLEN = 20
print('PKCS padded form of {0} is {1}'.format(str1, sp.pkcs7pad(str1.encode('utf-8'),BLOCKLEN)))
print('PKCS padded form of {0} is {1}'.format(str2, sp.pkcs7pad(str2.encode('utf-8'),BLOCKLEN)))
print('PKCS padded form of {0} is {1}'.format(str3, sp.pkcs7pad(str3.encode('utf-8'),BLOCKLEN)))
print('PKCS padded form of {0} is {1}'.format(str4, sp.pkcs7pad(str4.encode('utf-8'),BLOCKLEN)))