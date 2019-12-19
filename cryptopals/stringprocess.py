#!/bin/python
import base64
import binascii
import sys
import os

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend

# converts string to bytes
def str_to_bytes(s):
    """Given a string of ASCII characters, return a byte string"""
    return binascii.unhexlify(s)

# b64 encodes string
def encode_str2b64(s):
    return base64.b64encode(str_to_bytes(s))

# b - ASCII string
def str_to_hex(b):
    "Converts ascii str to hex"
    return binascii.hexlify(b)

# s - bytes
# d - bytes
def hamming_distance(s,d):
    """Calculates the hamming distance between two strings of same lenght"""
    if len(s) != len(d):
        return -1
    all_h = 0
    for a1,a2 in zip(s,d):
        v = a1^a2
        h = 0
        for i in range(8):
            h += ((v >> i) & 0x01)
        all_h += h
    return all_h

# s - source str
# k - key str
# return value - str rep of s ^ k 
# equal length strings expected 
def fixed_xor_str(s,k): #returns str object
    if len(s) != len(k):
        return ''
    s_bytes = str_to_bytes(s)
    k_bytes = str_to_bytes(k)
    pt_k_pair = zip(s_bytes,k_bytes)
    outlist = []
    for a1,a2 in pt_k_pair:
        outlist.append(a1 ^ a2)
    return ''.join([ chr(x) for x in outlist ])

# s - byte source str
# k - byte key str
# return value - bytearray rep of s ^ k
def fixed_xor_bytes(s,k): #returns bytearray object
    if len(s) != len(k):
        print('Error: srclen = {0}, {1}; keylen = {2} '.format(s,len(s),len(k)))
        return b''
    pt_k_pair = zip(s,k)
    outlist = []
    for a1,a2 in pt_k_pair:
        outlist.append(a1 ^ a2)
    return bytearray(outlist)

#freq_order = 'etaoinshrdlcumwfgypbvkjxqz' # this wasn't too successful
# http://www.math.cornell.edu/~mec/2003-2004/cryptography/subs/frequencies.html
#freq_order = ' etaoinshrdlucmfywgpbvkxqjzETAOINSHRDLUCMFYWGPBVKXQJZ,.\'?!;":-)(&0123456789'
freq_order = ' ETAOINSHRDLUCMFYWGPBVKXQJZetaoinshrdlucmfywgpbvkxqjz,.\'?!;":-)(&0123456789'
# s - str
# returns num of ascii chars
def score_str(s):
    i = 0
    for c in s:
        #if ( (ord(c)>=65 and ord(c)<=90) or (ord(c)>=97 and ord(c)<=122) or ord(c) == 32 ):
        if chr(c) in freq_order:
            i += 1
        else:
            if c > 127:  # the cipher text is ASCII - assumption, if we find anything else we negatively score to -ver infinity
                i -= 100000
        #else:
        #    i -= -2
    return i

# s - byte str
# k - byte
# bytesarr = s is a bytearray or not 
# returns bytearray of single char xor of s with k
def rep_key_xor(s,k):
    ctlen = len(s)
    return fixed_xor_bytes(s,k*ctlen)

# s - bytes representation of str
# k - bytes representation of key
# returns bytearray of repeating string key xor
def rep_strkey_xor(s,k):
    #ctbytes = str_to_bytes(s)
    ctlen = len(s)
    times = ctlen // len(k)
    sublen = ctlen % len(k)
    keystr = times*k + k[0:sublen]
    #print(s)
    #print(keystr)
    return fixed_xor_bytes(s,keystr)

# s - sample bytes string
def guess_keysize(s):
    keysize = range(1,41)
    sum_hamming = 0
    normalized_avg_hamming = {}
    for n in keysize:
        count = 0
        sum_hamming = 0
        for index in range(n):
            times = len(s)//n # number of times we can calculate the hamming distances
            for offset in range(times):
                if (index+n + offset*n) < len(s):
                    #print('keysize({0}) b/w s[{1}] s[{2}]'.format(n,index + offset*n,index+n + offset*n))
                    sum_hamming += hamming_distance(str(chr(s[index + offset*n])).encode('utf-8'),str(chr(s[index+n + offset*n])).encode('utf-8'))
                    #sum_hamming += hamming_distance(s[index:index + offset*n],s[index+n:index+n + offset*n])
                    count += 1
        normalized_avg_hamming[n] = (sum_hamming/count) #/n
    sorted_avg_hamming = []
    for k,v in sorted(normalized_avg_hamming.items(), key=lambda x: x[1],reverse=False):
        sorted_avg_hamming.append([k,v])
    return sorted_avg_hamming

# Finds the most likely xor character key for decryption
# s - encrypted bytes string
# returns a list of lists [key, num of ascii chars, plaintext] ordered by likelihood
def most_likely_decryption_repkey(s):
    """Creates a list of positional key guesses"""
    xor_res = dict()
    sorted_res = dict()
    retlist = list()
    for k in freq_order.encode('utf-8'):
        score = score_str(rep_key_xor(s,bytes([k])))
        xor_res[k] = score / len(s)
    for k,v in sorted(xor_res.items(), key=lambda x: x[1],reverse=True):
        sorted_res[k] = v
    #print(sorted_res)
    for i in sorted_res.keys():
        output = rep_key_xor(s,bytes([i]))
        #print('----\nkey: {0}, plain = {1}\n'.format(i,rep_key_xor(s,bytes([i]))))
        #output = rep_strkey_xor(s,len(s)*i,bytesarr) # rep_key_xor(s,i,bytesarr)
        retlist.append([i, score_str(output), output])
    return retlist

# s - bytes
# k - size 
def string_slicer(s,k):
    """Constructs a list of strings using the nth bytes"""
    samplestr = []
    times = len(s)//k
    for i in range(times):
        samplestr.extend(s[i*k])
    return samplestr

# s - bytes
# n - blocklen
def pkcs7pad(s,n):
    """Performs a PKCS#7 padding"""
    times = len(s)//n
    num = n - (len(s) % n )
    #if num == 0:
    #    pad = int(8).to_bytes(1,sys.byteorder) * 8
    #else:
    pad = num.to_bytes(1,sys.byteorder) * num
    return s + pad

# c - string in bytes
# k - key in bytes
def aes_ecb_decrypt(c,k):
    """Decrypts using AES ECB Mode"""
    backend = default_backend()
    cipher = Cipher(algorithms.AES(k), modes.ECB(), backend=backend)
    dec = cipher.decryptor()
    p = dec.update(c) + dec.finalize()
    return p


# s - string in bytes
# k - key in bytes
def aes_ecb_encrypt(s,k):
    """Encrypts using AES key k in Electronic Code Book (ECB) mode"""
    backend = default_backend()
    cipher = Cipher(algorithms.AES(k), modes.ECB(), backend=backend)
    enc = cipher.encryptor()
    p = enc.update(c) + enc.finalize()
    return p

# iv - initialization vector bytes
# s - plain text bytes expected
# k - key bytes
# returns ciphertext as bytes
def aes_cbc_encrypt(iv,s,k):
    """Perform AES CBC encryption using AES ECB mode"""
    BLOCKSIZE = 16
    src = pkcs7pad(s,BLOCKSIZE)
    aesstr = aes_ecb_encrypt(src,k)
    times = len(aesstr)//BLOCKSIZE
    init_vec = iv
    ct = b''
    for i in range(times):
        blockct = rep_strkey_xor(fixedaesstr[BLOCKSIZE*i:(BLOCKSIZE+1)*i],init_vec)
        ct += blockct
        init_vec = blockct
    return ct


# iv - initialization vector bytes
# s - ciphertext bytes expected
# k - key bytes
# returns plain text as bytes
def aes_cbc_decrypt(iv,c,k):
    """Perform AES CBC encryption using AES ECB mode"""
    BLOCKSIZE = 16
    if len(c) % BLOCKSIZE != 0:
        print('Error in blocksize len = {0} '.format(len(c),file=sys.stderr))
        return open("/dev/urandom","rb").read(BLOCKSIZE) # a choice made to return something as an error
    #print('{0}, {1} {2}'.format(iv,c,k))
    times = len(c)//BLOCKSIZE
    init_vec = iv
    pt = b''
    for i in range(times):
        pt += fixed_xor_bytes(aes_ecb_decrypt(c[BLOCKSIZE*i:(BLOCKSIZE)*(i+1)],k),init_vec)
        init_vec = c[BLOCKSIZE*i:(BLOCKSIZE)*(i+1)]
    return pt

# n - number of bytes
# returns random n bytes
def gen_random_bytes(n):
    return open("/dev/urandom","rb").read(n) # Using /dev/urandom so it does not block