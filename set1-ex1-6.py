#!/bin/python
import binascii
import base64
from cryptopals import stringprocess as sp
import itertools

# example 1
ch1_set1_input = '49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d'
ch1_set1_output = sp.encode_str2b64(ch1_set1_input)
print(ch1_set1_output)

# example 2 
print(binascii.hexlify(sp.fixed_xor_bytes(sp.str_to_bytes('1c0111001f010100061a024b53535009181c'),sp.str_to_bytes('686974207468652062756c6c277320657965'))) )

# example 3
ct = sp.str_to_bytes('1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736')
test = sp.most_likely_decryption_repkey(ct)
print(test[0])

# example 4
test = []
file_count = []
pt_to_ct = {}
max_score = []
max_key = []
max_ct = []
max_pt = [] 
output = []
ctfile = open('s01ex04.txt','r')
for line in ctfile:
    #print('{0} = {1}'.format(len(line),line))
    output = sp.most_likely_decryption_repkey(sp.str_to_bytes(line.rstrip()))
    file_count.extend(output[0:4])
    for item in output[0:4]:
        pt_to_ct[str(item[2])] = line.rstrip()
#print(file_count)
final_list = []
print('\r\n==========================r\n')
#print(sorted(file_count, key=lambda x: x[1], reverse=True))
for k,v,r in sorted(file_count, key=lambda x: x[1], reverse=True):
    final_list.extend([k,v,r])
    #print('{0} {1} {2} {3}'.format(k,v,r,pt_to_ct[str(r)]))

ctfile.close()
# example 5
str1 = 'Burning \'em, if you ain\'t quick and nimble' +'\n' + 'I go crazy when I hear a cymbal'

print(sp.str_to_hex(sp.rep_strkey_xor(str1.encode('utf-8'),'ICE'.encode('utf-8'))))
#print(sp.str_to_hex(sp.rep_strkey_xor(str2.encode('utf-8'),'ICE'.encode('utf-8'))))

# example 6
str2 = 'this is a test'
str3 = 'wokka wokka!!!'
print('[+] Hamming distance is {0}'.format(sp.hamming_distance(str2.encode('utf-8'),str3.encode('utf-8'))))

# example 7
# read N lines to make a determination
N = 50
with open('s01e06.txt','r') as repkeyfile:
    #head = [ next(repkeyfile) for x in range(N) ]
    head = repkeyfile.readlines()
#print(head)
samplestr = bytearray()
for x in head:
    samplestr += base64.b64decode(x.rstrip())
#print(samplestr)

keysizeguess = sp.guess_keysize(samplestr)
repkeyfile.close()
print('Keysizes : {0}'.format( [x for x in keysizeguess] ))
keysize_keyguess = {}
# try top 5 key size guesses
for i in range(3):
    keysize = keysizeguess[i][0]
    #print('Trying keysize({0})'.format(keysize))
    guess_key = dict()
    for index in range(keysize):
        #testbytes = sp.string_slicer(samplestr,keysize) # bytearr
        testbytes = samplestr[index::keysize]
        #print('Trying {0}, {1}'.format(testbytes,len(testbytes)))
        ml = sp.most_likely_decryption_repkey(testbytes)
        #print(' ==> ',ml)
        guess_key[index] = [ chr(ml[i][0]) for i in range(1) ]
    print('Guessed key {0}'.format(guess_key))
    keyguess_as_list = []
    for i in guess_key.keys():
        keyguess_as_list.append(guess_key[i])
    #print(keyguess_as_list)
    x = ''
    for trykey in itertools.product(*keyguess_as_list):
        if keysize not in keysize_keyguess:
            keysize_keyguess[keysize] = []
        #print(''.join(trykey))
        #for j in range(keysize):
        #    x += str(guess_key[j][0])
        #print('Key = {0}'.format(x))
        keysize_keyguess[keysize].append(''.join(trykey))
#print(keysize_keyguess)
i = 0
for samplekey in keysize_keyguess.items():
    print('Trying {0} - {1}'.format(i,samplekey[1]))
    print(sp.rep_strkey_xor(samplestr,bytes(''.join(samplekey[1]).encode('utf-8'))))
    i += 1
