#!/usr/bin/python3
import binascii

keysize = [16, 24, 32]
k = 16
f = open('s01ex08.txt','r')
i = 0
for line in f:
    # for k in keysize:
    for j in range(k):
        chars = set()
        sl = binascii.unhexlify(line.rstrip())[j::k]
        for x in sl:
            chars.add(x)
        #print('Line : {0},  len({1}) = {2}'.format(i,sl,len(sl)))
        if len(chars) < len(sl)-3:
            print ('Line {0} : {1} , {2} is ECB encrypted'.format(i, line.rstrip(),sl))
    i += 1

