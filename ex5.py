#!/usr/bin/python

# Repeating key XOR encrypter
import re
import base64
import sys
import operator

class CXorEncrypt:
	def __init__(self,inplainstr,inkey):
		self.ciphtext = ''
		self.key = inkey
		self.ptext = inplainstr
		
	def calculate(self):
		keylen = len(self.key)
		i = 0
		#self.ciphtext = ''.join([chr(ord(byte)^ord(self.key[i%keylen]) for byte in self.ptext])
		for byte in self.ptext:
			k = i % keylen
			self.ciphtext += chr(ord(byte)^ord(self.key[k]))
			i += 1
		#print self.ciphtext	
	def hexdump(self,str):
		hexstr = ''.join(["%02x" % ord(x) for x in str])	
		return hexstr
	
	def getciphertext(self):
		return self.ciphtext

class Usage(Exception):
	def __init__(self, msg):
		self.msg = msg

def main(argv=None):
	if argv is None:
		argv = sys.argv
	try:
		try:
			c = CXorEncrypt(argv[1],argv[2])
			c.calculate()
			print c.hexdump(c.getciphertext())
		except IOError:
			print >>sys.stderr, "ERROR: %s" % sys.exc_info()[1]
			raise Usage(sys.exc_info()[0])
		except IndexError:
			raise Usage(sys.exc_info()[0])
        		# more code, unchanged
		except ValueError as v:
			print >>sys.stderr, "ERROR: digits 0-9 and a-f are only allowed in hex input!\n"
			print >>sys.stderr, "Value error {0} : {1}".format(sys.exc_info()[1],sys.exc_info()[2])
			raise Usage(sys.exc_info()[0])
    	except Usage, err:
        	print >>sys.stderr, "Usage: ex5.py <ASCII-inputstring> <ASCII-repeatingkey>"
        	return 2

if __name__ == "__main__":
	sys.exit(main())		
