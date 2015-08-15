#!/usr/bin/python
# XOR encryptor
import re
import base64
import sys

class CXor:
	def __init__(self,str1,str2):
		self.ptext= str1
		self.key = str2
		self.ciphtext = ''	
	def calculate(self):
		#print 'Input %s ' % self.rawstr
		ptexbytes = re.findall('..',self.ptext)
		keybytes = re.findall('..',self.key)
		i = 0
		for bytes in ptexbytes:
			self.ciphtext += chr(int('0x'+bytes,16)^int('0x'+keybytes[i],16))
			i = i + 1
		return self.ciphtext
	def hexdump(self):
		hexstr = ''
		#for i in range(len(self.ciphtext)):
		#hexstr += '%02X' % self.ciphtext[i]
		hexstr = ''.join(["%02x" % ord(x) for x in self.ciphtext])	
		print hexstr
class Usage(Exception):
	def __init__(self, msg):
		self.msg = msg

def main(argv=None):
	if argv is None:
		argv = sys.argv
	try:
		try:
			if (len(argv[1]) == len(argv[2])):
				b = CXor(argv[1],argv[2])
				b.calculate()
				b.hexdump()
			else:
				print >>sys.stderr, "ERROR: unequal lengths for two strings"
		except IndexError as e:
			raise Usage(sys.exc_info()[0])
        		# more code, unchanged
		except ValueError as v:
			print >>sys.stderr, "ERROR: digits 0-9 and a-f are only allowed in hex input!\n"
			raise Usage(sys.exc_info()[0])
    	except Usage, err:
        	print >>sys.stderr, "Usage: ex2.py <inputstring> <keystring>"
        	return 2

if __name__ == "__main__":
	sys.exit(main())		
