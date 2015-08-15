#!/usr/bin/python
# Hex to Base64 encoder
import re
import base64
import sys

class CBase64:
	def __init__(self,initstr):
		self.rawstr = initstr
		self.modstr = ''
		self.base64str = ''
	def encode(self):
		#print 'Input %s ' % self.rawstr
		bytelist = re.findall('..',self.rawstr)
		for bytes in bytelist:
			self.modstr += chr(int('0x'+bytes,16))
		self.base64str =  base64.b64encode(self.modstr)
		return self.base64str
	def decode(self):
		return base64.b64decode(rawstr)
class Usage(Exception):
	def __init__(self, msg):
		self.msg = msg

def main(argv=None):
	if argv is None:
		argv = sys.argv
	try:
		try:
			b = CBase64(argv[1])
			print b.encode()
		except IndexError as e:
			raise Usage(sys.exc_info()[0])
        		# more code, unchanged
		except ValueError as v:
			print >>sys.stderr, "ERROR: digits 0-9 and a-f are only allowed in hex input!\n"
			raise Usage(sys.exc_info()[0])
    	except Usage, err:
        	print >>sys.stderr, "Usage: ex1.py <inputstring>"
        	return 2

if __name__ == "__main__":
	sys.exit(main())		
