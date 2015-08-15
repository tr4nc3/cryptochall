#!/usr/bin/python

# XOR decrypter
import re
import base64
import sys
import operator

class CXorDecrypter:
	def __init__(self,str1):
		self.ciphtext = str1
		self.temptxt = ''
		self.key = 0
		self.top7 = ''
		self.ptext = ''
	def calculate(self):
		#print 'Input %s ' % self.ciphtext
		asciicount = 0
		minout = 65536
		ciphbytes = re.findall('..',self.ciphtext)
		#i = 0
		for keyguess in xrange(256):
			self.temptxt = ''
			i = 0 
			for bytes in ciphbytes:
				pbyte = chr(int('0x'+bytes,16)^keyguess)	
				self.temptxt += pbyte
				if ord(pbyte) > 31:
					if ord(pbyte) < 127:
						asciicount += 1
				i += 1
			#if asciicount == len(ciphbytes):
			#	self.key = keyguess
			output =  self.runmetrics(self.temptxt)
			if output < 65536:
				if minout > output:
					self.key = keyguess
					minout = output
					self.ptext = self.temptxt
				#print "Number: %f; Top 4: \"%s\"" % (output,self.top7)
				#print "Key: %d, ASCII: %d, plain: %s\n" % (keyguess,asciicount,self.temptxt)
			else:
				pass
				#print>>sys.stderr, "*** Number: %f; Top 4: \"%s\"" % (output,self.top7)
				#print>>sys.stderr, "*** Key: %d, ASCII: %d, plain: %s\n" % (keyguess,asciicount,self.temptxt)
			asciicount = 0
		return self.temptxt
	def hexdump(self,str):
		hexstr = ''.join(["%02x" % ord(x) for x in str])	
		return hexstr
	def keyguess(self):
		return self.key
	def runmetrics(self,text):
		goodletters = {chr(x):0 for x in xrange(32,123)}
		score = 0 
		for byte in text.lower():
			if ord(byte) > 31 and ord(byte) < 123:
				goodletters[byte] += 1	
			else:
				self.top7 = None
				return 65536
		freq = sorted(goodletters.iteritems(),key=operator.itemgetter(1),reverse=True)
		self.top7 = ''
		for n in xrange(8):
			self.top7 += freq[n][0] 
		order = [b for b in ' etaoinshrdlucmfywgpbvkxqjz\'!/?:";></{}[]+-=)(*&^%$#@\~`']
		# http://www.math.cornell.edu/~mec/2003-2004/cryptography/subs/frequencies.html
		# TBD: Create a statistically sound weighting function 
		score = 0 
		for n in xrange(0,5):
			score += (5-n)*(order.index(self.top7[n]))	
				
#		if order.index(freq[0][0]) == 0 or order.index(freq[0][0]) == 1:
#			if order.index(freq[1][0]) == 1 or order.index(freq[1][0]) == 2:
#				return 1
#			elif order.index(freq[1][0]) == 2 or order.index(freq[1][0]) == 3:
#				return 0.5
#			elif order.index(freq[2][0]) == 3 or order.index(freq[1][0]) == 4:
#				return 0.25
#		if len(self.top7) == 4:
#			return 0.1
		return score
	def getplain(self):
		return self.ptext
class Usage(Exception):
	def __init__(self, msg):
		self.msg = msg

def main(argv=None):
	if argv is None:
		argv = sys.argv
	try:
		try:
			b = CXorDecrypter(argv[1])
			b.calculate()
			#b.hexdump()
			print "Keyguess : %d" % b.keyguess()
			print "Plaintext: %s" % b.getplain()
		except IndexError:
			raise Usage(sys.exc_info()[0])
        		# more code, unchanged
		except ValueError as v:
			print >>sys.stderr, "ERROR: digits 0-9 and a-f are only allowed in hex input!\n"
			print >>sys.stderr, "Value error {0}:{1}".format(sys.exc_info()[1],sys.exc_info()[2])
			raise Usage(sys.exc_info()[0])
    	except Usage, err:
        	print >>sys.stderr, "Usage: ex3.py <inputstring>"
        	return 2

if __name__ == "__main__":
	sys.exit(main())		
