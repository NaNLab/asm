# coding: utf-8


#-----------------------------------------------------------------------------------------	
def comp2toint(val, bits=8):
	"""	Given a number 'val' in two's complement representation, returns the corresponding integer
		http://stackoverflow.com/questions/1604464/twos-complement-in-python """
	if (val & (1 << (bits - 1))) != 0: # if sign bit is set e.g., 8bit: 128-255
		val = val - (1 << bits)        # compute negative value
	return val                         # return positive value as is


def inttocomp2(n, bits=8):
	""" Given a number 'n', returns the two's complement representation of 'n' """
	return n + (1 << bits) if n<0 else n
#-----------------------------------------------------------------------------------------



