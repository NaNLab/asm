# coding: utf-8


#-----------------------------------------------------------------------------------------
# ComputerRam
#-----------------------------------------------------------------------------------------
class ComputerRam:
	def __init__(self, size, printfunction = None, printdisplayfunction = None):
		self.RamSize = size
		self.RAM = [[0x00,"----"] for _ in range(size)]
		self.RamShowHexa = True							# True = hexa; False = source
		self.printfun = printfunction					# function used to print/refresh the part of screen corresponding to the Ram
		self.printdisplayfun = printdisplayfunction		# function used to print/refresh the display corresponding to the video Ram
	
	def print(self,*args):
		self.printfun(self,*args)
	
	def printdisplay(self,*args):
		self.printdisplayfun(self,*args)
	
	def size(self):
		return self.RamSize

	def switchRamShowHexaSource(self):
		self.RamShowHexa = not(self.RamShowHexa)
	
	def __getitem__(self, key):
		return self.RAM[key][0]

	def getCh(self, key):
		return self.RAM[key][1]

	def setCh(self, key, ch):
		self.RAM[key][1] = ch

	def __setitem__(self, key, value):
		""" either assign a list of two elements, or just an hexa value:
			myRam[3] = 0x05
			myRam[7] = [0x09,"ok"] """
		if type(value) is list:
			self.RAM[key] = value[:]	# make a real copy
		else:
			self.RAM[key][0] = value
			self.RAM[key][1] = format(value, '02X')
#-----------------------------------------------------------------------------------------




#-----------------------------------------------------------------------------------------
# ComputerRegisters
#-----------------------------------------------------------------------------------------
class ComputerRegisters:
	def __init__(self, reglist, printfunction = None):
		self.registerslist = reglist
		self.registers = dict()
		for reg in self.registerslist:
			self.registers[reg] = 0x00 								# register contains an integer in range 0..255
		self.registers["SP"] = 0xBF									# Stack Pointer register starts at address BF
		self.printfun = printfunction
	
	def print(self,*args):
		self.printfun(self,*args)
	
	def reglist(self):
		return self.registerslist

	
	def __getitem__(self, key):
		return self.registers[key]

	def __setitem__(self, key, value):
		self.registers[key] = value
#-----------------------------------------------------------------------------------------
