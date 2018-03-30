# coding: utf-8

from simcomputer import ComputerRam, ComputerRegisters
from simgui import printRam, printRegisters, printDisplay

#-----------------------------------------------------------------------------------------
RAM_SIZE = 256	# size of RAM
#-----------------------------------------------------------------------------------------

global RAM, reglist, registers

RAM = ComputerRam(RAM_SIZE, printfunction=printRam, printdisplayfunction = printDisplay)		# the RAM of our machine
reglist = [0x00, 0x01, 0x02, 0x03, "IP", "SP", "SR"]											# list of the available registers (0x00=AL, ..., 0x03=CL)
registers = ComputerRegisters(reglist, printfunction=printRegisters)							# machine's registers

