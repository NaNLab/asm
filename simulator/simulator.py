# coding: utf-8
# version 1.3

# Bonne pratique pour le nommage :https://www.python.org/dev/peps/pep-0008/
# https://docs.python.org/3/library/zipapp.html
# séparer analyse lexicale et syntaxique


# https://asciinema.org/

# https://github.com/peterbrittain/asciimatics
# https://docs.python.org/3/howto/curses.html
# https://github.com/Chiel92/unicurses
# https://pdcurses.sourceforge.io/


# approche: isoler python
# 1) télécharger sur python.org (pour windows : https://www.python.org/downloads/windows/)
#	- la version embeddable zip file (soit en 32 bits, soit en 64 bits)
# 2) télécharger unicurses sur https://github.com/Chiel92/unicurses (archive en zip)
#	- la décompresser et mettre le répertoire unicurses dans le répertoire de Python

# Pour le debuggage :
#		printMessage(stdscr, str(...))
#		stdscr.getch()

# Parser :
#	http://pyparsing.wikispaces.com
#	http://shop.oreilly.com/product/9780596514235.do
#	http://stackoverflow.com/questions/37301142/how-to-parse-asm-file-and-get-opcode



from sys import argv
#import curses
import unicurses
import re

import time

import simvar as sv
from simgui import STRING_SIZE, createWindow, printMessage, getFromKeyboard, simwrapper
from simutils import comp2toint, inttocomp2




#-----------------------------------------------------------------------------------------
# Functions to read and write in SR (Status Register)
#-----------------------------------------------------------------------------------------
def setFlags_SR(*args):
	""" SR= ___ISOZ_, *args is given as couple (flagname,value) as ("Z", True) """
	registerVal = [int(bit) for bit in format(sv.registers["SR"], '08b')]
	for (flagname,value) in args:
		if flagname=="I":
			registerVal[3] = (1 if value else 0)
		elif flagname=="S":
			registerVal[4] = (1 if value else 0)
		elif flagname=="O":
			registerVal[5] = (1 if value else 0)
		elif flagname=="Z":
			registerVal[6] = (1 if value else 0)
		else:
			raise Exception("Unknown flag to set in register SR")
	sv.registers["SR"] = int( "".join(map(str, registerVal)) ,2)


def getFlag_SR(flagname):
	""" SR: ___ISOZ_ """
	registerVal = [int(bit) for bit in format(sv.registers["SR"], '08b')]
	
	if flagname=="I":
		return (registerVal[3]==1)
	elif flagname=="S":
		return (registerVal[4]==1)
	elif flagname=="O":
		return (registerVal[5]==1)
	elif flagname=="Z":
		return (registerVal[6]==1)
	else:
		raise Exception("Unknown flag to get in register SR")
#-----------------------------------------------------------------------------------------


#-----------------------------------------------------------------------------------------
# functions corresponding to the instructions supported by the CPU
#-----------------------------------------------------------------------------------------
# (Interrupt) If the I flag is set, the CPU will respond to hardware interrupts
# (Sign)      If a calculation gives a negative answer, the S flag is set
# (Overflow)  If a calculation overflows, the O flag is set (i.e. a number not in [-128,+127]
# (Zero)      If a calculation gives a zero answer, the Z zero flag is set
#-----------------------------------------------------------------------------------------

def ARITH(operator,op1,op2):
	""" en binaire, en complément à deux """
	res = operator(comp2toint(op1), comp2toint(op2))
	return (inttocomp2(res), res<0, (res < -128) or (res > 127), res==0)


def fun_ADD_rr(arg1,arg2):
	op1 = sv.registers[arg1]
	op2 = sv.registers[arg2]
	(sv.registers[arg1],S,O,Z) = ARITH( (lambda x,y:x+y) , op1,op2)
	setFlags_SR( ("S",S), ("O",O), ("Z",Z) )
	sv.registers["IP"] += 3

def fun_ADD_rd(arg1,arg2):
	op1 = sv.registers[arg1]
	op2 = arg2
	(sv.registers[arg1],S,O,Z) = ARITH( (lambda x,y:x+y) , op1,op2)
	setFlags_SR( ("S",S), ("O",O), ("Z",Z) )
	sv.registers["IP"] += 3

def fun_SUB_rr(arg1,arg2):
	op1 = sv.registers[arg1]
	op2 = sv.registers[arg2]
	(sv.registers[arg1],S,O,Z) = ARITH( (lambda x,y:x-y) , op1,op2)
	setFlags_SR( ("S",S), ("O",O), ("Z",Z) )
	sv.registers["IP"] += 3

def fun_SUB_rd(arg1,arg2):
	op1 = sv.registers[arg1]
	op2 = arg2
	(sv.registers[arg1],S,O,Z) = ARITH( (lambda x,y:x-y) , op1,op2)
	setFlags_SR( ("S",S), ("O",O), ("Z",Z) )
	sv.registers["IP"] += 3

def fun_MUL_rr(arg1,arg2):
	op1 = sv.registers[arg1]
	op2 = sv.registers[arg2]
	(sv.registers[arg1],S,O,Z) = ARITH( (lambda x,y:x*y) , op1,op2)
	setFlags_SR( ("S",S), ("O",O), ("Z",Z) )
	sv.registers["IP"] += 3

def fun_MUL_rd(arg1,arg2):
	op1 = sv.registers[arg1]
	op2 = arg2
	(sv.registers[arg1],S,O,Z) = ARITH( (lambda x,y:x*y) , op1,op2)
	setFlags_SR( ("S",S), ("O",O), ("Z",Z) )
	sv.registers["IP"] += 3

def fun_DIV_rr(arg1,arg2):
	op1 = sv.registers[arg1]
	op2 = sv.registers[arg2]
	(sv.registers[arg1],S,O,Z) = ARITH( (lambda x,y:x//y) , op1,op2)
	setFlags_SR( ("S",S), ("O",O), ("Z",Z) )
	sv.registers["IP"] += 3

def fun_DIV_rd(arg1,arg2):
	op1 = sv.registers[arg1]
	op2 = arg2
	(sv.registers[arg1],S,O,Z) = ARITH( (lambda x,y:x//y) , op1,op2)
	setFlags_SR( ("S",S), ("O",O), ("Z",Z) )
	sv.registers["IP"] += 3

def fun_MOD_rr(arg1,arg2):
	op1 = sv.registers[arg1]
	op2 = sv.registers[arg2]
	(sv.registers[arg1],S,O,Z) = ARITH( (lambda x,y:x%y) , op1,op2)
	setFlags_SR( ("S",S), ("O",O), ("Z",Z) )
	sv.registers["IP"] += 3

def fun_MOD_rd(arg1,arg2):
	op1 = sv.registers[arg1]
	op2 = arg2
	(sv.registers[arg1],S,O,Z) = ARITH( (lambda x,y:x%y) , op1,op2)
	setFlags_SR( ("S",S), ("O",O), ("Z",Z) )
	sv.registers["IP"] += 3

def fun_INC_r(arg1):
	op1 = sv.registers[arg1]
	(sv.registers[arg1],S,O,Z) = ARITH( (lambda x,y:x+1) , op1,op1)
	setFlags_SR( ("S",S), ("O",O), ("Z",Z) )
	sv.registers["IP"] += 2

def fun_DEC_r(arg1):
	op1 = sv.registers[arg1]
	(sv.registers[arg1],S,O,Z) = ARITH( (lambda x,y:x-1) , op1,op1)
	setFlags_SR( ("S",S), ("O",O), ("Z",Z) )
	sv.registers["IP"] += 2


def LOGIC(operator,op1,op2):
	""" compute bit-wise the logical operator over op1 and op2 """
	BinOp1 = [int(bit) for bit in format(op1, '08b')]
	BinOp2 = [int(bit) for bit in format(op2, '08b')]
	BinRes = [ operator(BinOp1[i],BinOp2[i]) for i in range(len(BinOp1))]
	return int( "".join(map(str, BinRes)) ,2)


def fun_AND_rr(arg1,arg2):
	op1 = sv.registers[arg1]
	op2 = sv.registers[arg2]
	sv.registers[arg1] = LOGIC( (lambda x,y:x and y),op1,op2 )
	sv.registers["IP"] += 3

def fun_AND_rd(arg1,arg2):
	op1 = sv.registers[arg1]
	op2 = arg2
	sv.registers[arg1] = LOGIC( (lambda x,y:x and y),op1,op2 )
	sv.registers["IP"] += 3

def fun_OR_rr(arg1,arg2):
	op1 = sv.registers[arg1]
	op2 = sv.registers[arg2]
	sv.registers[arg1] = LOGIC( (lambda x,y:x or y),op1,op2 )
	sv.registers["IP"] += 3

def fun_OR_rd(arg1,arg2):
	op1 = sv.registers[arg1]
	op2 = arg2
	sv.registers[arg1] = LOGIC( (lambda x,y:x or y),op1,op2 )
	sv.registers["IP"] += 3

def fun_XOR_rr(arg1,arg2):
	op1 = sv.registers[arg1]
	op2 = sv.registers[arg2]
	sv.registers[arg1] = LOGIC( (lambda x,y:x ^ y),op1,op2 )
	sv.registers["IP"] += 3

def fun_XOR_rd(arg1,arg2):
	op1 = sv.registers[arg1]
	op2 = arg2
	sv.registers[arg1] = LOGIC( (lambda x,y:x ^ y),op1,op2 )
	sv.registers["IP"] += 3

def fun_NOT_r(arg1):
	op1 = sv.registers[arg1]
	sv.registers[arg1] = LOGIC( (lambda x,y:int(not(x))),op1,op1 )
	sv.registers["IP"] += 2


def fun_CMP_rr(arg1, arg2):
	op1 = sv.registers[arg1]
	op2 = sv.registers[arg2]
	res = comp2toint(op1)-comp2toint(op2)
	setFlags_SR( ("S",res<0), ("O",res<-128 or res>127), ("Z",res==0) )
	sv.registers["IP"] += 3

def fun_CMP_rd(arg1, arg2):
	op1 = sv.registers[arg1]
	op2 = arg2
	res = comp2toint(op1)-comp2toint(op2)
	setFlags_SR( ("S",res<0), ("O",res<-128 or res>127), ("Z",res==0) )
	sv.registers["IP"] += 3

def fun_CMP_rm(arg1, arg2):
	op1 = sv.registers[arg1]
	op2 = sv.RAM[arg2]
	res = comp2toint(op1)-comp2toint(op2)
	setFlags_SR( ("S",res<0), ("O",res<-128 or res>127), ("Z",res==0) )
	sv.registers["IP"] += 3


def fun_JMP_d(arg1):
	sv.registers["IP"] += comp2toint(arg1)

def fun_JZ_d(arg1):
	if getFlag_SR("Z"):
		sv.registers["IP"] += comp2toint(arg1)
	else:
		sv.registers["IP"] += 2
	
def fun_JNZ_d(arg1):
	if not(getFlag_SR("Z")):
		sv.registers["IP"] += comp2toint(arg1)
	else:
		sv.registers["IP"] += 2
	
def fun_JS_d(arg1):
	if getFlag_SR("S"):
		sv.registers["IP"] += comp2toint(arg1)
	else:
		sv.registers["IP"] += 2
	
def fun_JNS_d(arg1):
	if not(getFlag_SR("S")):
		sv.registers["IP"] += comp2toint(arg1)
	else:
		sv.registers["IP"] += 2

def fun_JO_d(arg1):
	if getFlag_SR("O"):
		sv.registers["IP"] += comp2toint(arg1)
	else:
		sv.registers["IP"] += 2

def fun_JNO_d(arg1):
	if not(getFlag_SR("O")):
		sv.registers["IP"] += comp2toint(arg1)
	else:
		sv.registers["IP"] += 2


def fun_MOV_rd(arg1,arg2):
	sv.registers[arg1] = arg2
	sv.registers["IP"] += 3

def fun_MOV_rm(arg1,arg2):
	sv.registers[arg1] = sv.RAM[arg2]
	sv.registers["IP"] += 3

def fun_MOV_mr(arg1,arg2):
	sv.RAM[arg1] = sv.registers[arg2]
	sv.registers["IP"] += 3

def fun_MOV_rp(arg1,arg2):
	sv.registers[arg1] = sv.RAM[sv.registers[arg2]]
	sv.registers["IP"] += 3

def fun_MOV_pr(arg1,arg2):
	sv.RAM[sv.registers[arg1]] = sv.registers[arg2]
	sv.registers["IP"] += 3



def fun_PUSH_r(arg1):
	sv.RAM[sv.registers["SP"]] = sv.registers[arg1]
	sv.registers["SP"] -= 1
	sv.registers["IP"] += 2


def fun_PUSH_d(arg1):
	sv.RAM[sv.registers["SP"]] = arg1
	sv.registers["SP"] -= 1
	sv.registers["IP"] += 2


def fun_POP_r(arg1):
	sv.registers["SP"] += 1
	sv.registers[arg1] = sv.RAM[sv.registers["SP"]]
	sv.registers["IP"] += 2

def fun_PUSHF():
	sv.RAM[sv.registers["SP"]] = sv.registers["SR"]
	sv.registers["SP"] -= 1
	sv.registers["IP"] += 1

def fun_POPF():
	sv.registers["SP"] += 1
	sv.registers["SR"] = sv.RAM[sv.registers["SP"]]
	sv.registers["IP"] += 1

def fun_CALL_d(arg1):
	sv.RAM[sv.registers["SP"]]  = sv.registers["IP"] + 2
	sv.registers["SP"] -= 1
	sv.registers["IP"] = arg1									# est-ce que ça marche si arg1 est donné en hexa ?

def fun_RET():
	sv.registers["SP"] += 1
	sv.registers["IP"] = sv.RAM[sv.registers["SP"]]

def fun_INT_d(arg1):										# est-ce correct ?
	sv.RAM[sv.registers["SP"]]  = sv.registers["IP"] + 2
	sv.registers["SP"] -= 1
	sv.registers["IP"] = sv.RAM[arg1]


def fun_IRET():												# est-ce correct ?
	sv.registers["SP"] += 1
	sv.registers["IP"] = sv.RAM[sv.registers["SP"]]

def fun_IN_d(arg1):
	if arg1 == 0x00:
		sv.registers[0x00] = getFromKeyboard(keybw)
	else:
		raise Exception("Unknown input peripheral")
	sv.registers["IP"] += 2
	
def fun_NOP():
	sv.registers["IP"] += 1

def fun_UNDEF(*arg):
	""" undefined instruction with an undefined number of arguments """
	pass

#-----------------------------------------------------------------------------------------


#-----------------------------------------------------------------------------------------
AssemblerInstr2OpCode = {
	# for each entry corresponding to the signature of the operation, contains the OpCode)
	# 'reg'=register, 'ram'=ram, 'data'=number or data, 'preg'=register containing a pointer to the ram (indirection)
	
	# Arithmetic Instructions
	("ADD", "reg", "reg")   : (0xA0, fun_ADD_rr),
	("ADD", "reg", "data")  : (0xB0, fun_ADD_rd),

	("SUB", "reg", "reg")   : (0xA1, fun_SUB_rr),
	("SUB", "reg", "data")  : (0xB1, fun_SUB_rd),

	("MUL", "reg", "reg")   : (0xA2, fun_MUL_rr),
	("MUL", "reg", "data")  : (0xB2, fun_MUL_rd),

	("DIV", "reg", "reg")   : (0xA3, fun_DIV_rr),
	("DIV", "reg", "data")  : (0xB3, fun_DIV_rd),

	("MOD", "reg", "reg")   : (0xA6, fun_MOD_rr),
	("MOD", "reg", "data")  : (0xB6, fun_MOD_rd),

	("INC", "reg")          : (0xA4, fun_INC_r),
	("DEC", "reg")          : (0xA5, fun_DEC_r),

	# Logic Instructions
	("AND", "reg", "reg")   : (0xAA, fun_AND_rr),
	("AND", "reg", "data")  : (0xBA, fun_AND_rd),

	("OR",  "reg", "reg")   : (0xAB, fun_OR_rr),
	("OR",  "reg", "data")  : (0xBB, fun_OR_rd),
	
	("XOR", "reg", "reg")   : (0xAC, fun_XOR_rr),
	("XOR", "reg", "data")  : (0xBC, fun_XOR_rd),
	
	("NOT", "reg")          : (0xAD, fun_NOT_r),

	# Compare Instructions
	("CMP", "reg", "reg")   : (0xDA, fun_CMP_rr),
	("CMP", "reg", "data")  : (0xDB, fun_CMP_rd),
	("CMP", "reg", "ram")   : (0xDC, fun_CMP_rm),
	
	# Branch Instructions
	("JMP", "data")         : (0xC0, fun_JMP_d),
	("JZ",  "data")         : (0xC1, fun_JZ_d),
	("JNZ", "data")         : (0xC2, fun_JNZ_d),
	("JS",  "data")         : (0xC3, fun_JS_d),
	("JNS", "data")         : (0xC4, fun_JNS_d),
	("JO",  "data")         : (0xC5, fun_JO_d),
	("JNO", "data")         : (0xC6, fun_JNO_d),
	
	# Move Instructions
	("MOV", "reg", "data")  : (0xD0, fun_MOV_rd),
	("MOV", "reg", "ram")   : (0xD1, fun_MOV_rm),
	("MOV", "ram", "reg")   : (0xD2, fun_MOV_mr),
	("MOV", "reg", "preg")  : (0xD3, fun_MOV_rp),
	("MOV", "preg", "reg")  : (0xD4, fun_MOV_pr),

	# Procedures and Interrupts Instructions
	("CALL", "data")        : (0xCA, fun_CALL_d),
	("RET",)                : (0xCB, fun_RET),
	("INT",  "data")        : (0xCC, fun_INT_d),
	("IRET",)               : (0xCD, fun_IRET),
  	
	# Stack Instructions
	("PUSH", "reg")         : (0xE0, fun_PUSH_r),
	("PUSH", "data")        : (0xE2, fun_PUSH_d),
	("POP",  "reg")         : (0xE1, fun_POP_r),
	("PUSHF",)              : (0xEA, fun_PUSHF),
	("POPF",)               : (0xEB, fun_POPF),

	# Keyboard Instructions
	("IN", "data")          : (0xF0, fun_IN_d),
		
	# Miscellaneous Instructions
	("HALT",)               : (0x00, fun_UNDEF),
	("NOP",)                : (0xFF, fun_NOP),
	
	# Assembler Directives
	("ORG", "data")         : (None, fun_UNDEF),
	("DB",  "data")         : (None, fun_UNDEF),
}


# reversed AssemblerInstr2OpCode
OpCode2AssemblerInstr = [None for _ in range(256)]
for key in AssemblerInstr2OpCode:
	if AssemblerInstr2OpCode[key][0] is not None:
		#populate OpCode2AssemblerInstr with tuples (AssemblerInstr, (args1, arg2, ...), fun) for each OpCode
		OpCode2AssemblerInstr[ AssemblerInstr2OpCode[key][0] ] = (key[0], key[1:], AssemblerInstr2OpCode[key][1] )

# reversed AssemblerInstr2OpCode
AssemblerInstrSignature = dict()
for key in AssemblerInstr2OpCode:
	AssemblerInstrSignature[ AssemblerInstr2OpCode[key][0] ] = key

# compute the arity of each instruction
arityInstr = dict()
for key in AssemblerInstr2OpCode:
	arityInstr[key[0]]=len(key)-1
#-----------------------------------------------------------------------------------------




#-----------------------------------------------------------------------------------------
# assemble(...) : assemble the program from file to Ram
#-----------------------------------------------------------------------------------------
def typeof(arg):
	""" return the type of an argument among ("reg", "ram", "data", "preg")
		examples : BL -> reg; [B4] -> ram; D2 -> num; [CL] -> preg """
	if arg == "AL":
		return ("reg",0x00)
	elif arg == "BL":
		return ("reg",0x01)
	elif arg == "CL":
		return ("reg",0x02)
	elif arg == "DL":
		return ("reg",0x03)

	elif arg == "[AL]":
		return ("preg",0x00)
	elif arg == "[BL]":
		return ("preg",0x01)
	elif arg == "[CL]":
		return ("preg",0x02)
	elif arg == "[DL]":
		return ("preg",0x03)

	elif arg[0]=="[" and arg[-1]=="]":
		return ("ram", int(arg.strip('[]'),16))

	else:
		return ("data", int(arg,16))



def assemble(filename):
	""" read the given file filename and assemble into the RAM """

	addr = 0		# pointer in RAM address
	labels=dict()	# to handle labels used in the program
	
	with open(filename, 'r') as file:
		for line in file:
			try:
				## -----------------------------------------------------------------------
				# for each line, extract the listOp of operator, operands, and comments
				listOp = re.split(r'\s*,\s*|\s+' ,line.strip(' \t\n\r\n'))
				listOp = list(map(lambda x:x.strip(', ').upper(), listOp))	# remove "," and replace everything to uppercase
			
				if len(listOp)==0 or len(listOp[0])==0 or listOp[0][0]==";" :
					# empty line or only a comment on the line; ignore that ligne
					pass
			
				elif listOp[-1][-1]==":" :
					# a label on the line; the label is added to the labels dictionary
					label = listOp[0].strip(' :')
					if label not in labels:
						labels[label] = [addr,[]]
					else:
						labels[label][0] = addr
			
				elif listOp[0]=="DB" :
					if listOp[1][0]=="\"":
						deb = line.find("\"")
						fin = line.find("\"",deb+1)
						for c in line[deb+1:fin]:
							sv.RAM[addr] = ord(c)
							addr += 1
					else:
						# a DB directive; add the integer to the RAM
						sv.RAM[addr] = int(listOp[1],16)	#convert 'hex string' (representing an integer in 2 complement) to an 'int'
						addr += 1

				elif listOp[0]=="ORG" :
					# a ORG directive; change the addr to write in RAM
					addr = int("0x"+listOp[1],16)

				elif listOp[0] in ["JMP","JZ","JNZ","JS","JNS","JO","JNO"] :
					# The precise address (i.e. Offset) can only be updated at the end because labels might appear later in the file
					OpCode = AssemblerInstr2OpCode[ (listOp[0],"data") ][0]
					sv.RAM[addr] = [OpCode, listOp[0]]	# store the OpCode in the RAM, as well as the name of the instruction/operande
					label = listOp[1].strip(' :')
					if label not in labels:
						labels[label] = [None,[addr+1]]
					else:
						labels[label][1].append(addr+1)
					addr += 2
				
				else:
					# all other instruction are parsed here
					t = (listOp[0],)
					arity = arityInstr[listOp[0]]
					if arity >= 1:
						(arg1type, arg1) = typeof(listOp[1])
						t = t + (arg1type,)
						if arg1type == "data":
							sv.RAM[addr+1] = arg1				# store the OpCode in the RAM, as well as the name of the instruction/operande
						else:
							sv.RAM[addr+1] = [arg1, listOp[1]]	# store the OpCode in the RAM, as well as the name of the instruction/operande

					if arity == 2:
						(arg2type, arg2) = typeof(listOp[2])
						t = t + (arg2type,)
						if arg2type == "data":
							sv.RAM[addr+2] = arg2				# store the OpCode in the RAM, as well as the name of the instruction/operande
						else:
							sv.RAM[addr+2] = [arg2, listOp[2]]	# store the OpCode in the RAM, as well as the name of the instruction/operande

					OpCode = AssemblerInstr2OpCode[t][0]
					sv.RAM[addr] = [OpCode, listOp[0]]			# store the OpCode in the RAM, as well as the name of the instruction/operande
					addr += arity+1
				## -----------------------------------------------------------------------
			#finally:
			except:
				raise Exception('assemble','Problem on the following line :', line)
    
		#Finally, write the correct address corresponding to each label
		for label in labels:
			for addr in labels[label][1]:
				sv.RAM[addr] = inttocomp2(labels[label][0] - addr+1)	#OFFSET
#-----------------------------------------------------------------------------------------




#-----------------------------------------------------------------------------------------
# run(...) : execute the program in Ram
#-----------------------------------------------------------------------------------------
def run(screen,ramw,regw,dispw):
	delay = 0
	while True:
		addr = sv.registers["IP"]
		sv.RAM.print(ramw, [sv.registers["IP"],sv.registers["SP"]])
		sv.registers.print(regw)
		sv.RAM.printdisplay(dispw)
		printMessage(screen, str(OpCode2AssemblerInstr[sv.RAM[addr]][0]) + " (" + ", ".join(str(x) for x in OpCode2AssemblerInstr[sv.RAM[addr]][1]) +")")
	
		time.sleep(delay)
		key = screen.getch()
		
		if key in [ord('q'),ord('Q')]:
			exit(1)
		elif key in [ord('s'),ord('S')]:
			sv.RAM.switchRamShowHexaSource()
			sv.RAM.print(ramw)
		elif key in [ord('0')]:
			screen.nodelay(False)
			delay = 0
		elif key in [ord('1'),ord('2'),ord('3'),ord('4'),ord('5'),ord('6'),ord('7'),ord('8'),ord('9')]:
			screen.nodelay(True)
			delay = 1.5/pow(2,(key-49))
		else:
			if OpCode2AssemblerInstr[sv.RAM[addr]] is not None:	#i.e. this instruction is defined for that CPU
				t = ()
				addrArg = addr
				for typeArg in OpCode2AssemblerInstr[sv.RAM[addr]][1]:
					addrArg += 1
					arg = sv.RAM[addrArg]
					t = t+(arg,)
				
				OpCode2AssemblerInstr[sv.RAM[addr]][2](*t)		# execute the instruction together with its arguments
			else:
				raise Exception("Does not correspond to any OpCode for this CPU")
#-----------------------------------------------------------------------------------------
			

		
#-----------------------------------------------------------------------------------------
# Main
#-----------------------------------------------------------------------------------------

def main(screen):
	global keybw	#ugly but this avoid to give keybw as a parameter of fun_IN_d
	
	# Clear screen
	screen.clear()
	screen.refresh()
	unicurses.curs_set(False)
	unicurses.noecho()

	# Create color pairs
	unicurses.init_pair(1, unicurses.COLOR_RED, unicurses.COLOR_BLACK)
	unicurses.init_pair(2, unicurses.COLOR_MAGENTA, unicurses.COLOR_BLACK)
	unicurses.init_pair(3, unicurses.COLOR_CYAN, unicurses.COLOR_BLACK)
	
    # Create a new window ramw to show the RAM
	ramw=createWindow(42, 0, 19, 4+16*STRING_SIZE, "RAM")
	sv.RAM.print(ramw)

    # Create a new window regw to show the Registers
	regw=createWindow(0, 0, 6, 42, "Registers")
	sv.registers.print(regw)
	
	# Create a new window to show the display peripheral (4 rows and 16 column)
	dispw = createWindow(4, 8, 6, 1+2*16, title="display")
	sv.RAM.printdisplay(dispw)
	
	# Create a new window to show the keyboard peripheral
	keybw = createWindow(4, 15, 3, 1+2*16, title="keyboard")
	
	assemble(argv[1])
	sv.RAM.print(ramw)
	
	printMessage(screen, "Program has been assembled. Press a key to start the execution.")
	screen.getch()
	
	run(screen,ramw,regw,dispw)
	
	printMessage(screen, "Fin ?")
	screen.getch()

	key = screen.getkey()
	if key == "q":
		return 1


if __name__ == "__main__":
	if len(argv)!=2:
		print('usage: %s filename' % (argv[0],))
		exit(1)

	simwrapper(main)
#-----------------------------------------------------------------------------------------

