# coding: utf-8

import unicurses
from simutils import comp2toint, inttocomp2


#-----------------------------------------------------------------------------------------
STRING_SIZE = 5									# size of words-ram to be print on screen
#-----------------------------------------------------------------------------------------



#-----------------------------------------------------------------------------------------
# Fonctions used to print things on screen
#-----------------------------------------------------------------------------------------
def createWindow(begin_x, begin_y, height, width, title=""):
	""" Create a window on screen, starting at (begin_x,begin_y) of dimension (height,width) with given title """
	win = unicurses.newwin(height, width, begin_y, begin_x)
	win.box()
	win.addstr(0, int((width-len(title))/2), title)
	win.refresh()
	return win

def printRam(RAM, box, highlightAdrr=[]):
	""" print on screen box the content of the RAM ; if highlightAdrr is defined then the two addresses (IP and SP) are higlighted  """
	for k in range(16):
		box.addstr(1, 4+k*STRING_SIZE, " "+str(hex(k))[2:].upper()+" ", unicurses.color_pair(1))
		box.addstr(k+2, 1, str(hex(k))[2:].upper()+"0", unicurses.color_pair(1))
	
	for k in range(RAM.size()):
		if k in highlightAdrr:
			attrb = unicurses.A_REVERSE
		elif k>=0xC0:
			attrb = unicurses.color_pair(2)
		elif highlightAdrr and k>=highlightAdrr[1]: # <=> k>=sv.registers["SP"]:
			attrb = unicurses.color_pair(3)
		else:
			attrb = unicurses.A_NORMAL
		l,c = divmod(k,16)
		box.addstr(2+l, 4+c*STRING_SIZE, " "*(STRING_SIZE-1))	# to erase
		if RAM.RamShowHexa: # hexa
			box.addstr(2+l, 4+c*STRING_SIZE, format(RAM[k], '02X'), attrb)
		else : # source
			if k>=0xC0:	# video ram: show in Ascii
				box.addstr(2+l, 4+c*STRING_SIZE, mychr(RAM[k]), attrb)
			else:	# ram
				box.addstr(2+l, 4+c*STRING_SIZE, format(RAM.getCh(k), '.5s'), attrb)
	box.refresh()

def printRegisters(registers, box):
	""" print on screen box the contents of the Registers """
	name = ["AL","BL","CL","DL","IP","SP","SR"]
	for k, reg in enumerate(registers.reglist()):
		c,l = divmod(k,4)
		bin = format(registers[reg], '08b')
		hex = format(registers[reg], '02X')
		dec = format(comp2toint(registers[reg]), '+04')
		box.addstr(1+l, 1+c*21, name[k]+" "+bin+" "+hex+" "+dec)
	box.addstr(2+l, 1+c*21, "      ISOZ")
	box.refresh()

def mychr(x):
    if x>=32 and x<128:
        return chr(x)
    else:
        return ' '

def printDisplay(RAM, box):
	attrb = unicurses.color_pair(2)
	for k in range(0xC0, RAM.size()):
		l,c = divmod(k-0xC0,16)
		box.addstr(1+l,1+2*c, mychr(RAM[k]), attrb)
	box.refresh()
	
def printMessage(screen, message):
	""" print on screen a given message """
	screen.addstr(20,1, " "*100)
	screen.addstr(20,1, message, unicurses.A_REVERSE)

def getFromKeyboard(box):
	unicurses.curs_set(True)
	box.addstr(1,1, "> _", unicurses.A_BLINK )
	unicurses.echo()
	box.refresh()
	c=box.getch(1,3)
	box.addstr(1,1, "> "+chr(c).strip(' \t\n\r\n')+" ", unicurses.A_NORMAL )
	unicurses.curs_set(False)
	unicurses.noecho()
	box.refresh()
	return c

# The following wrapper is a copy of the original curses library, adpated to unicurses.
def simwrapper(func, *args, **kwds):
    """Wrapper function that initializes curses and calls another function,
    restoring normal keyboard/screen behavior on error.
    The callable object 'func' is then passed the main window 'stdscr'
    as its first argument, followed by any other arguments passed to
    wrapper().
    """

    try:
        # Initialize curses
        stdscr = unicurses.initscr()

        # Turn off echoing of keys, and enter cbreak mode,
        # where no buffering is performed on keyboard input
        unicurses.noecho()
        unicurses.cbreak()

        # In keypad mode, escape sequences for special keys
        # (like the cursor keys) will be interpreted and
        # a special value like curses.KEY_LEFT will be returned
        stdscr.keypad(1)

        # Start color, too.  Harmless if the terminal doesn't have
        # color; user can test with has_color() later on.  The try/catch
        # works around a minor bit of over-conscientiousness in the curses
        # module -- the error return from C start_color() is ignorable.
        try:
            unicurses.start_color()
        except:
            pass

        return func(stdscr, *args, **kwds)
    finally:
        # Set everything back to normal
        if 'stdscr' in locals():
            stdscr.keypad(0)
            unicurses.echo()
            unicurses.nocbreak()
            unicurses.endwin()
#-----------------------------------------------------------------------------------------
