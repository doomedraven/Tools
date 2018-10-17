# encoding: utf-8
# http://www.hexblog.com/?p=120
# Default IDA Pro Paths:
# MAC	/Applications/IDA\ Pro\ X/idaq.app/Contents/MacOS/plugins/
# Windows	C:\Program Files (x86)\IDA X\plugins

# to make it autoexec on openfile
# add this to plugins.cfg
# ; Other plugins
#FullColor                        FullColor.py       0       0  SILENT

# thanks @JR0driguezB for help :)

from idautils import *
from idc import *
import idaapi

idaapi.autoWait()

class full_color(idaapi.plugin_t):
    flags = idaapi.PLUGIN_UNL
    comment = "Set colors :)"
    help = "No help needed"
    wanted_name = "FullColor"
    wanted_hotkey = ""
    
    def init(self):
        idaapi.msg("init() called!\n")
        self.run(0)
        return idaapi.PLUGIN_OK

    def run(self, arg):
        idaapi.msg("run() called with %d!\n" % arg)
        #Color the Calls off-white
        heads = Heads(SegStart(ScreenEA()), SegEnd(ScreenEA()))
        funcCalls = []
        for i in heads:
            if GetMnem(i) == "call":
                funcCalls.append(i)
        print "Number of calls: %d" % (len(funcCalls))

        for i in funcCalls:
            SetColor(i, CIC_ITEM, 0xc7fdff)

        #Color Anti-VM instructions Red and print their location
        heads = Heads(SegStart(ScreenEA()), SegEnd(ScreenEA()))

        antiVM = []
        for i in heads:
            if (GetMnem(i) == "sidt" or GetMnem(i) == "sgdt" or GetMnem(i) == "sldt" or GetMnem(i) == "smsw" or GetMnem(i) == "str" or GetMnem(i) == "in" or GetMnem(i) == "cpuid"):
                antiVM.append(i)
        print "Number of potential Anti-VM instructions: %d" % (len(antiVM))
        for i in antiVM:
            print "Anti-VM potential at %x" % i
            SetColor(i, CIC_ITEM, 0x0000ff)

        #Color non-zeroing out xor instructions Orange
        heads = Heads(SegStart(ScreenEA()), SegEnd(ScreenEA()))
        xor = []
        for i in heads:
            if GetMnem(i) == "xor":
                if (GetOpnd(i,0) != GetOpnd(i,1)):
                    xor.append(i)

        print "Number of xor: %d" % (len(xor))
        for i in xor:
            SetColor(i, CIC_ITEM, 0x00a5ff)

    def term(self):
        idaapi.msg("term() called!\n")

def PLUGIN_ENTRY():
    return full_color()