# encoding: utf-8
# http://www.hexblog.com/?p=120
# Default IDA Pro Paths:
# MAC	/Applications/IDA\ Pro\ X/idaq.app/Contents/MacOS/plugins/
# Windows	C:\Program Files (x86)\IDA X\plugins

# to make it autoexec on openfile
# add this to plugins.cfg
# ; Other plugins
#FullColor                        FullColor.py       0       0  SILENT

# thanks @JR0driguezB for help :)

from __future__ import print_function
from idautils import Heads
from idc import get_segm_start, get_segm_end, print_insn_mnem, get_screen_ea, print_operand, set_color, CIC_ITEM
import idaapi

#idaapi.auto_wait()
PLUGIN_TEST = 1

class FullColor_t(idaapi.plugin_t):
    flags = idaapi.PLUGIN_UNL
    comment = "Set colors :)"
    help = "No help needed"
    wanted_name = "FullColor"
    wanted_hotkey = ""

    def init(self):
        #idaapi.msg("init() called!\n")
        #self.run(0)
        return idaapi.PLUGIN_OK

    def run(self, arg=0):
        print("hell2")
        idaapi.msg("run() called with %d!\n" % arg)
        heads = Heads(get_segm_start(get_screen_ea()), get_segm_end(get_screen_ea()))
        funcCalls = []
        xor = []
        antiVM = []
        for i in heads:
            # Color the Calls off-white
            if print_insn_mnem(i) == "call":
                funcCalls.append(i)
            # Color Anti-VM instructions Red and print their location
            elif print_insn_mnem(i) in ("sidt", "sgdt",  "sldt", "smsw", "str", "in", "cpuid"):
                antiVM.append(i)
            # Color non-zeroing out xor instructions Orange
            elif print_insn_mnem(i) == "xor" and (print_operand(i,0) != print_operand(i,1)):
                xor.append(i)

        print("Number of calls: %d" % (len(funcCalls)))
        for i in funcCalls:
            set_color(i, CIC_ITEM, 0xc7fdff)

        print("Number of potential Anti-VM instructions: %d" % (len(antiVM)))
        for i in antiVM:
            print("Anti-VM potential at %x" % i)
            set_color(i, CIC_ITEM, 0x0000ff)

        print("Number of xor: %d" % (len(xor)))
        for i in xor:
            set_color(i, CIC_ITEM, 0x00a5ff)

    def term(self):
        idaapi.msg("term() called!\n")

def PLUGIN_ENTRY():
    return FullColor_t()

if PLUGIN_TEST:
    # Create form
    f = PLUGIN_ENTRY()
    f.init()
    f.run()
    f.term()
