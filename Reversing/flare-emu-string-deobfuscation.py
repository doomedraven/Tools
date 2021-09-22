# https://unit42.paloaltonetworks.com/using-idapython-to-make-your-life-easier-part-1/
# https://www.hex-rays.com/products/ida/support/ida74_idapython_no_bc695_porting_guide.shtml
# https://gitlab.com/krabsonsecurity/buer-loader-analysis/blob/master/stringdec.py
# https://hex-rays.com/products/ida/support/idapython_docs/

from __future__ import print_function
from datetime import datetime
import flare_emu

def find_function_arg_key(addr):
  while True:
    addr = idc.prev_head(addr)
    if idc.print_insn_mnem(addr) == "push":
      return idc.get_operand_value(addr, 0)
  return False

def deobfuscate(argv):
    myEH = flare_emu.EmuHelper()
    allocated = myEH.allocEmuMem(1024)
    # we do must disable skip calls due to internal calls
    # stack for x86, first arg is ret addr so 0
    # registers for x64
    myEH.emulateRange(myEH.analysisHelper.getNameAddr("stringDecrypt"), skipCalls=False, stack = [0, argv[0], "useless", allocated])
    return myEH.getEmuString(allocated).decode("latin-1")

if __name__ == '__main__':
    now = datetime.now()
    eh = flare_emu.EmuHelper()
    # you must rename func inside of the IDA
    deobf_func_addr = eh.analysisHelper.getNameAddr("stringDecrypt")
    for x in XrefsTo(deobf_func_addr):
        indexed = find_function_arg_key(x.frm)
        s = deobfuscate([indexed])
        print(f"{hex(x.frm)}: {s}")
        eh.analysisHelper.setComment(x.frm, s, False)
    print(f"It took {datetime.now()-now} seconds")
