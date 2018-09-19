#include <idc.idc>
static main(void) {
  auto currentEA;
  auto currentMnem;
  auto prevMnem;
  auto currentOp;
  prevMnem = "";
  currentOp;
  currentEA = FirstSeg();
  currentEA = NextHead(currentEA, 0xFFFFFFFF);
  while (currentEA != BADADDR) {
    currentMnem = GetMnem(currentEA);

    //Highlight call functions
    if (currentMnem == "call")
      SetColor(currentEA, CIC_ITEM, 0xc7c7ff);
    //Non-zeroing XORs are often signs of data encoding
    if (currentMnem == "xor") {
      if (GetOpnd(currentEA, 0) != GetOpnd(currentEA, 1)) {
        SetColor(currentEA, CIC_ITEM, 0xFFFF00);
      }
    }
    //Instructions used for Anti-VM, sidt, sgdt, sldt, smsw, str, in, cpuid
    if (currentMnem == "sidt" || currentMnem == "sgdt" || currentMnem == "sldt"
      || currentMnem == "smsw" || currentMnem == "str"
      || currentMnem == "in" || currentMnem == "cpuid")
      SetColor(currentEA, CIC_ITEM, 0xFFFF00);

  //Highlight interrupts in code as an anti-debugging measure
  if (currentMnem == "int" &&
    (GetOpnd(currentEA, 0) == "3" || GetOpnd(currentEA, 0) == "2D")) {
    SetColor(currentEA, CIC_ITEM, 0xFFFF00);
  }

  //Highlight other instructions sometimes used for anti-debugging
  if (currentMnem == "rdtsc" || currentMnem == "icebp") {
    SetColor(currentEA, CIC_ITEM, 0xFFFF00);
  }
  //Highlight push/ret combinations as a shellcode
  if (currentMnem == "ret" && prevMnem == "push")
    SetColor(currentEA, CIC_ITEM, 0xFFFF00);

  currentEA = NextHead(currentEA, 0xFFFFFFFF);
  prevMnem = currentMnem;
  }
}