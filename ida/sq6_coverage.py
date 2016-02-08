import idaapi
import idc
import idautils

F = open("/data/tmp/dosbox_sq6_coverage")
F2 = open("/data/tmp/dosbox_sq6_coverage.idc", "w")
F2.write("#include <idc.idc>\nstatic main(void)\n{\n")
for L in F.xreadlines():
  s = L.split(' ')
  ea = int(s[0], 16) - 0x1AF000
  if not (ea >= 0x10000 and ea <= 0x9DC6D):
    continue
  count = int(s[1])
  if count > 1000000:
    color = 0x00FF00
  elif count > 100000:
    color = 0x33FF33
  elif count > 10000:
    color = 0x55FF55
  elif count > 1000:
    color = 0x77FF77
  elif count > 100:
    color = 0x99FF99
  elif count > 10:
    color = 0xBBFFBB
  elif count > 0:
    color = 0xDDFFDD
  else:
    color = 0xFFFFFF
  idc.SetColor(ea, idc.CIC_ITEM, color)
  F2.write("  SetColor(%s, CIC_ITEM, %s);\n" % (hex(ea), hex(color)))

F2.write("}\n")
F2.close()


