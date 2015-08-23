import idaapi
import idautils

F = open("calls.log")
refs = {}
for L in F.xreadlines():
  if not L.startswith('call5: 0170 '):
    continue
  s = L.split(' ')
  ea_from = int(s[2], 16) - 0x1AF000  # TODO: Verify
  ea_from = idaapi.prev_head(ea_from, 0) # the recorded address is the
  ea_to = int(s[3], 16) - 0x1AF000
  if not (ea_from >= 0x10000 and ea_from <= 0x9DC6D and ea_to >= 0x10000 and ea_to <= 0x9DC6D):
    continue
  if ea_from not in refs.keys():
    refs[ea_from] = set()
  refs[ea_from].add(ea_to)

L = refs.keys()
L.sort()

F2 = open("/tmp/indcalls.idc", "w")
F2.write("#include <idc.idc>\nstatic main(void)\n{\n")

for ea_from in L:
  cmt = []
  L2 = list(refs[ea_from])
  L2.sort()
  for ea_to in L2:
    name = idaapi.get_ea_name(ea_to)
    cmt.append('ind.call: ' + name)
    idaapi.add_cref(ea_from, ea_to, idaapi.fl_CF | idaapi.XREF_USER)
    F2.write("  AddCodeXref(%s, %s, fl_CF | XREF_USER);\n" % (hex(ea_from), hex(ea_to)) )
  if len(cmt) > 3:
    cmt = cmt[0:2] + ["ind.call: ..."]
  newcmt = "\n".join(cmt)
  cmt = idaapi.get_cmt(ea_from, 0)
  if cmt is not None:
    cmt = re.sub("ind.call: .*\n?", "", cmt, 0).rstrip()
  if cmt:
    cmt = cmt + "\n" + newcmt
  else:
    cmt = newcmt
    
  idaapi.set_cmt(ea_from, cmt, 0)
  idccmt = re.sub("\n", "\\\\n", newcmt, 0)
  F2.write("  MakeComm(%s, \"%s\");\n" % (hex(ea_from), idccmt))

F2.write("}\n")
F2.close()
