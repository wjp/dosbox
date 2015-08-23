import idaapi
import idautils

class indcall_cmt_idp_hook_t(idaapi.IDP_Hooks):
    def __init__(self):
        idaapi.IDP_Hooks.__init__(self)
        self.renaming = {}

    def rename(self, ea, new_name):
        old_name = idaapi.get_ea_name(ea)
        self.renaming[ea] = old_name
        return 0

    def renamed(self, ea, new_name, local_name):
        import re
        if ea not in self.renaming:
            return 0
        old_name = self.renaming[ea]
        del self.renaming[ea]
        pattern = r'^ind\.call:\s+' + old_name + r'\s*$'
        for ref in idautils.CodeRefsTo(ea, 0):
            for repeatable in [0, 1]:
                cmt = idaapi.get_cmt(ref, repeatable)
                if cmt is not None and re.search(pattern, cmt, re.MULTILINE):
                    print "updating ind.call comments after rename"
                    cmt = re.sub(pattern, 'ind.call ' + new_name, cmt, 0, re.MULTILINE)
                    idaapi.set_cmt(ref, cmt, repeatable)
        return 0


try:
    print "IDP hook checking for hook..."
    indcall_cmt_idphook
    print "IDP hook unhooking...."
    indcall_cmt_idphook.unhook()
    del indcall_cmt_idphook
except:
    print "IDP hook was not installed"

try:
    indcall_cmt_idphook = indcall_cmt_idp_hook_t()
    indcall_cmt_idphook.hook()
    print "IDP hook installed"
except:
    print "Failed installing hook"

