import ida_kernwin
import idaapi
import idc

act_name = "memdumper:opendump"
label = "Memory dumper"


class MemDumper_t(idaapi.plugin_t):
    flags = idaapi.PLUGIN_PROC
    comment = "MemDumper"
    help = "A plugin to dump the memory region where you wannted from the debugger"
    wanted_name = label
    wanted_hotkey = "Ctrl-Alt-M"

    def init(self):
        self.hextays_inited = False

        print("Memory Dumper (v1.0) by yueluo")
        print("Plugin has been loaded.")

        self.hexrays_inited = True
        return idaapi.PLUGIN_KEEP

    def run(self, arg):
        s = """Memory Dumper

        Enter the memory region:
        
        begin:  <:n::12::>
        
        size:   <:n::12::> (optional, fill it to ignore the end address)        
        or        
        end:    <:n::12::>
        """

        currea = idaapi.get_screen_ea()
        begin = idaapi.Form.NumericArgument('N', currea)
        size = idaapi.Form.NumericArgument('N', 0x0)
        end = idaapi.Form.NumericArgument('N', 0x0)

        ok = idaapi.ask_form(s,
                             begin.arg,
                             size.arg,
                             end.arg)
        if ok == 1:
            print("Begin dump")

            if size.value == 0:
                if end.value <= begin.value:
                    idaapi.warning("Incorrect Address!")
                    return
                else:
                    dumpsize = end.value - begin.value

            else:
                dumpsize = size.value

            print("begin: 0x%x, end: 0x%x" % (begin.value, begin.value + dumpsize))

            path = ida_kernwin.ask_file(True, "*", "Save dump to?")

            if not path:
                return

            print("path: %s" %path)

            if idc.savefile(path, 0, begin.value, dumpsize) is not 0:
                idaapi.info("Save successed!")
            else:
                idaapi.warning("Failed to save dump file!")

    def term(self):
        if self.hexrays_inited:
            idaapi.term_hexrays_plugin()


def PLUGIN_ENTRY():
    return MemDumper_t()
