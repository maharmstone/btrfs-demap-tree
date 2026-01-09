python

import re

class le_pretty_printer:
    def __init__(self, val):
        self.val = val

    def to_string(self):
        int_type = self.val.type.strip_typedefs().template_argument(0)
        signed = int_type.is_signed

        return int.from_bytes(self.val.bytes, byteorder = 'little',
                              signed = signed)

def le_pretty_printer_func(val):
    type = val.type.strip_typedefs()

    if type.name is None:
        return None

    match = re.match("^(.*?)<", type.name)
    if match:
        if match.group(1) == "little_endian@cxxbtrfs":
            return le_pretty_printer(val)

    return None

gdb.pretty_printers.append(le_pretty_printer_func)

end
