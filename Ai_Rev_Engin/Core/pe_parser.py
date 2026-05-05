class PeParser:
    def __init__(self,filepath):
        self.filepath = filepath
        self.pe = None
    
    def load(self):
        import pefile
        try:
            self.pe = pefile.PE(self.filepath)
            return True
        except:
            return False
        
    def is_valid_pe(self):
        if not self.pe:
            return False
        return True
    
    def get_dos_header(self):
        if not self.pe:
            return{}
        return
        {
            'e_magic': hex(self.pe.DOS_HEADER.e_magic),  # this is the signature at the start of the file
            'e_lfanew': self.pe.DOS_HEADER.e_lfanew  # this is an offset that can tell us where th real Pe Header start
        }