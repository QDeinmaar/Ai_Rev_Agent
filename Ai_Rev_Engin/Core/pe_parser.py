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
        return {
            'e_magic': hex(self.pe.DOS_HEADER.e_magic),  # this is the signature at the start of the file
            'e_lfanew': self.pe.DOS_HEADER.e_lfanew  # this is an offset that can tell us where th real Pe Header start
        }
    
    def get_file_header(self):
        if not self.pe:
            return{}
        
        fh = self.pe.FILE_HEADER

        machine_type = {
            0x14c: "x86 (32 bits)",
            0x8664: "x64 (64 bits)",
            0x1c0: "ARM",
            0xaa64: "ARM64"
        }

        return{
            'machine':machine_type.get(fh.Machine, f"Unkhnown (0x{fh.Machine:x})"),
            'number_of_sections': fh.NumberOfSections,
            'time_date_stamp': fh.TimeDateStamp,
            'size_of_optional_header': fh.SizeOfOptionalHeader,
            'characteristics': hex(fh.Characteristics)
        }

if __name__ == '__main__':
    import sys

    if len(sys.argv) > 2:
        print("Usage : python pe_parser.py <file_path> !")
        sys.exit(1)

    parser = PeParser(sys.argv[1])

    if parser.load():
        print("Valid PE file !")
        dos = parser.get_dos_header()
        print(f"DOS magic : {dos['e_magic']}")
        print(f"PE header offset : {dos['e_lfanew']}")

        file_header = parser.get_file_header()
        print(f"\n[FILE HEADER]")
        print(f"  Machine: {file_header['machine']}")
        print(f"  Sections: {file_header['number_of_sections']}")
        print(f"  Optional header size: {file_header['size_of_optional_header']} bytes")
        
    else:
        print("Not a valid PE file")