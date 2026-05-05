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
    
    def get_sections(self):
        if not self.pe:
            return[]
        
        sections= []

        for section in self.pe.sections:
            name = section.Name.decode('utf-8', errors = 'ignore').strip('\x00')
            sections.append({
                'name': name,
                'virtual_size': section.Misc_VirtualSize,
                'raw_size': section.SizeOfRawData,
                'entropy': round(section.get_entropy(), 2)
            })
        return sections
    
    def is_packed(self):
        if not self.pe:
            return False
        
        sections = self.get_sections()

        for s in sections:
            if s['entropy'] > 7.0:
                return True
            
        suspicious_name = ['UPX', 'UPX0', 'UPX1', '.aspack', '.MPRESS', 'themida'] # suspicious names

        for s in sections:
            if s['name'] in suspicious_name:
                return True
            
        return False
    
    def get_imports(self):
        if not self.pe:
            return []
        
        imports = []

        if not hasattr(self.pe, "DIRECTORY_ENTRY_IMPORT"): # We check if the file have imports
            return imports
        
        for entry in self.pe.DIRECTORY_ENTRY_IMPORT:
            dll_name = entry.dll.decode('utf-8', errors = 'ignore')

            for imp in entry.imports:
                if imp.name:
                    api_name = imp.name.decode('utf-8', errors = 'ignore')

                else:
                    api_name = f"Ordinal_{imp.ordinal}"

                    imports.append({
                        'dll': dll_name,
                        'api': api_name,
                        'ordinal': imp.ordinal
                    })

        return imports
    
    def get_dangerous_apis(self):

        dangerous_list = {
            # Process Injection
            'CreateRemoteThread', 'WriteProcessMemory', 'VirtualAllocEx',
            'ReadProcessMemory', 'OpenProcess', 'NtOpenProcess',

            #Command Exec
            'WinExec', 'ShellExecute', 'system', 'popen',

            #NetWork
            'URLDownloadToFile', 'InternetOpen', 'InternetConnect',
            'HttpOpenRequest', 'HttpSendRequest', 'socket', 'connect',

            #Persistence
            'RegSetValue', 'RegCreateKey', 'RegOpenKey',

            #Anti-Debug
            'IsDebuggerPresent', 'CheckRemoteDebuggerPresent',

            #Encryption
            'CryptEncrypt', 'CryptDecrypt', 'CryptAcquireContext',

            #File Ope
            'CreateFile', 'WriteFile', 'DeleteFile', 'MoveFile'
        }

        all_imports = self.get_imports()

        dangerous = []
        for imp in all_imports:
            if imp['api'] in dangerous_list:
                dangerous.append(imp)

            return dangerous
    

if __name__ == '__main__':
    import sys

    if len(sys.argv) < 2:
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

        sections = parser.get_sections()
        print(f"\n[SECTIONS]")
        for s in sections:
            packed_warning = "Packed" if s['entropy'] > 7.0 else ""
            print(f"{s['name']:10} | Size: {s['virtual_size']:8} | Entropy: {s['entropy']}{packed_warning}")

        if parser.is_packed():
            print("\n DETECTED: File appears to be PACKED!")
            print("   The real code is compressed/encrypted.")
            print("   Static analysis may be limited.")
        else:
            print("\n File is NOT packed.")
            print("   Static analysis will work normally.")

        imports = parser.get_imports()
        print(f"\n[IMPORTS]")
        print(f"  Total APIs imported: {len(imports)}")
        
        dangerous = parser.get_dangerous_apis()
        if dangerous:
            print(f"\n  DANGEROUS APIs Found ({len(dangerous)}):")
            for imp in dangerous[:15]:  # Show first 15
                print(f"    - {imp['api']} (from {imp['dll']})")
        else:
            print(f"\n  No dangerous APIs detected")

    else:
        print("Not a valid PE file")