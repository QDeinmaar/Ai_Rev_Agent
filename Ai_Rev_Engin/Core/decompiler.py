import os
import tempfile
from pathlib import Path

from ghidra.program.model.listing import FunctionManager
from ghidra.app.decompiler import DecompInterface
from ghidra.util.task import ConsoleTaskMonitor

try:
    from pyhidra import start_headless
    PYHIDRA__AVAILABLE = True
except ImportError:
    PYHIDRA__AVAILABLE = False
    print("Pyhidra not installed please run pip install pyhidra !")


class GhidraDecompiler:
    def __init__(self, ghidra_path=r"C:\Users\tudor\Downloads\ghidra"):
        self.ghidra_path = ghidra_path
        self.available = PYHIDRA__AVAILABLE and self._check_ghidra()

    def _check_ghidra(self):
        if not os.path.exists(self.ghidra_path):
            print(f"Ghidra not found at : {self.ghidra_path}")
            print("Please download ghidra !")

            return False

        if not os.path.exists(os.path.join(self.ghidra_path, "ghidraRun.bat")): #We check if Ghidrarun.bat
            print(f"Invalid Ghidra instalation at : {self.ghidra_path}")
            return False
        
        print(f"Ghidra found at : {self.ghidra_path}")
        return True

    def decompile(self, file_path, timeout = 60):
        if not self.available:
            return {"error : Ghidra is not available !"}
        
        if not os.path.exists(file_path):
            return {f"error : Ghidra not found : {file_path}"}
        
        print(f"Starting the Decompilation : {Path(file_path).name}")
        print("This might time 20 To 60 second Please Relax !")

        try:
            with start_headless(
                self.ghidra_path,
                str(Path(file_path).parent),
                project_name = "Temp_Project" 
            ):
                