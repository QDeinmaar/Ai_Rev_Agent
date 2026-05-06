import os
import tempfile
import json
import time
import subprocess
from pathlib import Path

try:
    from pyhidra import start_headless
    PYHIDRA_AVAILABLE = True
except ImportError:
    PYHIDRA_AVAILABLE = False
    print("Pyhidra not installed please run pip install pyhidra !")


class GhidraDecompiler:
    def __init__(self, ghidra_path=r"C:\Users\tudor\Downloads\ghidra\ghidra_12.0.4_PUBLIC"):
        self.ghidra_path = ghidra_path
        self.headless = os.path.join(ghidra_path, "support", "analyzeHeadless.bat")
        self.script_path = Path(__file__).parent.parent / "ghidra_scripts" / "decompiler_func.py"
        self.available = self._check_ghidra()

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

        temp_dir = os.path.join(os.environ.get('TEMP', 'C:\\temp'), 'ghidra_project')
        os.makedirs(temp_dir, exist_ok=True)
    
        output_file = r"C:\Users\tudor\Desktop\ghidra_output.json"
        if os.path.exists(output_file):
            os.remove(output_file)

        
        cmd = [
            self.headless,
            temp_dir,
            "temp_project",
            "import", file_path,
            "postScript", str(self.script_path),
            "DeleteProject"
        ]

        try:
            result = subprocess.run(
                cmd,
                capture_output = True,
                text = True,
                timeout = 120
            )

            time.sleep(3)

            if os.path.exists(output_file):
                with open(output_file, 'r') as f:
                    functions = json.load(f)
                os.remove(output_file)

                print(f"Decompiled {len(functions)} functions")
                return {
                    "Success :": True,
                    "Functions": functions,
                    "Total": len(functions)
                }
            else:
                return {
                    "success": False,
                    "error": "No output generated",
                    "stdout": result.stdout,
                    "stderr": result.stderr
                }

        
        
