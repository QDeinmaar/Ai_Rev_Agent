import subprocess
import json
import os
import time
from pathlib import Path


class GhidraClient:
    def __init__(self, ghidra_path=r"C:\Users\tudor\Downloads\ghidra\ghidra_12.0.4_PUBLIC"):
        self.ghidra_path = ghidra_path
        self.headless = os.path.join(ghidra_path, "support", "analyzeHeadless.bat")
        self.script_path = Path(__file__).parent.parent / "ghidra_scripts" / "SimpleExport.java"
        self.output_file = r"C:\Users\tudor\Desktop\ghidra_output.json"
    
    def decompile(self, file_path, timeout=180):

        if not os.path.exists(file_path):
            print(f"File not found: {file_path}")
            return []
        
        # Delete old output
        if os.path.exists(self.output_file):
            os.remove(self.output_file)
        
        cmd = [
            self.headless,
            "C:\\temp", "ghidra_auto",
            "-import", file_path,
            "-scriptPath", str(self.script_path.parent),
            "-postScript", "SimpleExport.java",
            "-deleteProject"
        ]
        
        print(f"[*] Decompiling: {Path(file_path).name}")
        print("    This takes 30-120 seconds...")
        
        try:
            # Run Ghidra
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=timeout
            )

            time.sleep(2)
            
            # Check if output exists

            if os.path.exists(self.output_file):
                with open(self.output_file, 'r', encoding='utf-8') as f:
                    functions = json.load(f)
                print(f"Decompiled {len(functions)} functions")
                return functions
            else:
                print(f"No output file created")
                return []
                
        except subprocess.TimeoutExpired:
            print(f"Timeout after {timeout} seconds")
            return []
        except Exception as e:
            print(f"Error: {e}")
            return []
    
    def get_pseudocode_text(self, file_path, max_functions=3):
       
        functions = self.decompile(file_path)
        
        if not functions:
            return "No decompiled functions available"
        
        output = f"Decompiled code from {Path(file_path).name}:\n\n"
        
        for func in functions[:max_functions]:
            output += f"\n{'=' *60}\n"
            output += f"Function: {func.get('name', 'unknown')}\n"
            output += f"Address: {func.get('address', 'unknown')}\n"
            output += f"{'=' *60}\n"
            
            pseudocode = func.get('pseudocode', '')

            # Clean up escaped characters

            pseudocode = pseudocode.replace('\\n', '\n').replace('\\"', '"')
            output += pseudocode[:3000] + "\n"
        
        return output


# Test

if __name__ == "__main__":
    client = GhidraClient()
    result = client.get_pseudocode_text(r"C:\Windows\System32\notepad.exe")
    print(result)