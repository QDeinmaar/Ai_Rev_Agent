import json
from ghidra.app.decompiler import DecompInterface
from ghidra.util.task import ConsoleTaskMonitor

def decompile_functions():
    program = getCurrentProgram()
    decomp = DecompInterface()
    decomp.openProgram(program)
    monitor = ConsoleTaskMonitor()
    
    function_manager = program.getFunctionManager()
    functions = function_manager.getFunctions(True)
    
    results = []
    count = 0
    
    for func in functions:
        if count >= 10:
            break
            
        result = decomp.decompileFunction(func, 0, monitor)
        
        if result.decompileCompleted():
            pseudocode = result.getDecompiledFunction().getC()
            results.append({
                "name": func.getName(),
                "address": str(func.getEntryPoint()),
                "pseudocode": pseudocode
            })
            count += 1
    
    decomp.dispose()
    
    # Save output
    with open(r"C:\Users\tudor\Desktop\ghidra_output.json", "w") as f:
        json.dump(results, f, indent=2)
    
    print(f"Decompiled {count} functions")

decompile_functions()