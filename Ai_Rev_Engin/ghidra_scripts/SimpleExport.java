/* SimpleExport.java - Works with Ghidra's Java version */

import ghidra.app.script.GhidraScript;
import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileResults;
import ghidra.program.model.listing.Function;
import ghidra.util.task.ConsoleTaskMonitor;
import java.io.FileWriter;
import java.util.ArrayList;
import java.util.List;

public class SimpleExport extends GhidraScript {

    @Override
    public void run() throws Exception {
        
        if (currentProgram == null) {
            println("ERROR: No program loaded");
            return;
        }
        
        println("Starting decompilation...");
        
        DecompInterface decomp = new DecompInterface();
        decomp.openProgram(currentProgram);
        ConsoleTaskMonitor monitor = new ConsoleTaskMonitor();
        
        // Collect functions into a list (old Java way)
        List<Function> functionList = new ArrayList<Function>();
        for (Function func : currentProgram.getFunctionManager().getFunctions(true)) {
            functionList.add(func);
        }
        
        StringBuilder json = new StringBuilder();
        json.append("[\n");
        
        int count = 0;
        int max = 5;
        
        for (Function func : functionList) {
            if (count >= max) break;
            
            DecompileResults res = decomp.decompileFunction(func, 0, monitor);
            
            json.append("  {\n");
            json.append("    \"name\": \"").append(escape(func.getName())).append("\",\n");
            json.append("    \"address\": \"").append(func.getEntryPoint().toString()).append("\"");
            
            if (res.decompileCompleted()) {
                String code = res.getDecompiledFunction().getC();
                // Remove newlines for JSON
                code = code.replace("\n", "\\n").replace("\r", "");
                json.append(",\n    \"pseudocode\": \"").append(escape(code)).append("\"\n");
            } else {
                json.append("\n");
            }
            
            json.append("  }");
            if (count < max - 1) json.append(",");
            json.append("\n");
            
            count++;
            println("Decompiled: " + func.getName());
        }
        
        json.append("]\n");
        decomp.dispose();
        
        String path = "C:\\Users\\tudor\\Desktop\\ghidra_output.json";
        try (FileWriter fw = new FileWriter(path)) {
            fw.write(json.toString());
        }
        
        println("Saved " + count + " functions to " + path);
    }
    
    private String escape(String s) {
        if (s == null) return "";
        return s.replace("\\", "\\\\")
                .replace("\"", "\\\"");
    }
}