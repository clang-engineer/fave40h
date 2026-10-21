// Reproducible, original-only Ghidra evidence inspection. No executable-byte edits.
import ghidra.app.script.GhidraScript;
import ghidra.app.decompiler.*;
import ghidra.program.model.listing.*;

public class InspectOriginalVial extends GhidraScript {
    public void run() throws Exception {
        String sha = currentProgram.getExecutableSHA256();
        if (!"9df2375a5dfc7d155c3320ea5df3f2cff6920686928ae6ff5c186de5bee453e4".equals(sha)
            || !"ARM:LE:32:Cortex".equals(currentProgram.getLanguageID().toString())) {
            throw new Exception("Wrong target: original FAve40H_VIAL payload and Cortex language required");
        }
        println("ORIGINAL VIAL SHA256=" + sha);
        // The reset routine requests SYSRESETREQ then loops forever. Propagate
        // that verified fact to its reboot caller so decompilation does not
        // falsely run on into the next function or RGB-switch case.
        for (long address : new long[] {0x0801B010L, 0x08013ECCL}) {
            Function f = getFunctionAt(toAddr(address));
            if (f == null) {
                disassemble(toAddr(address));
                f = createFunction(toAddr(address), null);
            }
            if (f == null) throw new Exception("Unable to define known reset function");
            f.setNoReturn(true);
            println("Analysis metadata only: no-return at " + f.getEntryPoint());
        }
        long[][] ranges = {
            {0x08014548L, 0x08014580L}, // Keycode EEPROM address arithmetic
            {0x08015824L, 0x08015920L}, // Factory defaults and Vial record reset
            {0x08015EDCL, 0x08015F7CL}, // Custom key argument cases 1..11
            {0x08015FA8L, 0x08016032L}, // Cases 12..21 and EEPROM clear
            {0x0801D4C8L, 0x0801D568L}, // Shared space-cadet state machine
            {0x0801AA7EL, 0x0801AA9CL}, // GPIO register writer field ordering
            {0x0801B034L, 0x0801B168L}, // Original early GPIO/clock init
            {0x08018C0AL, 0x08018C14L}, // Boot request marker
            {0x0801B010L, 0x0801B02AL}  // SCB reset/no-return
        };
        for (long[] range : ranges) {
            println(String.format("RANGE 0x%08x..0x%08x", range[0], range[1]));
            Instruction instruction = getInstructionAt(toAddr(range[0]));
            if (instruction == null) {
                // Explicit seed at a manually verified boundary in this exact
                // payload. Headerless auto-analysis need not discover it.
                disassemble(toAddr(range[0]));
                instruction = getInstructionAt(toAddr(range[0]));
            }
            if (instruction == null) throw new Exception("Missing instruction at range start");
            while (instruction != null && instruction.getAddress().getOffset() < range[1]) {
                println(instruction.getAddress() + "  " + instruction);
                instruction = instruction.getNext();
            }
        }
        DecompInterface decompiler = new DecompInterface();
        try {
            if (!decompiler.openProgram(currentProgram)) throw new Exception(decompiler.getLastMessage());
            for (long address : new long[] {0x08015824L, 0x08013ECCL, 0x0801B010L, 0x0801D4C8L}) {
                Function f = getFunctionAt(toAddr(address));
                if (f == null) throw new Exception("Missing function for decompilation");
                DecompileResults result = decompiler.decompileFunction(f, 30, monitor);
                if (!result.decompileCompleted() || result.getDecompiledFunction() == null)
                    throw new Exception(result.getErrorMessage());
                println("PSEUDOCODE (not original source): " + f.getEntryPoint());
                println(result.getDecompiledFunction().getC());
            }
        } finally { decompiler.dispose(); }
        println("ORIGINAL_INSPECTION_COMPLETE");
    }
}
