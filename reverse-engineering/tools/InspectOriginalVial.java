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
            {0x08018ED6L, 0x08018F82L}, // Matrix edge -> RGB hit-buffer gate (inspection only)
            {0x08019212L, 0x08019218L}, // Release edge skips RGB hit block
            {0x080192BCL, 0x0801933EL}, // Hit append and heatmap gate
            {0x08019772L, 0x080197BCL}, // VialRGB table literal load, stride4/count45 supported loop
            {0x08013CD8L, 0x08013D18L}, // RGB default reset / captured-storage boundary inspection
            {0x080132ECL, 0x08013380L}, // GRB setter and PWM encoding
            {0x08013924L, 0x08013A74L}, // PB10, DMA and PWM initialization
            {0x080184B6L, 0x080184D8L}, // PWM object assigned TIM2 base
            {0x080156F8L, 0x08015756L}, // Per-chunk switch/underglow gating
            {0x08015AB6L, 0x08015AC4L}, // Last shift edge, not modifier mask
            {0x08015EBAL, 0x08015EDCL}, // Backspace/Delete selection
            {0x08015FE0L, 0x08016038L}, // Six press-only RGB controls
            {0x08014148L, 0x08014182L}, // Tap register -> 64-bit delay conversion -> unregister
            {0x08014188L, 0x08014196L}, // Caps Lock vs normal uint16 delay selection
            {0x080141FAL, 0x08014218L}, // Byte EEPROM read wrapper (not emulated backend)
            {0x080143C0L, 0x0801443CL}, // Byte update and core init (inspection only)
            {0x0801AE04L, 0x0801AE80L}, // VIA validity/init/layout (init NOT executed)
            {0x08018B5CL, 0x08018B66L}, // Early VIA-only gate
            {0x08018BBCL, 0x08018BCEL}, // Later core-magic gate
            {0x08018C22L, 0x08018C2CL}, // Later gate's VIA-valid branch
            {0x08014218L, 0x08014248L}, // QS 40-byte load and 26-prototype callback walk
            {0x080144DCL, 0x08014524L}, // QS RAM defaults, BEFORE EEPROM save
            {0x08014548L, 0x08014580L}, // Keycode EEPROM address arithmetic
            {0x08014604L, 0x08014620L}, // Clear cache RAM and reset write cursor, no flash
            {0x08014A7CL, 0x08014AA4L}, // Original RGB chunk limits, all uint8 inputs
            {0x080147C0L, 0x08014868L}, // Actual HSV conversion (inspection only)
            {0x08014900L, 0x0801493CL}, // Byte RNG and bounded byte-range helper
            {0x0801509CL, 0x0801513EL}, // Hidden mode29 final-chunk continuation
            {0x08014F58L, 0x08015068L}, // Hidden mode29 entry and adjacent continuation inspection
            {0x08012B48L, 0x08012B9CL}, // Factory mode15 candidate Chevron math
            {0x0801BE34L, 0x0801BEE0L}, // Index-based effect runner
            {0x08014D1AL, 0x08014D52L}, // Mode15 dispatch branch
            {0x08014AA4L, 0x08014B80L}, // Effect dispatch and jump-table inspection
            {0x08015618L, 0x080156CEL}, // Original renderer dispatch (static inspection only)
            {0x080156CEL, 0x08015756L}, // Caps-before-chunk-filter composition
            {0x0801441EL, 0x08014434L}, // RGB group reset: RAM and captured kb/user writes, before flush
            {0x08018C84L, 0x08018C98L}, // RGB group startup: zeroed temporary, complete controlled read
            {0x0801AA7EL, 0x0801AA9CL}, // GPIO seven-register writer (RAM-only oracle)
            {0x0801280CL, 0x0801283AL}, // Backing program wrapper (never actual driver execution)
            {0x08012848L, 0x08012888L}, // Backing read/word complement and flag order
            {0x0801B49CL, 0x0801B4D0L}, // Sector offset/size helpers
            {0x08018758L, 0x08018816L}, // Consolidated read, FNV64 and checksum comparison
            {0x08018816L, 0x0801888AL}, // Journal entry header, payload and cursor (commit inspection only)
            {0x08018C14L, 0x08018C18L}, // One-word entry cursor
            {0x08019FA2L, 0x08019FAAL}, // Invalid header/address or second-read failure exit
            {0x08019F96L, 0x08019F9EL}, // Data-read failure clear/exit, before outer clear
            {0x08015824L, 0x08015920L}, // Factory defaults and Vial record reset
            {0x08015EDCL, 0x08015F7CL}, // Custom key argument cases 1..11
            {0x08015FA8L, 0x08016032L}, // Cases 12..21 and EEPROM clear
            {0x0801D4A0L, 0x0801D4C4L}, // Term lookup: vendor codes use global uint16
            {0x0801D4C8L, 0x0801D568L}, // Shared space-cadet helper state machine
            {0x08016646L, 0x0801665AL}, // Built-in core switch, before TBB data
            {0x0801679EL, 0x0801680EL}, // Seven built-in argument cases
            {0x0801733CL, 0x08017350L}, // Core default release skip / press reset
            {0x080174D4L, 0x080174DEL}, // Default release boundary, before later handlers
            {0x08015E96L, 0x08015EA4L}, // Earlier vendor switch, before TBB data
            {0x0801B57CL, 0x0801B63CL}, // TIM5 IRQ50 handler / system timer setup (inspection only)
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
        // Static table/literal references; no HID or original code execution.
        for (long address : new long[] {0x0801E5ECL}) {
            for (ghidra.program.model.symbol.Reference ref : getReferencesTo(toAddr(address))) {
                println("RGB_TABLE_REFERENCE " + toAddr(address) + " <- " + ref.getFromAddress());
                for (ghidra.program.model.symbol.Reference load : getReferencesTo(ref.getFromAddress())) {
                    long site = load.getFromAddress().getOffset();
                    println("RGB_TABLE_LITERAL_LOAD " + load.getFromAddress());
                    InstructionIterator code = currentProgram.getListing().getInstructions(toAddr(site - 48), true);
                    while (code.hasNext()) {
                        Instruction ins = code.next();
                        if (ins.getAddress().getOffset() > site + 96) break;
                        println(ins.getAddress() + "  " + ins);
                    }
                }
            }
        }
        for (long literal : new long[] {0x08018F94L}) {
            for (ghidra.program.model.symbol.Reference ref : getReferencesTo(toAddr(literal))) {
                long site = ref.getFromAddress().getOffset();
                println("RGB_EVENT_LED_LITERAL_LOAD " + ref.getFromAddress());
                Function owner = getFunctionContaining(ref.getFromAddress());
                if (owner != null) println("RGB_EVENT_OWNER " + owner.getEntryPoint());
                InstructionIterator code = currentProgram.getListing().getInstructions(toAddr(site - 80), true);
                while (code.hasNext()) {
                    Instruction ins = code.next();
                    if (ins.getAddress().getOffset() > site + 96) break;
                    println(ins.getAddress() + "  " + ins);
                }
            }
        }
        Function renderer = getFunctionContaining(toAddr(0x080156CEL));
        if (renderer != null) println("RGB_RENDERER_CONTAINING_CAPS " + renderer.getEntryPoint());
        DecompInterface decompiler = new DecompInterface();
        try {
            if (!decompiler.openProgram(currentProgram)) throw new Exception(decompiler.getLastMessage());
            for (long address : new long[] {0x08012B48L, 0x0801BE34L, 0x080147C0L, 0x08014900L, 0x08014924L, 0x08014AA4L, 0x08015618L, 0x08013CD8L, 0x08013CF4L, 0x080132ECL, 0x08013320L, 0x08013924L, 0x08014148L, 0x08014188L, 0x080144DCL, 0x08014604L, 0x080143E4L, 0x0801AE04L, 0x0801AE2EL, 0x0801AE74L, 0x08015824L, 0x08013ECCL, 0x0801B010L, 0x0801D4A0L, 0x0801D4C8L}) {
                Function f = getFunctionAt(toAddr(address));
                if (f == null) f = createFunction(toAddr(address), null);
                if (f == null) throw new Exception(String.format("Missing function for decompilation: %08x", address));
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
