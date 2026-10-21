// Read-only Listing export for the manufacturer eight-layer inspection.
// Use only after audit_layer8.py accepts the exact input. See docs/layer8-audit.md.
import ghidra.app.script.GhidraScript;
import ghidra.program.model.listing.Instruction;

public class AuditLayer8 extends GhidraScript {
    public void run() throws Exception {
        if (!currentProgram.getLanguageID().toString().equals("ARM:LE:32:Cortex")) {
            throw new Exception("Expected ARM:LE:32:Cortex");
        }
        String hash = currentProgram.getExecutableSHA256();
        if (!"eb3c2bc80ed7f4495f77781da6918b9b30738fcff6a3c59af9d583bc21e0809a".equals(hash)) {
            throw new Exception("Unknown payload; refusing fixed-address inspection");
        }
        println("LAYER8 AUDIT SHA256=" + hash);
        println("Static observations only; no hardware or flashing validation.");
        long[][] ranges = {
            {0x080101E0L, 0x080102B0L}, // Startup, VTOR and early-init calls
            {0x0801386AL, 0x080138A4L}, // Keycode bounds and EEPROM addressing
            {0x080142B2L, 0x080142D4L}, // GPIO input/pullup helper
            {0x0801861CL, 0x0801869AL}, // Storage sizing and sector selection
            {0x08018A2AL, 0x08018A5AL}, // Matrix initialization
            {0x08018ACEL, 0x08018AD8L}, // Bootloader request marker and reset call
            {0x0801958AL, 0x080195D2L}, // Layer count and keymap buffer bounds
            {0x08019EA0L, 0x08019F08L}, // USB descriptor selection
            {0x0801A9B8L, 0x0801A9D2L}, // SCB AIRCR reset
            {0x0801AA62L, 0x0801AB10L}, // RCC/HSE/PLL programming
            {0x0801D108L, 0x0801D1BAL}  // Column selection and row IDR reads
        };
        for (long[] range : ranges) {
            println(String.format("RANGE 0x%08x..0x%08x", range[0], range[1]));
            Instruction instruction = getInstructionAt(toAddr(range[0]));
            if (instruction == null) {
                throw new Exception("No instruction at requested start; inspect manually, do not infer decoding.");
            }
            while (instruction != null && instruction.getAddress().getOffset() < range[1]) {
                println(instruction.getAddress() + "  " + instruction);
                instruction = instruction.getNext();
            }
        }
    }
}
