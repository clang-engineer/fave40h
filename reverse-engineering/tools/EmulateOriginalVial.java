// Execute ORIGINAL Thumb instructions with Ghidra 12.1's P-code emulator.
// Pure-RAM routines / bounded case slices only. No USB, MMIO or device access.
// args: [--rgb-events | --rgb-mode29-interval | --rgb-mode29-frames | --rgb-mode29-frames-real-hsv | --rgb-mode15 | --rgb-mode15-staging | --rgb-hsv] OUTPUT.json [--check]. Default refuses overwrite; --check is read-only.
import ghidra.app.script.GhidraScript;
import ghidra.pcode.emu.*;
import ghidra.program.model.lang.RegisterValue;
import com.google.gson.*;
import java.math.BigInteger;
import java.nio.file.*;
import java.security.MessageDigest;
import java.util.HexFormat;

public class EmulateOriginalVial extends GhidraScript {
    private static final long COLORS = 0x20005064L, PWM = 0x200031E0L;
    private static final long FLAGS = 0x20001EE4L, SHIFT = 0x20001C40L;
    private static final String SHA = "9df2375a5dfc7d155c3320ea5df3f2cff6920686928ae6ff5c186de5bee453e4";
    private PcodeEmulator emu;
    private PcodeThread<byte[]> thread;
    private final HexFormat hex = HexFormat.of();

    private void put(long address, byte[] data) {
        emu.getSharedState().setConcrete(toAddr(address), data);
    }
    private byte[] get(long address, int size) {
        return emu.getSharedState().inspectConcrete(toAddr(address), size);
    }
    private void register(String name, long value) {
        var reg = currentProgram.getRegister(name);
        thread.getState().setVar(reg, thread.getArithmetic().fromConst(value, reg.getMinimumByteSize()));
    }
    private long register(String name) {
        return thread.getState().inspectRegisterValue(currentProgram.getRegister(name)).getUnsignedValue().longValue();
    }
    private interface Hook { boolean intercept(long address) throws Exception; }
    private void execute(long entry, long stop, long... args) throws Exception {
        executeHooked(entry, stop, null, args);
    }
    private void executeHooked(long entry, long stop, Hook hook, long... args) throws Exception {
        executeBudgeted(entry, stop, hook, 50000, args);
    }
    private void executeBudgeted(long entry, long stop, Hook hook, int budget, long... args) throws Exception {
        thread.overrideContext(new RegisterValue(currentProgram.getRegister("TMode"), BigInteger.ONE));
        thread.overrideCounter(toAddr(entry));
        for (int i = 0; i < 13; ++i) register("r" + i, i < args.length ? args[i] : 0);
        register("CY", 0); // ASR by zero preserves carry; do not read undefined CPU state.
        register("sp", 0x20010000L);
        register("lr", 0x08010001L);
        for (int i = 0; i < budget; ++i) {
            monitor.checkCancelled();
            long pc = thread.getCounter().getOffset();
            if (pc == stop) return;
            if (hook != null && hook.intercept(pc)) continue;
            thread.stepInstruction();
        }
        throw new Exception(String.format("Instruction budget exhausted: entry=%08x pc=%s", entry, thread.getCounter()));
    }
    private String digest(byte[] bytes) throws Exception {
        return hex.formatHex(MessageDigest.getInstance("SHA-256").digest(bytes));
    }
    private JsonArray unsigned(byte[] bytes) {
        JsonArray array = new JsonArray();
        for (byte b : bytes) array.add(b & 255);
        return array;
    }
    private byte[] ramp() {
        byte[] data = new byte[216];
        for (int i = 0; i < data.length; ++i) data[i] = (byte)(i * 73 + 19);
        return data;
    }
    private void encode(JsonArray cases, String name, byte[] input) throws Exception {
        put(COLORS, input);
        byte[] initial = new byte[1952 * 4];
        java.util.Arrays.fill(initial, (byte)0xA5); // Includes canary reset tail.
        put(PWM, initial);
        execute(0x08013320L, 0x08010000L);
        JsonObject row = new JsonObject();
        row.addProperty("name", name);
        row.addProperty("input_grb_hex", hex.formatHex(input));
        row.addProperty("initial_pwm_byte", 0xA5);
        row.addProperty("expected_pwm_sha256", digest(get(PWM, initial.length)));
        if (!java.util.Arrays.equals(input, get(COLORS, 216))) throw new Exception("Encoder changed colors");
        cases.add(row);
    }
    private void putTime(int timestamp) {
        put(0x200051BCL, new byte[] {(byte)timestamp, (byte)(timestamp >> 8)});
    }
    private int getTime() {
        byte[] bytes = get(0x200051BCL, 2);
        return (bytes[0] & 255) | ((bytes[1] & 255) << 8);
    }
    private void putTapDelays(int normal, int caps) {
        put(0x200011E6L, new byte[] {(byte)normal,(byte)(normal >> 8),(byte)caps,(byte)(caps >> 8)});
    }
    private boolean captureTapBoundary(JsonArray effects, long pc) {
        String kind = pc == 0x08013F88L ? "register_code" : pc == 0x080140AAL ? "unregister_code" :
            pc == 0x0801B464L ? "sleep_ticks" : null;
        if (kind == null) return false;
        JsonObject effect = new JsonObject();
        effect.addProperty("kind", kind);
        effect.addProperty("argument", register("r0"));
        effects.add(effect);
        thread.overrideCounter(toAddr(register("lr") & ~1L));
        return true;
    }
    private void gpioStartup(JsonArray cases, int index) throws Exception {
        long base = 0x20007004L;
        byte[] guarded = new byte[48]; java.util.Arrays.fill(guarded, (byte)0xA5);
        put(base - 4, guarded);
        executeHooked(0x0801AA7EL, 0x08010000L, pc -> {
            if (pc < 0x0801AA7EL || pc >= 0x0801AA9CL) throw new Exception("GPIO writer escaped bounded RAM probe");
            return false;
        }, base, 0x0801EA14L + index * 28);
        if (getWord(base - 4) != 0xA5A5A5A5L || getWord(base + 40) != 0xA5A5A5A5L)
            throw new Exception("GPIO writer changed guards");
        JsonObject row = new JsonObject(); row.addProperty("port", "ABCDEH".substring(index,index+1));
        JsonArray words = new JsonArray();
        for (int i = 0; i < 10; ++i) words.add(getWord(base + i * 4));
        row.add("register_words", words); cases.add(row);
    }
    private void rgbComposedChunk(JsonArray cases, int iter, int caps, int keylight, int underglow) throws Exception {
        byte[] input = ramp(); put(COLORS, input);
        put(FLAGS, new byte[] {(byte)keylight,(byte)underglow});
        put(0x20000EE8L, new byte[] {(byte)(iter+1)});
        put(0x20008000L, new byte[] {(byte)(iter==4 ? 2 : 1)});
        int[] white = {0};
        executeHooked(0x080156CEL, 0x0801571AL, pc -> {
            if (pc == 0x0801AE80L) {
                register("r0",caps); thread.overrideCounter(toAddr(register("lr") & ~1L)); return true;
            }
            if (pc == 0x08014A78L) {
                int led=(int)register("r0"),r=(int)register("r1"),g=(int)register("r2"),b=(int)register("r3");
                if (led<0 || led>=72 || ((r|g|b)&~255)!=0) throw new Exception("RGB setter escaped bounded colors");
                if (led==22 && r==255 && g==255 && b==255) ++white[0];
                put(COLORS+led*3,new byte[] {(byte)g,(byte)r,(byte)b});
                thread.overrideCounter(toAddr(register("lr") & ~1L)); return true;
            }
            if (!((pc>=0x080156CEL && pc<0x08015756L) || (pc>=0x08014A7CL && pc<0x08014AA4L)))
                throw new Exception("Composed RGB chunk escaped renderer slice");
            return false;
        },0,0,0,0,1,0,0x20008000L);
        JsonObject row=new JsonObject(); row.addProperty("iter",iter); row.addProperty("caps",caps);
        row.addProperty("keylight",keylight); row.addProperty("underglow",underglow);
        row.addProperty("input_grb_hex",hex.formatHex(input)); row.addProperty("expected_grb_sha256",digest(get(COLORS,216)));
        row.addProperty("caps_white_calls",white[0]); row.add("caps_led_after",unsigned(get(COLORS+22*3,3)));
        cases.add(row);
    }
    private void rgbGroupLifecycle(JsonArray cases, boolean reset, long initial, long stored) throws Exception {
        byte[] guard = new byte[12]; java.util.Arrays.fill(guard, (byte)0xA5);
        put(FLAGS - 4, guard); putWord(FLAGS, initial);
        put(0x2001004CL, guard);
        JsonArray io = new JsonArray();
        long entry = reset ? 0x0801441EL : 0x08018C84L;
        long stop = reset ? 0x08014434L : 0x08018C98L;
        executeHooked(entry, stop, pc -> {
            if ((reset && pc == 0x08013C1CL) || (!reset && pc == 0x0801D620L)) {
                JsonObject event = new JsonObject();
                event.addProperty("kind", reset ? "write" : "read");
                event.addProperty("offset", register("r0"));
                event.addProperty("size", 4);
                event.addProperty("state_at_io", getWord(FLAGS));
                if (reset) event.addProperty("word", register("r1"));
                else {
                    long destination = register("r1");
                    if (register("r0") != 0x13 || register("r2") != 4 || destination != 0x20010050L || getWord(destination) != 0)
                        throw new Exception("RGB group load escaped zeroed four-byte temporary");
                    putWord(destination, stored); event.addProperty("word", stored);
                }
                io.add(event);
                thread.overrideCounter(toAddr(register("lr") & ~1L));
                return true;
            }
            if (pc < entry || pc >= stop) throw new Exception("RGB group slice escaped bounded reset/load");
            return false;
        });
        if (getWord(FLAGS - 4) != 0xA5A5A5A5L || getWord(FLAGS + 4) != 0xA5A5A5A5L ||
            getWord(0x2001004CL) != 0xA5A5A5A5L || getWord(0x20010054L) != 0xA5A5A5A5L)
            throw new Exception("RGB group state/temporary guard changed");
        JsonObject row = new JsonObject(); row.addProperty("kind", reset ? "reset" : "load");
        row.addProperty("initial_word", initial); row.addProperty("stored_word", stored);
        row.addProperty("state_after", getWord(FLAGS)); row.add("io", io);
        cases.add(row);
    }
    private void putWord(long address, long word) {
        put(address, new byte[] {(byte)word,(byte)(word >>> 8),(byte)(word >>> 16),(byte)(word >>> 24)});
    }
    private long getWord(long address) {
        byte[] b = get(address, 4);
        return (b[0]&255L) | ((b[1]&255L)<<8) | ((b[2]&255L)<<16) | ((b[3]&255L)<<24);
    }
    private void fakeBacking() {
        putWord(0x200017A4L, 0x2000D000L);
        putWord(0x2000D000L, 0x2000D040L);
        put(0x2000D040L, new byte[32]);
        putWord(0x2000D044L, 0x2000D101L); // controlled get-descriptor callback
        putWord(0x2000D04CL, 0x2000D121L); // captured program callback
        put(0x2000E000L, new byte[28]);
        putWord(0x2000E014L, 0x20008000L); // physical word loads redirected to RAM
    }
    private void backingProgram(JsonArray cases, long offset, long word, int flag, long status) throws Exception {
        fakeBacking();
        putWord(0x20000EB4L, 0xC000);
        put(0x200017A8L, new byte[] {(byte)flag});
        JsonObject row = new JsonObject();
        int[] calls = {0};
        executeHooked(0x0801280CL, 0x08010000L, pc -> {
            if (pc == 0x2000D120L) {
                if (register("r0") != 0x2000D000L || register("r2") != 4) throw new Exception("Unexpected program intent ABI");
                ++calls[0];
                row.addProperty("driver_offset", register("r1"));
                row.addProperty("physical_word", getWord(register("r3")));
                register("r0", status);
                thread.overrideCounter(toAddr(register("lr") & ~1L));
                return true;
            }
            if (pc < 0x0801280CL || pc >= 0x0801283AL) throw new Exception("Program wrapper escaped into real driver");
            return false;
        }, offset, word);
        if (calls[0] != 1) throw new Exception("Program intent missing");
        row.addProperty("offset", offset); row.addProperty("logical_word", word);
        row.addProperty("inversion_flag", flag); row.addProperty("driver_status", status);
        row.addProperty("success", register("r0") == 1);
        cases.add(row);
    }
    private void backingRead(JsonArray cases, long word, int flag, int stale, int observed) throws Exception {
        fakeBacking();
        int offset = new int[] {0,4,4096,4100,8188}[cases.size() % 5];
        putWord(0x20000EB4L, 0x100);
        put(0x200017A8L, new byte[] {(byte)flag});
        put(0x20001791L, new byte[] {(byte)stale});
        put(0x200018EEL, new byte[] {0x5A});
        putWord(0x20008100L + offset, word);
        byte[] output = new byte[12]; java.util.Arrays.fill(output, (byte)0xA5);
        put(0x2000D200L, output);
        int[] calls = {0};
        executeHooked(0x08012848L, 0x08010000L, pc -> {
            if (pc == 0x2000D100L) {
                if (register("r0") != 0x2000D000L) throw new Exception("Unexpected descriptor ABI");
                ++calls[0]; register("r0", 0x2000E000L);
                thread.overrideCounter(toAddr(register("lr") & ~1L)); return true;
            }
            if (pc < 0x08012848L || pc >= 0x08012888L) throw new Exception("Read wrapper escaped RAM probe");
            if (pc == 0x08012876L) {
                if (get(0x20001791L,1)[0] != 0 || get(0x200018EEL,1)[0] != 0)
                    throw new Exception("Read wrapper failed to clear stale flags");
                // Controlled final-check byte, NOT a physical bus-fault injection.
                put(0x20001791L, new byte[] {(byte)observed});
            }
            return false;
        }, offset, 0x2000D204L);
        if (calls[0] != 1 || getWord(0x20008100L + offset) != word) throw new Exception("Read source changed");
        if (getWord(0x2000D200L) != 0xA5A5A5A5L || getWord(0x2000D208L) != 0xA5A5A5A5L)
            throw new Exception("Read output guards changed");
        JsonObject row = new JsonObject();
        row.addProperty("physical_word", word); row.addProperty("inversion_flag", flag);
        row.addProperty("offset", offset); row.addProperty("probe_driver_base", 0x100);
        row.addProperty("stale_error", stale); row.addProperty("observed_error", observed);
        row.addProperty("success", register("r0") == 1); row.addProperty("logical_word", getWord(0x2000D204L));
        row.addProperty("final_error", get(0x20001791L,1)[0]&255);
        row.addProperty("final_active", get(0x200018EEL,1)[0]&255);
        cases.add(row);
    }
    private void backingGeometry(JsonArray cases, int index, boolean size) throws Exception {
        fakeBacking();
        long descriptor = 0x0801DE24L + 28 * index;
        long entry = size ? 0x0801B4B6L : 0x0801B49CL;
        executeHooked(entry, 0x08010000L, pc -> {
            if (pc == 0x2000D100L) {
                register("r0", descriptor); thread.overrideCounter(toAddr(register("lr") & ~1L)); return true;
            }
            if (pc < entry || pc >= (size ? 0x0801B4D0L : 0x0801B4B6L)) throw new Exception("Geometry helper escaped");
            return false;
        }, 0x2000D000L, 3);
        JsonObject row = new JsonObject(); row.addProperty("descriptor", descriptor);
        row.addProperty("sector", 3); row.addProperty("kind", size ? "size" : "offset");
        row.addProperty("value", register("r0")); cases.add(row);
    }
    private byte[] journalEntry(int address, int length, int type) {
        return new byte[] {(byte)((type << 6) | (length << 3) | ((address >>> 16) & 7)),
            (byte)(address >>> 8), (byte)address, (byte)0xD3,0x29,(byte)0x80,0,(byte)0xFF};
    }
    private void journalCase(JsonArray cases, byte[] entry, int position, boolean secondOk) throws Exception {
        final long cache = 0x200021D8L, stack = 0x2000FE00L;
        byte[] guards = new byte[4104];
        java.util.Arrays.fill(guards, (byte)0xA5);
        put(cache - 4, guards);
        put(cache, snapshotData("ramp"));
        byte[] frame = new byte[128];
        java.util.Arrays.fill(frame, (byte)0x6D);
        put(stack, frame);
        put(stack + 0x44, java.util.Arrays.copyOf(entry, 4));
        int[] kind = {-1}, reads = {1}; // First word is supplied, not read by this slice.
        boolean[] readFailed = {false};
        executeHooked(0x08018824L, 0x0801887EL, pc -> {
            if (pc == 0x08018824L) {
                register("sp", stack);
                register("r4", position);
                register("r7", cache);
            }
            if (pc == 0x08012848L) {
                if (register("r0") != position + 4 || register("r1") != stack + 0x54 || position + 8 > 8192)
                    throw new Exception("Journal second read escaped bounded slot");
                ++reads[0];
                put(stack + 0x54, secondOk ? java.util.Arrays.copyOfRange(entry, 4, 8) : new byte[4]);
                register("r0", secondOk ? 1 : 0);
                readFailed[0] = !secondOk;
            } else if (pc == 0x08011890L) {
                long target = register("r0"), source = register("r1"), length = register("r2");
                if (source != stack + 0x53 || length > 5 || target < cache || target + length > cache + 4096)
                    throw new Exception("Journal copy escaped writer-domain RAM bounds");
                if (length != 0) put(target, get(source, (int)length));
                kind[0] = 1;
                register("r0", target); // memcpy returns destination
            } else if (pc == 0x08018886L) {
                // Stop BEFORE global cursor commit and all consolidation callbacks.
                kind[0] = register("r0") == 1 ? 0 : readFailed[0] ? 3 : 2;
                thread.overrideCounter(toAddr(0x0801887EL));
                return true;
            } else {
                if (!((pc >= 0x08018824L && pc < 0x0801887EL) || pc == 0x08018884L ||
                    (pc >= 0x08018C14L && pc < 0x08018C18L) || (pc >= 0x08019FA2L && pc < 0x08019FAAL)))
                    throw new Exception("Journal slice escaped into unapproved code");
                return false;
            }
            thread.overrideCounter(toAddr(register("lr") & ~1L));
            return true;
        });
        if (kind[0] < 0) throw new Exception("Journal outcome missing");
        byte[] after = get(cache - 4, 4104);
        for (int i : new int[] {0,1,2,3,4100,4101,4102,4103})
            if (after[i] != (byte)0xA5) throw new Exception("Journal cache/cursor guards changed");
        JsonObject row = new JsonObject();
        row.addProperty("entry_hex", hex.formatHex(entry));
        row.addProperty("position", position);
        row.addProperty("second_read_ok", secondOk);
        row.addProperty("kind", kind[0]);
        row.addProperty("next_position", register("r4"));
        row.addProperty("read_words", reads[0]);
        boolean nonzero = false;
        for (int i = 0; i < 4; ++i) nonzero |= entry[i] != 0;
        if (nonzero && (entry[0] & 0xC0) == 0) {
            row.addProperty("decoded_address", register("r5"));
            row.addProperty("decoded_length", register("r9"));
        }
        row.addProperty("cache_sha256", digest(get(cache, 4096)));
        cases.add(row);
    }
    private byte[] snapshotData(String pattern) {
        byte[] data = new byte[4096];
        long seed = 0x12345678L;
        for (int i = 0; i < data.length; ++i) {
            seed = (seed * 1664525L + 1013904223L) & 0xFFFFFFFFL;
            data[i] = (byte)(pattern.equals("ff") ? 255 : pattern.equals("ramp") ? i * 73 + 19 :
                pattern.equals("lcg") ? seed >>> 24 : 0);
        }
        return data;
    }
    private void snapshotCase(JsonArray cases, String pattern, String mode, int failWord) throws Exception {
        final long cache = 0x200021D8L;
        byte[] data = snapshotData(pattern), input = new byte[4104];
        System.arraycopy(data, 0, input, 0, data.length);
        // Construct a candidate checksum; EXPECTED results come from Thumb below.
        long hash = 0xCBF29CE484222325L;
        for (byte value : data) hash = (hash ^ (value & 255L)) * 0x100000001B3L;
        if (mode.equals("bit0")) hash ^= 1;
        if (mode.equals("bit63")) hash ^= Long.MIN_VALUE;
        if (mode.equals("erased")) hash = 0; // normalized backing zeros, not physical flash
        for (int i = 0; i < 8; ++i) input[4096 + i] = (byte)(hash >>> (8 * i));
        byte[] guards = new byte[4108];
        java.util.Arrays.fill(guards, (byte)0xA5);
        put(cache - 4, guards);
        put(cache + 4096, new byte[] {(byte)0xEF,(byte)0xBE,(byte)0xAD,(byte)0xDE});
        byte[] stack = new byte[128];
        java.util.Arrays.fill(stack, (byte)0x6D);
        put(0x2000FDF0L, stack);
        int[] reads = {0}, clears = {0};
        boolean[] failed = {false};
        String[] computed = {null};
        executeBudgeted(0x08018758L, 0x08018816L, pc -> {
            if (pc == 0x08018758L) register("sp", 0x2000FE00L);
            if (pc == 0x080187F0L)
                computed[0] = String.format("%016x", (register("r5") << 32) | register("r4"));
            if (pc == 0x08012848L) {
                long offset = register("r0"), destination = register("r1");
                if ((offset & 3) != 0 || offset < 0 || offset > 4100 ||
                    destination != (offset < 4096 ? cache + offset : 0x2000FE50L + offset - 4096))
                    throw new Exception("Snapshot read escaped controlled input/RAM");
                ++reads[0];
                boolean ok = offset >= 4096 || offset / 4 != failWord;
                put(destination, ok ? java.util.Arrays.copyOfRange(input, (int)offset, (int)offset + 4) : new byte[4]);
                if (!ok) failed[0] = true;
                register("r0", ok ? 1 : 0);
            } else if (pc == 0x08011ABCL) {
                if (register("r0") != cache || register("r1") != 0 || register("r2") != 4096)
                    throw new Exception("Unexpected snapshot memset");
                put(cache, new byte[4096]);
                register("r0", cache);
                ++clears[0];
            } else if (pc == 0x08018896L) {
                if (!failed[0]) throw new Exception("Unexpected failed-load exit");
                // Stop before the caller's second clear and all later startup work.
                thread.overrideCounter(toAddr(0x08018816L));
                return true;
            } else {
                if (!((pc >= 0x08018758L && pc < 0x08018816L) ||
                    (pc >= 0x08014604L && pc < 0x08014620L) ||
                    (pc >= 0x08019F96L && pc < 0x08019F9EL)))
                    throw new Exception("Snapshot slice escaped into unapproved code");
                return false;
            }
            thread.overrideCounter(toAddr(register("lr") & ~1L));
            return true;
        }, 200000);
        byte[] after = get(cache - 4, 4108);
        for (int i : new int[] {0,1,2,3,4104,4105,4106,4107})
            if (after[i] != (byte)0xA5) throw new Exception("Snapshot crossed cache/cursor guards");
        byte[] cursor = get(cache + 4096, 4);
        long writeAddress = 0;
        for (int i = 0; i < 4; ++i) writeAddress |= (cursor[i] & 255L) << (8 * i);
        JsonObject row = new JsonObject();
        row.addProperty("pattern", pattern);
        row.addProperty("mode", mode);
        row.addProperty("fail_data_word", failWord);
        row.addProperty("input_data_sha256", digest(data));
        row.addProperty("checkpoint_le_hex", hex.formatHex(java.util.Arrays.copyOfRange(input, 4096, 4104)));
        row.addProperty("computed_fnv64_hex", computed[0]);
        row.addProperty("read_words", reads[0]);
        row.addProperty("cache_clears", clears[0]);
        row.addProperty("data_read_failed", failed[0]);
        row.addProperty("cache_sha256", digest(get(cache, 4096)));
        row.addProperty("write_address", writeAddress);
        cases.add(row);
    }
    private boolean prefixBoundary(byte[] prefix, JsonArray reads, JsonArray resets, long pc) throws Exception {
        if (pc == 0x080141FAL || pc == 0x08013BA8L) {
            long offset = register("r0");
            int size = pc == 0x080141FAL ? 1 : 2;
            if (offset < 0 || offset + size > prefix.length) throw new Exception("Prefix read escaped input");
            JsonObject read = new JsonObject();
            read.addProperty("offset", offset);
            read.addProperty("size", size);
            reads.add(read);
            int value = prefix[(int)offset] & 255;
            if (size == 2) value |= (prefix[(int)offset + 1] & 255) << 8;
            register("r0", value);
        } else if (pc == 0x0801AE2EL || pc == 0x080143E4L) {
            // Stop at reset entries: NO initializer, EEPROM or flash code executes.
            resets.add(pc == 0x0801AE2EL ? "via_init" : "core_init");
        } else return false;
        thread.overrideCounter(toAddr(register("lr") & ~1L));
        return true;
    }
    private void prefixValidityCase(JsonArray cases, byte[] stamp) throws Exception {
        byte[] prefix = new byte[41];
        java.util.Arrays.fill(prefix, (byte)0xA5);
        System.arraycopy(stamp, 0, prefix, 37, 3);
        JsonArray reads = new JsonArray(), resets = new JsonArray();
        executeHooked(0x0801AE04L, 0x08010000L, pc -> prefixBoundary(prefix, reads, resets, pc));
        if (resets.size() != 0) throw new Exception("Validity checker called reset");
        JsonObject row = new JsonObject();
        row.addProperty("stamp_hex", hex.formatHex(stamp));
        row.addProperty("valid", register("r0") != 0);
        row.add("reads", reads);
        cases.add(row);
    }
    private void tapCase(JsonArray cases, int keycode, int normal, int caps) throws Exception {
        putTapDelays(normal, caps);
        JsonArray effects = new JsonArray();
        // Execute the real 64-bit multiply/divide too; only HID and sleep are intercepted.
        executeHooked(0x08014188L, 0x08010000L, pc -> captureTapBoundary(effects, pc), keycode);
        JsonObject row = new JsonObject();
        row.addProperty("keycode", keycode);
        row.addProperty("normal_delay_ms", normal);
        row.addProperty("caps_delay_ms", caps);
        row.add("effects", effects);
        cases.add(row);
    }
    private void expandedCadetCase(JsonArray cases, long entry, int key, boolean core) throws Exception {
        execute(entry, 0x0801D4C8L, cadetArguments(key, false, core));
        int hold = (int)register("r2");
        put(0x20001CEDL, new byte[] {(byte)hold});
        putTime(100);
        put(0x200011E0L, new byte[] {(byte)200,0});
        putTapDelays(7, 19);
        JsonArray effects = new JsonArray();
        executeHooked(entry, 0x08015C6EL, pc -> {
            if (pc == 0x0801B374L) register("r0", 101);
            else if (pc == 0x08013F74L || pc == 0x08014098L) {
                JsonObject effect = new JsonObject();
                effect.addProperty("kind", pc == 0x08013F74L ? "register_mods" : "unregister_mods");
                effect.addProperty("argument", register("r0"));
                effects.add(effect);
            } else return captureTapBoundary(effects, pc);
            thread.overrideCounter(toAddr(register("lr") & ~1L));
            return true;
        }, cadetArguments(key, false, core));
        JsonObject row = new JsonObject();
        row.addProperty("keycode", key);
        row.addProperty("core_stage", core);
        row.addProperty("before_last_modifier", hold);
        row.addProperty("before_pressed_at", 100);
        row.addProperty("now", 101);
        row.addProperty("tapping_term", 200);
        row.addProperty("normal_delay_ms", 7);
        row.addProperty("caps_delay_ms", 19);
        row.addProperty("after_last_modifier", get(0x20001CEDL, 1)[0] & 255);
        row.addProperty("after_pressed_at", getTime());
        row.add("effects", effects);
        cases.add(row);
    }
    private long[] cadetArguments(int keycode, boolean pressed, boolean coreStage) {
        long[] args = new long[11];
        args[4] = keycode;
        args[5] = pressed ? 1 : 0;
        if (coreStage) {
            put(0x2000E000L, new byte[] {0,0,0,0,0,(byte)(pressed ? 1 : 0)});
            args[10] = 0x2000E000L;
        }
        return args;
    }
    private void cadetCase(JsonArray cases, long entry, int keycode, String name, boolean pressed,
        int last, int started, int now, int term, boolean coreStage) throws Exception {
        put(0x20001CEDL, new byte[] {(byte)last});
        putTime(started);
        put(0x200011E0L, new byte[] {(byte)term, (byte)(term >> 8)});
        JsonArray effects = new JsonArray();
        int[] timerReads = {0};
        executeHooked(entry, 0x08015C6EL, pc -> {
            if (pc == 0x0801B374L) {
                ++timerReads[0];
                register("r0", now); // Controlled clock boundary, not MMIO emulation.
            } else if (pc == 0x08013F74L || pc == 0x08014098L || pc == 0x08014188L) {
                JsonObject effect = new JsonObject();
                effect.addProperty("kind", pc == 0x08013F74L ? "register_mods" :
                    pc == 0x08014098L ? "unregister_mods" : "tap_code");
                effect.addProperty("argument", register("r0") & 255);
                effects.add(effect); // Record call intent; do NOT execute HID/delay code.
            } else return false;
            thread.overrideCounter(toAddr(register("lr") & ~1L));
            return true;
        }, cadetArguments(keycode, pressed, coreStage));
        JsonObject row = new JsonObject();
        row.addProperty("name", name);
        row.addProperty("keycode", keycode);
        row.addProperty("pressed", pressed);
        row.addProperty("before_last_modifier", last);
        row.addProperty("before_pressed_at", started);
        row.addProperty("now", now);
        row.addProperty("tapping_term", term);
        row.addProperty("after_last_modifier", get(0x20001CEDL, 1)[0] & 255);
        row.addProperty("after_pressed_at", getTime());
        row.addProperty("timer_reads", timerReads[0]);
        row.add("effects", effects);
        cases.add(row);
    }
    private void cadetScenarios(JsonArray cases, long entry, int key, int hold, boolean core) throws Exception {
        cadetCase(cases,entry,key,"press",true,255,65534,4660,200,core);
        cadetCase(cases,entry,key,"zero_elapsed",false,hold,100,100,200,core);
        cadetCase(cases,entry,key,"below_term",false,hold,100,299,200,core);
        cadetCase(cases,entry,key,"at_term",false,hold,100,300,200,core);
        cadetCase(cases,entry,key,"past_term",false,hold,100,301,200,core);
        cadetCase(cases,entry,key,"interrupted",false,0,100,101,200,core);
        cadetCase(cases,entry,key,"different_modifier",false,hold == 0xE1 ? 0xE5 : 0xE1,100,101,200,core);
        cadetCase(cases,entry,key,"wrap_quick",false,hold,65530,4,11,core);
        cadetCase(cases,entry,key,"wrap_at_term",false,hold,65530,4,10,core);
        cadetCase(cases,entry,key,"zero_term",false,hold,100,100,0,core);
        cadetCase(cases,entry,key,"max_term_quick",false,hold,0,65534,65535,core);
        cadetCase(cases,entry,key,"max_term_equal",false,hold,0,65535,65535,core);
        cadetCase(cases,entry,key,"one_term_quick",false,hold,100,100,1,core);
        cadetCase(cases,entry,key,"one_term_wrap_equal",false,hold,65535,0,1,core);
    }
    private void rgbKeyEvent(JsonArray cases, int row, int col, boolean pressed, int count) throws Exception {
        long hits=0x20001AC6L, stack=0x20010000L;
        byte[] initial=new byte[41];
        for(int i=0;i<initial.length;i++) initial[i]=(byte)(i*37+19);
        initial[0]=(byte)count;
        byte[] guarded=new byte[49]; java.util.Arrays.fill(guarded,(byte)0xA5);
        System.arraycopy(initial,0,guarded,4,41); put(hits-4,guarded);
        put(stack-256,new byte[384]);
        putWord(stack+12,0x0801DEA0L+row*12+col);
        final int[] copies={0};
        executeHooked(0x08018EFAL,0x080192CAL,pc -> {
            if(pc==0x08011890L) copies[0]++;
            if(!((pc>=0x08018EFAL && pc<0x08018F82L) ||
                 (pc>=0x08019294L && pc<0x080192CAL) ||
                 (pc>=0x08019212L && pc<0x08019218L) ||
                 (pc>=0x08011890L && pc<0x08011ABCL)))
                throw new Exception("RGB key event escaped hit-buffer/memcpy slice: "+Long.toHexString(pc));
            return false; // Original Thumb memcpy runs too; no memcpy API replacement.
        },0,0,0,0,0x0801DEA0L,0,0,pressed ? 1<<col : 0);
        byte[] after=get(hits-4,49);
        for(int i=0;i<4;i++) if(after[i]!=(byte)0xA5 || after[45+i]!=(byte)0xA5)
            throw new Exception("RGB hit-buffer guard changed");
        JsonObject entry=new JsonObject(); entry.addProperty("row",row); entry.addProperty("col",col);
        entry.addProperty("pressed",pressed); entry.addProperty("initial_count",count);
        entry.addProperty("before_hex",hex.formatHex(initial));
        entry.addProperty("after_hex",hex.formatHex(get(hits,41))); entry.addProperty("original_memcpy_calls",copies[0]);
        cases.add(entry);
    }

    private void rgbMode29Interval(JsonArray cases,int speed,long now) throws Exception {
        long config=0x20001CE0L,wait=0x20002180L,timer=0x200018E0L;
        byte[] cfg=new byte[6]; java.util.Arrays.fill(cfg,(byte)0xA5); cfg[4]=(byte)speed;
        byte[] guarded=new byte[12]; java.util.Arrays.fill(guarded,(byte)0xA5);
        put(config,cfg); put(wait-4,guarded); putWord(timer,now);
        executeHooked(0x080150D8L,0x080150FAL,pc -> {
            if(pc<0x080150D8L || pc>=0x080150FAL) throw new Exception("Mode29 interval escaped arithmetic slice");
            return false;
        },0,0,0,0,0,0,0,config,0,wait,timer);
        if(getWord(wait-4)!=0xA5A5A5A5L || getWord(wait+4)!=0xA5A5A5A5L ||
           getWord(timer)!=now || !java.util.Arrays.equals(cfg,get(config,6)))
            throw new Exception("Mode29 interval changed input/guards");
        JsonObject row=new JsonObject(); row.addProperty("speed",speed); row.addProperty("now",now);
        row.addProperty("next_wait",getWord(wait)); cases.add(row);
    }

    private void rgbMode29Frames(JsonArray sequences,int speed,int seed,boolean realHsv) throws Exception {
        long state=0x20001B55L,wait=0x20002180L,timer=0x200018E0L;
        byte[] guarded=new byte[224]; java.util.Arrays.fill(guarded,(byte)0xA5);
        java.util.Arrays.fill(guarded,4,220,(byte)0); put(state-4,guarded);
        byte[] waitGuard=new byte[12]; java.util.Arrays.fill(waitGuard,(byte)0xA5); put(wait-4,waitGuard); putWord(wait,0);
        byte[] globals=new byte[12]; java.util.Arrays.fill(globals,(byte)0xA5); put(0x20000EE4L,globals);
        put(0x20000EE6L,new byte[]{(byte)seed,(byte)(seed>>8)});
        byte[] pixels=new byte[216]; java.util.Arrays.fill(pixels,(byte)0xA5); put(COLORS,pixels);
        int value=seed==0 ? 255 : 128;
        JsonObject sequence=new JsonObject(); sequence.addProperty("speed",speed); sequence.addProperty("initial_seed",seed);
        sequence.addProperty("value",value); JsonArray steps=new JsonArray();
        int[] iters={0,1,2,3,4,0,0,0,1,2,3,4,0,0,4,0};
        int[] flags={255,4,2,0,255,255,255,255,255,255,255,255,255,255,255,255};
        long[] times={0,0,0,0,0,1,1,3000,3000,3000,3000,3000,3001,6000,0xFFFFFF00L,0xFFFFFF01L};
        for(int step=0;step<iters.length;step++) {
            boolean init=step==0 || step==5 || step==13;
            byte[] config={(byte)0x75,17,(byte)254,(byte)value,(byte)speed,(byte)flags[step],(byte)0xA5,(byte)0xA5};
            put(0x20001CE0L,config); putWord(timer,times[step]);
            put(0x20000EE8L,new byte[]{(byte)iters[step],(byte)flags[step],0,(byte)(init?0:29),1,1});
            put(0x2000FE00L,new byte[576]); // Fully defined synthetic call frame, incl HSV padding.
            JsonArray trace=new JsonArray(); final int[] copies={0},hsvCalls={0};
            final long[] hsvReturn={-1},hsvInput={0},hsvSaved=new long[9];
            executeHooked(0x08014AA4L,0x08010000L,pc -> {
                if(realHsv && pc==0x080147C0L) {
                    if(hsvReturn[0]!=-1) throw new Exception("Nested HSV call outside pure converter contract");
                    hsvReturn[0]=register("lr")&~1L; hsvInput[0]=register("r0"); hsvCalls[0]++;
                    if(!((hsvReturn[0]>=0x08014F58L && hsvReturn[0]<0x08015054L) ||
                         (hsvReturn[0]>=0x0801509CL && hsvReturn[0]<0x0801513EL)))
                        throw new Exception("HSV caller outside mode29");
                    for(int reg=4;reg<12;reg++) hsvSaved[reg-4]=register("r"+reg);
                    hsvSaved[8]=register("sp");
                    // Observation only: execute original HSV instructions, no argument/result/PC replacement.
                }
                if(realHsv && pc==hsvReturn[0]) {
                    long rgb=register("r0");
                    if((rgb&0xFF000000L)!=0 || register("sp")!=hsvSaved[8]) throw new Exception("HSV ABI result/frame mismatch");
                    for(int reg=4;reg<12;reg++) if(register("r"+reg)!=hsvSaved[reg-4]) throw new Exception("HSV saved register changed");
                    JsonArray event=new JsonArray(); event.add(2);
                    for(int shift:new int[]{0,8,16}) event.add((hsvInput[0]>>shift)&255);
                    for(int shift:new int[]{0,8,16}) event.add((rgb>>shift)&255);
                    trace.add(event); hsvReturn[0]=-1;
                }
                if(pc==0x08012FC8L || pc==0x08014A78L || (!realHsv && pc==0x080147C0L)) {
                    JsonArray event=new JsonArray();
                    if(pc==0x080147C0L) {
                        int packed=(int)register("r0"),h=packed&255,s=(packed>>8)&255,v=(packed>>16)&255;
                        int r=(h+v)&255,g=s^v,b=h^s;
                        for(int n:new int[]{2,h,s,v,r,g,b}) event.add(n);
                        register("r0",r|(g<<8)|(b<<16)); // Controlled HSV boundary; not original conversion.
                    } else if(pc==0x08012FC8L) {
                        event.add(0); for(int reg=0;reg<3;reg++) event.add(register("r"+reg)&255);
                    } else {
                        event.add(1); event.add(register("r0"));
                        for(int reg=1;reg<4;reg++) event.add(register("r"+reg)&255);
                    }
                    trace.add(event); thread.overrideCounter(toAddr(register("lr")&~1L)); return true;
                }
                if(pc==0x08011890L) copies[0]++;
                if(!((pc>=0x08014AA4L && pc<0x08014AE8L) || (pc>=0x08014B44L && pc<0x08014B50L) ||
                     (pc>=0x08014F58L && pc<0x08015054L) || (pc>=0x0801509CL && pc<0x0801513EL) ||
                     (pc>=0x08014A7CL && pc<0x08014AA4L) || (pc>=0x08014900L && pc<0x0801491EL) ||
                     (pc>=0x08014924L && pc<0x08014934L) || (pc>=0x08011890L && pc<0x08011ABCL) ||
                     (realHsv && pc>=0x080147C0L && pc<0x08014868L)))
                    throw new Exception("Mode29 frame escaped selected dispatch/effect/RNG/memcpy slice: "+Long.toHexString(pc));
                return false;
            },29);
            if(hsvReturn[0]!=-1) throw new Exception("HSV call did not return");
            for(long address:new long[]{state-4,state+216,wait-4,wait+4})
                if(getWord(address)!=0xA5A5A5A5L) throw new Exception("Mode29 frame guard changed");
            byte[] afterGlobals=get(0x20000EE4L,12);
            for(int index:new int[]{0,1,10,11}) if(afterGlobals[index]!=(byte)0xA5) throw new Exception("Mode29 globals guard changed");
            if(!java.util.Arrays.equals(config,get(0x20001CE0L,8)) || getWord(timer)!=times[step] ||
               !java.util.Arrays.equals(pixels,get(COLORS,216))) throw new Exception("Mode29 modified input or uncaptured pixel output");
            JsonObject row=new JsonObject(); row.addProperty("iter",iters[step]); row.addProperty("flags",flags[step]);
            row.addProperty("init",init); row.addProperty("now",times[step]); row.add("trace",trace);
            row.addProperty("rendering",(get(0x20000EEDL,1)[0]&255)==1);
            row.addProperty("params_after_hex",hex.formatHex(get(0x20000EE8L,3)));
            row.addProperty("seed_after",(get(0x20000EE6L,1)[0]&255)|((get(0x20000EE7L,1)[0]&255)<<8));
            row.addProperty("next_wait",getWord(wait)); row.addProperty("original_memcpy_calls",copies[0]);
            if(realHsv) row.addProperty("original_hsv_calls",hsvCalls[0]);
            row.addProperty("led_state_rgb_hex",hex.formatHex(get(state,216))); steps.add(row);
        }
        sequence.add("steps",steps); sequences.add(sequence);
    }

    private void rgbMode15Case(JsonArray cases,int speed,long now,int hsv,int flags,int iter) throws Exception {
        cases.add(rgbMode15Step(speed,now,hsv,flags,iter,false));
    }

    private JsonObject rgbMode15Step(int speed,long now,int hsv,int flags,int iter,boolean staging) throws Exception {
        boolean init=iter==0;
        byte[] config={(byte)0x3D,(byte)hsv,(byte)(hsv>>8),(byte)(hsv>>16),(byte)speed,(byte)flags,(byte)0xA5,(byte)0xA5};
        put(0x20001CE0L,config); putWord(0x200018E0L,now);
        byte[] globals=new byte[12]; java.util.Arrays.fill(globals,(byte)0xA5); put(0x20000EE4L,globals);
        put(0x20000EE8L,new byte[]{(byte)iter,(byte)flags,0,(byte)(init?0:15),1,1});
        byte[] guard=new byte[224]; java.util.Arrays.fill(guard,(byte)0xA5);
        put(0x20001B51L,guard); if(!staging) put(COLORS,guard); put(0x2000217CL,guard);
        put(0x2000FE00L,new byte[576]);
        JsonArray trace=new JsonArray(); final int[] phase={-1}; final long[] pending={-1,0};
        executeHooked(0x08014AA4L,0x08010000L,pc -> {
            if(pc==0x0801BE60L) phase[0]=(int)register("r5");
            if(pc==0x080147C0L) {
                if(pending[0]!=-1 || (register("lr")&~1L)!=0x0801BEBCL) throw new Exception("Unexpected mode15 HSV caller");
                pending[0]=register("lr")&~1L; pending[1]=register("r0");
            }
            if(pc==pending[0]) {
                JsonArray event=new JsonArray(); event.add(2);
                for(int shift:new int[]{0,8,16}) event.add((pending[1]>>shift)&255);
                for(int shift:new int[]{0,8,16}) event.add((register("r0")>>shift)&255);
                trace.add(event); pending[0]=-1; // Observe actual HSV return without changing it.
            }
            if(pc==0x08014A78L) {
                JsonArray event=new JsonArray(); event.add(1); event.add(register("r0"));
                for(int reg=1;reg<4;reg++) event.add(register("r"+reg)&255);
                trace.add(event);
                if(!staging) { thread.overrideCounter(toAddr(register("lr")&~1L)); return true; }
                // Staging mode executes the original setter's RAM stores.
            }
            if(!((pc>=0x08014AA4L && pc<0x08014AE8L) || (pc>=0x08014B44L && pc<0x08014B48L) ||
                 (pc>=0x08014D1AL && pc<0x08014D52L) ||
                 (pc>=0x08014FA4L && pc<0x08014FC6L) || (pc>=0x0801BE34L && pc<0x0801BED0L) ||
                 (pc>=0x08012B48L && pc<0x08012B98L) || (pc>=0x08014A7CL && pc<0x08014AA4L) ||
                 (pc>=0x080147C0L && pc<0x08014868L) ||
                 (staging && ((pc>=0x08014A78L && pc<0x08014A7CL) || (pc>=0x080132ECL && pc<0x08013300L)))))
                throw new Exception("Mode15 escaped selected dispatch/runner/math/HSV: "+Long.toHexString(pc));
            return false;
        },15);
        if(pending[0]!=-1 || phase[0]<0 || phase[0]>255) throw new Exception("Incomplete mode15 runner/HSV observation");
        for(long address:new long[]{0x20001B51L,0x2000217CL})
            if(!java.util.Arrays.equals(guard,get(address,224))) throw new Exception("Mode15 modified private state guard");
        if(!staging && !java.util.Arrays.equals(guard,get(COLORS,224))) throw new Exception("Mode15 modified uncaptured staging");
        if(staging && (getWord(COLORS-4)!=0xA5A5A5A5L || getWord(COLORS+216)!=0xA5A5A5A5L)) throw new Exception("Mode15 staging guard changed");
        for(int index:new int[]{0,1,2,3,10,11}) if(get(0x20000EE4L+index,1)[0]!=(byte)0xA5) throw new Exception("Mode15 modified RNG/global guard");
        if(!java.util.Arrays.equals(config,get(0x20001CE0L,8)) || getWord(0x200018E0L)!=now) throw new Exception("Mode15 modified input");
        JsonObject row=new JsonObject(); row.addProperty("speed",speed); row.addProperty("now",now); row.addProperty("hsv",hsv);
        row.addProperty("flags",flags); row.addProperty("iter",iter); row.addProperty("init",init); row.addProperty("phase",phase[0]);
        row.addProperty("rendering",(get(0x20000EEDL,1)[0]&255)==1); row.add("trace",trace);
        row.addProperty("params_after_hex",hex.formatHex(get(0x20000EE8L,3))); return row;
    }

    private void rgbMode15Staging(JsonArray sequences,int hsv,long now,int flags,int caps,int keylight,int underglow) throws Exception {
        byte[] input=ramp(),guard=new byte[224]; java.util.Arrays.fill(guard,(byte)0xA5);
        put(COLORS-4,guard); put(COLORS,input);
        byte[] groupGuard=new byte[12]; java.util.Arrays.fill(groupGuard,(byte)0xA5); put(FLAGS-4,groupGuard);
        long group=0xA5B60000L | keylight | (underglow<<8); putWord(FLAGS,group);
        JsonObject sequence=new JsonObject(); sequence.addProperty("speed",128); sequence.addProperty("hsv",hsv);
        sequence.addProperty("now",now); sequence.addProperty("flags",flags); sequence.addProperty("caps",caps);
        sequence.addProperty("group_word",group); sequence.addProperty("initial_grb_hex",hex.formatHex(input));
        JsonArray steps=new JsonArray();
        for(int iter=0;iter<5;iter++) {
            JsonObject row=rgbMode15Step(128,now,hsv,flags,iter,true);
            row.addProperty("effect_grb_hex",hex.formatHex(get(COLORS,216)));
            final int[] white={0};
            executeHooked(0x080156CEL,0x0801571AL,pc -> {
                if(pc==0x0801AE80L) {
                    register("r0",caps); thread.overrideCounter(toAddr(register("lr")&~1L)); return true;
                }
                if(pc==0x08014A78L && register("r0")==22 && register("r1")==255 && register("r2")==255 && register("r3")==255) white[0]++;
                if(!((pc>=0x080156CEL && pc<0x08015756L) || (pc>=0x08014A7CL && pc<0x08014AA4L) ||
                     (pc>=0x08014A78L && pc<0x08014A7CL) || (pc>=0x080132ECL && pc<0x08013300L)))
                    throw new Exception("Mode15 post-effect escaped indicator/filter/RAM setter slice");
                return false;
            },0,0,0,0,15,0,0x20000EEDL);
            if(getWord(FLAGS)!=group || getWord(FLAGS-4)!=0xA5A5A5A5L || getWord(FLAGS+4)!=0xA5A5A5A5L ||
               getWord(COLORS-4)!=0xA5A5A5A5L || getWord(COLORS+216)!=0xA5A5A5A5L)
                throw new Exception("Mode15 post-effect group/staging guard changed");
            row.addProperty("post_grb_hex",hex.formatHex(get(COLORS,216))); row.addProperty("caps_white_calls",white[0]); steps.add(row);
        }
        sequence.add("steps",steps); sequences.add(sequence);
    }

    private void rgbHsvCase(JsonArray cases,int h,int s,int v,int padding) throws Exception {
        long input=(h|(s<<8)|(v<<16))|((long)padding<<24);
        byte[] stack=new byte[584]; java.util.Arrays.fill(stack,(byte)0xA5); put(0x2000FDFCL,stack);
        executeHooked(0x080147C0L,0x08010000L,pc -> {
            if(pc<0x080147C0L || pc>=0x08014868L) throw new Exception("HSV escaped pure conversion body");
            return false;
        },input);
        long result=register("r0");
        if((result&0xFF000000L)!=0 || register("sp")!=0x20010000L ||
           getWord(0x2000FDFCL)!=0xA5A5A5A5L || getWord(0x20010040L)!=0xA5A5A5A5L)
            throw new Exception("HSV result/frame guard mismatch");
        for(int reg=4;reg<12;reg++) if(register("r"+reg)!=0) throw new Exception("HSV clobbered saved register");
        JsonArray row=new JsonArray(); row.add(input); row.add(result); cases.add(row);
    }

    public void run() throws Exception {
        if (!SHA.equals(currentProgram.getExecutableSHA256()) ||
            !"ARM:LE:32:Cortex".equals(currentProgram.getLanguageID().toString()))
            throw new Exception("Wrong target: original Vial payload/Cortex required");
        String[] args = getScriptArgs();
        boolean rgbEventsOnly=args.length>0 && args[0].equals("--rgb-events");
        boolean mode29IntervalOnly=args.length>0 && args[0].equals("--rgb-mode29-interval");
        boolean mode29FramesOnly=args.length>0 && args[0].equals("--rgb-mode29-frames");
        boolean realHsvFramesOnly=args.length>0 && args[0].equals("--rgb-mode29-frames-real-hsv");
        boolean mode15StagingOnly=args.length>0 && args[0].equals("--rgb-mode15-staging");
        boolean mode15Only=args.length>0 && args[0].equals("--rgb-mode15");
        boolean rgbHsvOnly=args.length>0 && args[0].equals("--rgb-hsv");
        if(rgbEventsOnly || mode29IntervalOnly || mode29FramesOnly || realHsvFramesOnly || mode15Only || mode15StagingOnly || rgbHsvOnly) args=java.util.Arrays.copyOfRange(args,1,args.length);
        if (args.length < 1 || args.length > 2 || (args.length == 2 && !args[1].equals("--check")))
            throw new Exception("Expected OUTPUT.json [--check]");
        emu = new PcodeEmulator(currentProgram.getLanguage());
        EmulatorUtilities.loadProgram(emu, currentProgram);
        thread = emu.newThread();
        JsonObject result = new JsonObject();
        result.addProperty("payload_sha256", SHA);
        result.addProperty("emulator", "Ghidra 12.1 P-code ARM:LE:32:Cortex");
        result.addProperty("scope", "Original instructions, RAM-only routines/case slices; not full firmware or hardware emulation");
        if(mode15StagingOnly) {
            JsonArray sequences=new JsonArray();
            for(int hsv:new int[]{0xFFFF00,0x8080FF}) for(long now:new long[]{0,256,0xFFFFFFFFL})
                for(int flags:new int[]{255,4,2,0}) for(int caps:new int[]{0,2})
                    for(int[] group:new int[][]{{0,0},{0,1},{1,0},{1,1},{2,255},{255,2}})
                        rgbMode15Staging(sequences,hsv,now,flags,caps,group[0],group[1]);
            result.add("rgb_mode15_staging",sequences);
            result.addProperty("boundary_policy","288 controlled five-chunk mode15 sequences. Actual original selected dispatch/runner/math/HSV and RAM setter14a78/132ec execute, then separately entered156ce..1571a post-effect Caps/filter slice with supplied effect/state register context. Host getter1ae80 alone returns supplied Caps bits. Persistent216-byte virtual GRB staging, input/group/private-state guards; no RGB setter replacement. Not execution of intervening renderer caller/start/sync/flags-change-clear, scan, scheduler/clock, flush/DMA/HAL/device or physical output. No target changes.");
            String json=new GsonBuilder().setPrettyPrinting().disableHtmlEscaping().create().toJson(result)+"\n";
            Path output=Path.of(args[0]);
            if(args.length==2) {
                if(!Files.readString(output).equals(json)) throw new Exception("Mode15 staging oracle mismatch");
            } else Files.writeString(output,json,StandardOpenOption.CREATE_NEW);
            println("ORIGINAL_RGB_MODE15_STAGING_COMPLETE sequences="+sequences.size()+" chunks=1440"); return;
        }
        if(mode15Only) {
            JsonArray cases=new JsonArray();
            for(int speed:new int[]{0,128,255}) for(long now:new long[]{0,1,255,256,65535,65536,0xFFFFFFFFL})
                for(int hsv:new int[]{0xFFFF00,0x8080FF,0x000080}) for(int flags:new int[]{255,4,2,0})
                    for(int iter=0;iter<5;iter++) rgbMode15Case(cases,speed,now,hsv,flags,iter);
            result.add("rgb_mode15",cases);
            result.addProperty("boundary_policy","Selected original mode15 dispatch14aa4/14d4e, runner1be34, math12b48, actual HSV147c0/CIE and limits execute. HSV entry/return and phase observed only; RGB setter14a78 captured and returned from. Guarded inputs, mode29 private state/wait, RNG/global bytes and physical staging; defined synthetic stack. Caller supplies iter/init/flags/time/config; not full renderer/indicator/group/flush/clock/HAL/device or physical colors. No target/catalog/default changes.");
            String json=new GsonBuilder().setPrettyPrinting().disableHtmlEscaping().create().toJson(result)+"\n";
            Path output=Path.of(args[0]);
            if(args.length==2) {
                if(!Files.readString(output).equals(json)) throw new Exception("Mode15 oracle mismatch");
            } else Files.writeString(output,json,StandardOpenOption.CREATE_NEW);
            println("ORIGINAL_RGB_MODE15_COMPLETE cases="+cases.size()); return;
        }
        if(rgbHsvOnly) {
            JsonArray gray=new JsonArray(),grid=new JsonArray();
            for(int v=0;v<256;v++) rgbHsvCase(gray,0,0,v,(v*73)&255);
            for(int h=0;h<256;h++) for(int s:new int[]{0,1,127,128,254,255})
                for(int v:new int[]{0,1,127,128,254,255}) rgbHsvCase(grid,h,s,v,0xA5);
            result.add("grayscale",gray); result.add("hsv_grid",grid);
            result.addProperty("cie_table_address","0x0801DB1A");
            result.addProperty("cie_table_hex",hex.formatHex(get(0x0801DB1AL,256)));
            result.addProperty("boundary_policy","Only actual original147c0..14868 HSV conversion and immutable CIE table reads; packed input R0 h/s/v plus opaque high byte, RGB result R0 low24. Defined synthetic guarded stack and saved-register checks. No callback replacements, matrix renderer/indicator/flush, clock/HAL/MMIO/device or target changes; sampled HSV grid, not exhaustive16777216 colors.");
            String json=new GsonBuilder().setPrettyPrinting().disableHtmlEscaping().create().toJson(result)+"\n";
            Path output=Path.of(args[0]);
            if(args.length==2) {
                if(!Files.readString(output).equals(json)) throw new Exception("HSV oracle mismatch");
            } else Files.writeString(output,json,StandardOpenOption.CREATE_NEW);
            println("ORIGINAL_RGB_HSV_COMPLETE grayscale="+gray.size()+" grid="+grid.size()+" total=9472"); return;
        }
        if(mode29FramesOnly || realHsvFramesOnly) {
            JsonArray sequences=new JsonArray();
            for(int speed:new int[]{0,128,255}) for(int seed:new int[]{0,65535}) rgbMode29Frames(sequences,speed,seed,realHsvFramesOnly);
            result.add("rgb_mode29_frames",sequences);
            if(realHsvFramesOnly) {
                result.addProperty("actual_hsv_conversion_executed",true);
                result.addProperty("cie_table_hex",hex.formatHex(get(0x0801DB1AL,256)));
                result.addProperty("boundary_policy","Six persistent16-call sequences of selected original14aa4 mode29 dispatch/effect/common-tail with supplied flags/iter/init/clock. Actual original RNG14900/14924, HSV147c0..14868 with CIE table, limits and memcpy execute. HSV entry/return observation only, no HSV argument/result/PC replacement; saved registers/SP checked. Only RGB APIs12fc8/14a78 captured and returned from. Guarded private state/wait/globals, defined synthetic stack. Not full renderer/scan/indicator/flush, scheduler/clock/HAL/IO/device execution or physical colors; no target configuration changes.");
            } else result.addProperty("boundary_policy","Six persistent16-call sequences of selected original14aa4 mode29 dispatch/effect/common-tail with supplied flags/iter/init/clock, original RNG14900/14924, limits and memcpy. HSV147c0 replaced with deterministic RGB=(h+v,s^v,h^s), RGB APIs12fc8/14a78 captured and returned from. Guarded private state/wait/globals, defined synthetic stack. Not real HSV/colors, full renderer/scan/indicator/flush, scheduler/clock/HAL/IO/device execution; no target configuration changes.");
            String json=new GsonBuilder().setPrettyPrinting().disableHtmlEscaping().create().toJson(result)+"\n";
            Path output=Path.of(args[0]);
            if(args.length==2) {
                if(!Files.readString(output).equals(json)) throw new Exception("Mode29 frame oracle mismatch");
            } else Files.writeString(output,json,StandardOpenOption.CREATE_NEW);
            println((realHsvFramesOnly ? "ORIGINAL_RGB_MODE29_FRAMES_REAL_HSV_COMPLETE" : "ORIGINAL_RGB_MODE29_FRAMES_COMPLETE")+" sequences="+sequences.size()+" calls=96"); return;
        }
        if(mode29IntervalOnly) {
            JsonArray cases=new JsonArray();
            for(int speed=0;speed<256;speed++) for(long now:new long[]{0,1,0xFFFFFF00L,0xFFFFFFFFL})
                rgbMode29Interval(cases,speed,now);
            result.add("rgb_mode29_interval",cases);
            result.addProperty("boundary_policy","Only original150d8..150fa arithmetic/store instructions execute; caller-supplied speed/config pointer, current uint32 timer and guarded wait RAM. No renderer dispatch, wait gate, init, RNG, HSV, LED state/IO, actual clock, IRQ or device execution.");
            String json=new GsonBuilder().setPrettyPrinting().disableHtmlEscaping().create().toJson(result)+"\n";
            Path output=Path.of(args[0]);
            if(args.length==2) {
                if(!Files.readString(output).equals(json)) throw new Exception("Mode29 interval oracle mismatch");
            } else Files.writeString(output,json,StandardOpenOption.CREATE_NEW);
            println("ORIGINAL_RGB_MODE29_INTERVAL_COMPLETE cases="+cases.size()); return;
        }
        if(rgbEventsOnly) {
            JsonArray cases=new JsonArray();
            for(int row=0;row<4;row++) for(int col=0;col<12;col++)
                for(boolean pressed:new boolean[]{false,true}) for(int count:new int[]{0,7,8})
                    rgbKeyEvent(cases,row,col,pressed,count);
            result.add("rgb_key_events",cases);
            result.addProperty("boundary_policy","Original 18efa..18f82/19212..19218/19294..192ca, stop before heatmap gate. Caller-supplied valid matrix-cell pointer and changed-edge pressed mask; guarded 41-byte buffer with counts0/7/8. Original Thumb memcpy11890..11abc executes; no replacement. No action/HID/matrix scan, heatmap, aging, renderer, timer, IRQ, MMIO or device execution.");
            String json=new GsonBuilder().setPrettyPrinting().disableHtmlEscaping().create().toJson(result)+"\n";
            Path output=Path.of(args[0]);
            if(args.length==2) {
                if(!Files.readString(output).equals(json)) throw new Exception("RGB event oracle mismatch");
            } else Files.writeString(output,json,StandardOpenOption.CREATE_NEW);
            println("ORIGINAL_RGB_EVENTS_COMPLETE cases="+cases.size());
            return;
        }
        JsonArray encodings = new JsonArray();
        encode(encodings, "black", new byte[216]);
        byte[] white = new byte[216];
        java.util.Arrays.fill(white, (byte)255);
        encode(encodings, "white", white);
        encode(encodings, "ramp", ramp());
        for (int led : new int[] {0, 71})
            for (int bit = 0; bit < 24; ++bit) {
                byte[] input = new byte[216];
                input[led * 3 + bit / 8] = (byte)(1 << (bit % 8));
                encode(encodings, "led" + led + "_bit" + bit, input);
            }
        result.add("encodings", encodings);
        JsonArray controls = new JsonArray();
        long[] entries = {0x08015FE0L, 0x08015FF2L, 0x08015FFEL, 0x0801600CL, 0x0801601EL, 0x0801602CL};
        for (int key = 0; key < entries.length; ++key)
            for (int pressed = 0; pressed < 2; ++pressed)
                for (byte[] initial : new byte[][] {{0,0}, {1,1}, {2,(byte)128}, {(byte)255,(byte)254}}) {
                    put(FLAGS, initial);
                    execute(entries[key], 0x08015C6EL, 0,0,0,0,0,pressed);
                    JsonObject row = new JsonObject();
                    row.addProperty("keycode", 0x7E10 + key);
                    row.addProperty("pressed", pressed != 0);
                    row.add("before", unsigned(initial));
                    row.add("after", unsigned(get(FLAGS, 2)));
                    controls.add(row);
                }
        result.add("rgb_controls", controls);
        JsonArray shifts = new JsonArray();
        for (int key : new int[] {0xE1, 0xE5, 0xE0, 0x4})
            for (int pressed = 0; pressed < 2; ++pressed) {
                put(SHIFT, new byte[] {(byte)128});
                execute(0x08015AB6L, 0x08015AC4L, 0,0,0,0,key,pressed);
                JsonObject row = new JsonObject();
                row.addProperty("keycode", key);
                row.addProperty("pressed", pressed != 0);
                row.addProperty("before", 128);
                row.addProperty("after", get(SHIFT, 1)[0] & 255);
                shifts.add(row);
            }
        result.add("shift_edges", shifts);
        JsonArray bsdl = new JsonArray();
        for (int selector : new int[] {0,1,128,255})
            for (int pressed = 0; pressed < 2; ++pressed) {
                put(SHIFT, new byte[] {(byte)selector});
                // Stop BEFORE register/unregister; never execute HID routines.
                execute(0x08015EBAL, pressed != 0 ? 0x08013F88L : 0x080140AAL, 0,0,0,0,0,pressed);
                JsonObject row = new JsonObject();
                row.addProperty("selector", selector);
                row.addProperty("pressed", pressed != 0);
                row.addProperty("keycode", register("r0"));
                bsdl.add(row);
            }
        result.add("backspace_delete", bsdl);
        JsonArray filters = new JsonArray();
        for (int[] range : new int[][] {{0,72},{0,42},{42,72},{12,61},{72,72}})
            for (byte[] enabled : new byte[][] {{0,0},{1,0},{0,1},{1,1},{2,(byte)128}}) {
                put(COLORS, ramp());
                put(FLAGS, enabled);
                // Start after the chunk-bound lookup, stop before the epilogue.
                execute(0x080156F8L, 0x0801571AL, range[0] | (range[1] << 8),0,0,0,0,0,0,FLAGS);
                JsonObject row = new JsonObject();
                row.addProperty("begin", range[0]);
                row.addProperty("end", range[1]);
                row.add("enabled", unsigned(enabled));
                row.addProperty("input_grb_hex", hex.formatHex(ramp()));
                row.addProperty("expected_grb_sha256", digest(get(COLORS, 216)));
                filters.add(row);
            }
        result.add("filters", filters);
        JsonArray cadet = new JsonArray();
        long[] cadetEntries = {0x08015EDCL,0x08015EF0L,0x08015EFEL,0x08015F0CL,0x08015F1AL,
            0x08015F28L,0x08015F36L,0x08015F44L,0x08015F52L,0x08015F60L,0x08015F6EL,
            0x08015FA8L,0x08015FB6L,0x08015FC4L};
        for (int index = 0; index < cadetEntries.length; ++index) {
            long entry = cadetEntries[index];
            int key = 0x7E01 + index;
            // Execute the actual vendor argument setup, do not copy recovered C parameters.
            execute(entry, 0x0801D4C8L);
            if (register("r1") != key) throw new Exception("Wrong cadet case boundary");
            int hold = (int)register("r2");
            cadetScenarios(cadet, entry, key, hold, false);
        }
        result.add("cadet", cadet);
        result.addProperty("cadet_boundary_policy", "Clock return controlled at 0x0801b374; ordered register_mods/unregister_mods/tap_code intents captured at 0x08013f74/0x08014098/0x08014188. Original global-term lookup executes. No HID reports/delays or automatic dispatcher interruption routing.");
        JsonArray resets = new JsonArray();
        for (int last : new int[] {0,0xE0,0xE5,255}) {
            put(0x20001CEDL, new byte[] {(byte)last});
            putTime(65530);
            execute(0x08017346L, 0x08017350L);
            JsonObject row = new JsonObject();
            row.addProperty("before_last_modifier", last);
            row.addProperty("before_pressed_at", 65530);
            row.addProperty("after_last_modifier", get(0x20001CEDL, 1)[0] & 255);
            row.addProperty("after_pressed_at", getTime());
            resets.add(row);
        }
        result.add("cadet_resets", resets);
        JsonArray builtin = new JsonArray();
        for (int key = 0x7C18; key <= 0x7C1E; ++key) {
            execute(0x08016646L, 0x0801D4C8L, cadetArguments(key, false, true));
            if (register("r1") != key) throw new Exception("Wrong built-in cadet table target");
            cadetScenarios(builtin, 0x08016646L, key, (int)register("r2"), true);
        }
        result.add("builtin_cadet", builtin);
        JsonArray defaults = new JsonArray();
        for (int key : new int[] {0x4,0xE1,0x2C,0x7000,0x7C16,0x7C17,0x7C1F,0xFFFF})
            for (boolean pressed : new boolean[] {false,true}) {
                put(0x20001CEDL, new byte[] {(byte)0xE1});
                putTime(65530);
                long stop = pressed ? 0x08017350L : 0x080174D4L;
                execute(0x08016646L, stop, cadetArguments(key, pressed, true));
                JsonObject row = new JsonObject();
                row.addProperty("keycode", key);
                row.addProperty("pressed", pressed);
                row.addProperty("before_last_modifier", 0xE1);
                row.addProperty("before_pressed_at", 65530);
                row.addProperty("after_last_modifier", get(0x20001CEDL, 1)[0] & 255);
                row.addProperty("after_pressed_at", getTime());
                defaults.add(row);
            }
        result.add("cadet_core_defaults", defaults);
        JsonArray bypasses = new JsonArray();
        // Explicit safe allowlist. NEVER execute 0x7E0F's erase/reset path.
        for (int key : new int[] {0x7E00,0x7E10,0x7E11,0x7E12,0x7E13,0x7E14,0x7E15})
            for (boolean pressed : new boolean[] {false,true}) {
                put(0x20001CEDL, new byte[] {(byte)0xE1});
                putTime(65530);
                put(SHIFT, new byte[] {1});
                put(FLAGS, new byte[] {1,1});
                JsonArray effects = new JsonArray();
                executeHooked(0x08015E96L, 0x08015C6EL, pc -> {
                    if (pc == 0x08016646L || pc == 0x08017346L || pc == 0x080143E4L || pc == 0x08013ECCL)
                        throw new Exception("Unexpected core/reset/destructive path from vendor allowlist");
                    if (pc != 0x08013F88L && pc != 0x080140AAL) return false;
                    JsonObject effect = new JsonObject();
                    effect.addProperty("kind", pc == 0x08013F88L ? "register_code" : "unregister_code");
                    effect.addProperty("argument", register("r0") & 255);
                    effects.add(effect);
                    thread.overrideCounter(toAddr(register("lr") & ~1L));
                    return true;
                }, cadetArguments(key, pressed, false));
                JsonObject row = new JsonObject();
                row.addProperty("keycode", key);
                row.addProperty("pressed", pressed);
                row.addProperty("before_last_modifier", 0xE1);
                row.addProperty("before_pressed_at", 65530);
                row.addProperty("after_last_modifier", get(0x20001CEDL, 1)[0] & 255);
                row.addProperty("after_pressed_at", getTime());
                row.add("after_flags", unsigned(get(FLAGS, 2)));
                row.add("effects", effects);
                bypasses.add(row);
            }
        result.add("cadet_vendor_bypasses", bypasses);
        result.addProperty("cadet_core_scope", "Starts at 0x08016646 ONLY; prior feature/vendor gates are not modeled. Default press stops at 0x08017350 after reset; release stops at 0x080174d4 before later handling. Vendor bypass cases start at 0x08015e96 and must return at 0x08015c6e without visiting core/reset. 0x7e0f is excluded.");
        JsonArray taps = new JsonArray();
        for (int key = 0; key < 256; ++key) tapCase(taps, key, 7, 19);
        for (int delay : new int[] {0,1,2,199,200,42949,42950,65535}) {
            tapCase(taps, 0x28, delay, 65535);
            tapCase(taps, 0x39, 65535, delay);
        }
        result.add("tap_code", taps);
        JsonArray expanded = new JsonArray();
        for (int index = 0; index < cadetEntries.length; ++index)
            expandedCadetCase(expanded, cadetEntries[index], 0x7E01 + index, false);
        for (int key = 0x7C18; key <= 0x7C1E; ++key)
            expandedCadetCase(expanded, 0x08016646L, key, true);
        result.add("cadet_tap_expanded", expanded);
        result.addProperty("tap_boundary_policy", "Real 0x08014188 wrapper, 0x08014148 delay arithmetic and 64-bit division execute; register_code/unregister_code/sleep_ticks boundaries are recorded and returned from. Expanded cadet cases do not stub tap_code itself. USB reports, scheduler and real waiting remain unexecuted.");
        JsonArray settingsResets = new JsonArray();
        for (int fill : new int[] {0,255,165,-1}) {
            byte[] before = new byte[40];
            for (int i = 0; i < before.length; ++i) before[i] = (byte)(fill < 0 ? i * 37 + 11 : fill);
            byte[] guarded = new byte[48];
            java.util.Arrays.fill(guarded, (byte)0x6D);
            System.arraycopy(before, 0, guarded, 4, before.length);
            put(0x200011C4L, guarded);
            // STOP before EEPROM save, keyboard clear or settings callbacks.
            execute(0x080144DCL, 0x08014524L);
            byte[] after = get(0x200011C8L, 40);
            byte[] guards = get(0x200011C4L, 48);
            for (int i : new int[] {0,1,2,3,44,45,46,47})
                if (guards[i] != (byte)0x6D) throw new Exception("QS reset crossed RAM region");
            JsonObject row = new JsonObject();
            row.addProperty("name", fill < 0 ? "ramp" : "fill_" + fill);
            row.addProperty("before_hex", hex.formatHex(before));
            row.addProperty("after_hex", hex.formatHex(after));
            settingsResets.add(row);
        }
        result.add("settings_reset_prefix", settingsResets);
        result.addProperty("settings_reset_boundary_policy", "Original 0x080144dc RAM assignments execute through 0x08014524 exclusive. EEPROM save/reset, keyboard clear and callbacks are NOT executed. Byte 35 is deliberately preserved.");
        JsonArray recordResets = new JsonArray();
        for (int fill : new int[] {0,255,165,-1}) {
            byte[] stack = new byte[64];
            for (int i = 0; i < stack.length; ++i) stack[i] = (byte)(fill < 0 ? i * 37 + 11 : fill);
            put(0x2000FEF0L, stack);
            JsonArray writes = new JsonArray();
            // Execute ONLY template assignments/loops. EEPROM is an intent boundary.
            executeHooked(0x08015880L, 0x08015916L, pc -> {
                if (pc == 0x08015880L) register("sp", 0x2000FF00L);
                if (pc == 0x0801D570L) {
                    long address = register("r0"), source = register("r1"), size = register("r2");
                    if (address < 0x1D1 || address + size > 0x471 || (size != 6 && size != 10) || source != 0x2000FF0CL)
                        throw new Exception("Unexpected record write boundary");
                    JsonObject write = new JsonObject();
                    write.addProperty("address", address);
                    write.addProperty("data_hex", hex.formatHex(get(source, (int)size)));
                    writes.add(write);
                    thread.overrideCounter(toAddr(register("lr") & ~1L));
                    return true;
                }
                if (pc < 0x08015880L || pc >= 0x08015916L)
                    throw new Exception("Record reset escaped bounded slice");
                return false;
            });
            byte[] after = get(0x2000FEF0L, 64);
            for (int i = 0; i < after.length; ++i)
                if ((i < 28 || i >= 38) && stack[i] != after[i])
                    throw new Exception("Record template crossed stack guard");
            if (writes.size() != 80) throw new Exception("Unexpected record write count");
            JsonObject row = new JsonObject();
            row.addProperty("name", fill < 0 ? "ramp" : "fill_" + fill);
            row.add("writes", writes);
            recordResets.add(row);
        }
        result.add("dynamic_record_reset", recordResets);
        result.addProperty("dynamic_record_boundary_policy", "Only 0x08015880..0x08015916 assignments/loops execute. 0x0801d570 writes are recorded and returned from, never persisted. Earlier keymap/QS reset, unlock changes, callbacks and later relock are excluded; stack guards checked.");
        JsonArray prefixValidity = new JsonArray();
        byte[] stamp = new byte[] {0x4B,(byte)0xF4,0x29};
        prefixValidityCase(prefixValidity, stamp);
        for (int index = 0; index < 3; ++index) {
            for (int value = 0; value < 256; ++value) {
                if (value == (stamp[index] & 255)) continue;
                byte[] changed = stamp.clone();
                changed[index] = (byte)value;
                prefixValidityCase(prefixValidity, changed);
            }
        }
        result.add("prefix_validity", prefixValidity);
        JsonArray prefixGates = new JsonArray();
        for (int core : new int[] {0xFEE3,0,0xFFFF,0xE3FE}) {
            for (int mask = 0; mask < 8; ++mask) {
                for (int fill : new int[] {0,255}) {
                    byte[] prefix = new byte[41];
                    java.util.Arrays.fill(prefix, (byte)fill);
                    prefix[0] = (byte)core;
                    prefix[1] = (byte)(core >> 8);
                    for (int i = 0; i < 3; ++i) prefix[37 + i] = (byte)(stamp[i] ^ ((mask & (1 << i)) != 0 ? 255 : 0));
                    JsonObject row = new JsonObject();
                    row.addProperty("prefix_hex", hex.formatHex(prefix));
                    JsonArray earlyReads = new JsonArray(), earlyResets = new JsonArray();
                    executeHooked(0x08018B5CL, 0x08018B66L, pc -> prefixBoundary(prefix, earlyReads, earlyResets, pc));
                    row.add("early_reads", earlyReads);
                    row.add("early_reset_entries", earlyResets);
                    JsonArray lateReads = new JsonArray(), lateResets = new JsonArray();
                    executeHooked(0x08018BBCL, 0x08018BCEL, pc -> prefixBoundary(prefix, lateReads, lateResets, pc));
                    row.add("later_reads", lateReads);
                    row.add("later_reset_entries", lateResets);
                    JsonArray layoutReads = new JsonArray(), layoutResets = new JsonArray();
                    executeHooked(0x0801AE74L, 0x08010000L, pc -> prefixBoundary(prefix, layoutReads, layoutResets, pc));
                    if (layoutResets.size() != 0) throw new Exception("Layout read called reset");
                    row.addProperty("layout_value", register("r0"));
                    row.add("layout_reads", layoutReads);
                    prefixGates.add(row);
                }
            }
        }
        result.add("prefix_gates", prefixGates);
        result.addProperty("prefix_boundary_policy", "Original validity checker and two independent startup slices execute. Read-byte/read-word return controlled input; reset entries 0x0801ae2e/0x080143e4 are recorded and returned from BEFORE executing their bodies. No EEPROM/flash/reset operations. Slices do not simulate full boot or the effects of a preceding reset.");
        JsonArray snapshots = new JsonArray();
        for (String pattern : new String[] {"zero","ff","ramp","lcg"})
            for (String mode : new String[] {"match","bit0","bit63"}) snapshotCase(snapshots, pattern, mode, -1);
        for (int word : new int[] {0,512,1023}) snapshotCase(snapshots, "ramp", "match", word);
        snapshotCase(snapshots, "zero", "erased", -1);
        result.add("consolidated_snapshot", snapshots);
        result.addProperty("snapshot_boundary_policy", "Original 0x08018758..0x08018816 load/hash/compare plus RAM-only clear execute. Backing reads return controlled translated bytes; memset is bounded to cache RAM. Data-failure path stops before outer clear at 0x08018896. No checksum-read failures, log playback, physical translation, flash init/erase/program/lock or full startup. Budget 200000 instructions per bounded 4096-byte case.");
        JsonArray journals = new JsonArray();
        for (int address : new int[] {0,1,40,41,4091,4092,4095,4096,4097,0x7FFFF}) {
            for (int length = 0; length <= 5; ++length) {
                journalCase(journals, journalEntry(address, length, 0), 0x1008, true);
                if (length > 1 && address + length <= 4096)
                    journalCase(journals, journalEntry(address, length, 0), 0x1008, false);
            }
        }
        for (int type = 1; type <= 3; ++type)
            for (int length = 0; length <= 5; ++length)
                journalCase(journals, journalEntry(41, length, type), 0x1008, true);
        for (int position : new int[] {0x1008,0x1FFC}) journalCase(journals, new byte[8], position, true);
        for (int length = 0; length <= 5; ++length) journalCase(journals, journalEntry(41, length, 0), 0x1FF8, true);
        for (int length = 0; length <= 1; ++length) journalCase(journals, journalEntry(41, length, 0), 0x1FFC, true);
        result.add("journal_entry", journals);
        result.addProperty("journal_boundary_policy", "One supplied first word, original 0x08018824 decode/copy, stop at 0x0801887e or before 0x08018886 global cursor commit. First-read status, whole-loop playback/consolidation and flash operations NOT executed. Backing second read controlled; memcpy bounded to cache. Lengths 6/7 and second reads beyond backing budget NOT emulated. Initial cache uses ramp pattern.");
        JsonArray programs = new JsonArray(), reads = new JsonArray(), geometries = new JsonArray();
        for (long word : new long[] {0,0xFFFFFFFFL,1,0x80000000L,0x01234567L,0xA5A55A5AL}) {
            for (int flag : new int[] {0,1,2,255}) {
                for (long status : new long[] {0,1,2,0xFFFFFFFFL})
                    for (long offset : new long[] {0,8188}) backingProgram(programs, offset, word, flag, status);
                for (int stale : new int[] {0,255})
                    for (int observed : new int[] {0,1,255}) backingRead(reads, word, flag, stale, observed);
            }
        }
        for (long offset : new long[] {1,8192,0xFFFFFFFCL}) backingProgram(programs, offset, 0x12345678L, 1, 0);
        for (int index = 0; index < 4; ++index) {
            backingGeometry(geometries, index, false); backingGeometry(geometries, index, true);
        }
        result.add("backing_program", programs); result.add("backing_read", reads); result.add("backing_geometry", geometries);
        result.addProperty("backing_boundary_policy", "RAM-only driver object/vtable/descriptor; program callback captured before first instruction; read physical base redirected to synthetic RAM; final error byte injected after stale clear, NOT a physical fault. Geometry callbacks return original immutable ROM descriptors. No flash init/lock/unlock/erase/program or real bus-fault handling executed.");
        JsonArray gpioStartup = new JsonArray();
        for (int i = 0; i < 6; ++i) gpioStartup(gpioStartup, i);
        result.add("gpio_startup_writes", gpioStartup);
        result.addProperty("gpio_startup_boundary_policy", "Original 0x0801aa7e leaf writer, GPIO destination redirected to guarded RAM, immutable original table at 0x0801ea14. No physical MMIO, whole early-init or clock procedure executed.");
        JsonArray rgbGroups = new JsonArray();
        for (long initial : new long[] {0,0xFFFFFFFFL,0xDEADBEEFL}) rgbGroupLifecycle(rgbGroups, true, initial, 0);
        for (long stored : new long[] {0,1,0x100,0x101,0x102,0xFF02,0xA5B6FF00L,0xDEADBEEFL,0xFFFFFFFFL,0x12345678L})
            rgbGroupLifecycle(rgbGroups, false, 0xA5A5A5A5L, stored);
        result.add("rgb_group_lifecycle", rgbGroups);
        JsonArray rgbLimits = new JsonArray();
        for (int iter=0;iter<256;iter++) {
            execute(0x08014A7CL,0x08010000L,iter);
            JsonObject row=new JsonObject(); row.addProperty("iter",iter); row.addProperty("packed_limits",register("r0")); rgbLimits.add(row);
        }
        result.add("rgb_limits",rgbLimits);
        JsonArray rgbComposed = new JsonArray();
        for (int iter : new int[] {0,1,4}) for (int caps : new int[] {0,2})
            for (int keylight : new int[] {0,1}) for (int underglow : new int[] {0,1})
                rgbComposedChunk(rgbComposed,iter,caps,keylight,underglow);
        result.add("rgb_composed_chunks",rgbComposed);
        result.addProperty("rgb_chunk_boundary_policy","Original limits helper all 256 uint8 inputs; only iter0..4 are normal valid rendering spans. Composed 0x080156ce..0x0801571a active-effect slices at iter0/1/4, state RENDERING except FLUSHING on iter4; host Caps and RGB setters controlled, original limits/filter instructions execute. No full effect engine, scheduler, HID or physical LEDs executed.");
        result.addProperty("rgb_group_boundary_policy", "Reset 0x0801441e..0x08014434 before flush captures logical writes only; load 0x08018c84..0x08018c98 supplies complete four-byte read into original zeroed temporary. No EEPROM backend, full reset, flush, partial/failing read, on-toggle persistence or migration executed.");
        String json = new GsonBuilder().setPrettyPrinting().disableHtmlEscaping().create().toJson(result) + "\n";
        Path output = Path.of(args[0]);
        if (args.length == 2) {
            if (!Files.readString(output).equals(json)) throw new Exception("Oracle fixture mismatch");
        } else Files.writeString(output, json, StandardOpenOption.CREATE_NEW);
        println("ORIGINAL_EMULATION_COMPLETE encodings=" + encodings.size() + " controls=" + controls.size() +
            " shifts=" + shifts.size() + " bsdl=" + bsdl.size() + " filters=" + filters.size() +
            " cadet=" + cadet.size() + " cadet_resets=" + resets.size() +
            " builtin=" + builtin.size() + " core_defaults=" + defaults.size() + " vendor_bypasses=" + bypasses.size() +
            " tap_code=" + taps.size() + " cadet_tap_expanded=" + expanded.size() +
            " settings_reset_prefix=" + settingsResets.size() + " dynamic_record_reset=" + recordResets.size() + " prefix_validity=" + prefixValidity.size() + " prefix_gates=" + prefixGates.size() + " consolidated_snapshot=" + snapshots.size() + " journal_entry=" + journals.size() + " backing_program=" + programs.size() + " backing_read=" + reads.size() + " backing_geometry=" + geometries.size() + " gpio_startup=" + gpioStartup.size() + " rgb_group_lifecycle=" + rgbGroups.size() + " rgb_limits=" + rgbLimits.size() + " rgb_composed=" + rgbComposed.size());
    }
}
