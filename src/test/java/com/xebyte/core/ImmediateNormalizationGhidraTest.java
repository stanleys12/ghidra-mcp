package com.xebyte.core;

import ghidra.GhidraApplicationLayout;
import ghidra.app.cmd.disassemble.DisassembleCommand;
import ghidra.framework.Application;
import ghidra.framework.ApplicationConfiguration;
import ghidra.program.database.ProgramBuilder;
import ghidra.program.database.ProgramDB;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Instruction;
import ghidra.util.task.TaskMonitor;
import org.junit.After;
import org.junit.Before;
import org.junit.BeforeClass;
import org.junit.Test;

import java.io.File;

import static org.junit.Assert.*;
import static org.junit.Assume.assumeTrue;

/**
 * A large immediate is an address only when it points into the program.
 *
 * <p>MSVC's STL inlines {@code max_size()} as {@code SIZE_MAX / sizeof(T)}: 0x1fffffff for an
 * 8-byte element, 0xccccccc for a 20-byte one. That constant is often the only difference
 * between two container instantiations, and normalizing every value of 0x10000 or more to
 * {@code IMM_LARGE} gave them the same hash.
 */
public class ImmediateNormalizationGhidraTest {

    private ProgramBuilder builder;
    private ProgramDB program;
    private Function func;

    @BeforeClass
    public static void initializeGhidra() throws Exception {
        String installDir = System.getenv("GHIDRA_INSTALL_DIR");
        assumeTrue("GHIDRA_INSTALL_DIR is required for real Ghidra tests",
            installDir != null && !installDir.isBlank());
        if (!Application.isInitialized()) {
            ApplicationConfiguration configuration = new ApplicationConfiguration();
            configuration.setInitializeLogging(false);
            Application.initializeApplication(new GhidraApplicationLayout(new File(installDir)),
                configuration);
        }
    }

    @Before
    public void setUp() throws Exception {
        builder = new ProgramBuilder("imm", ProgramBuilder._X86, this);
        program = builder.getProgram();
        builder.createMemory(".text", "0x401000", 0x100);
        // MOV EAX,0x1fffffff; MOV EAX,0xccccccc; MOV EAX,0x401000; RET
        builder.setBytes("0x401000", "b8 ff ff ff 1f b8 cc cc cc 0c b8 00 10 40 00 c3");
        builder.withTransaction(() -> new DisassembleCommand(builder.addr("0x401000"),
            new AddressSet(builder.addr("0x401000"), builder.addr("0x40100f")), true)
            .applyTo(program, TaskMonitor.DUMMY));
        func = builder.createFunction("0x401000");
    }

    @After
    public void tearDown() {
        if (builder != null) {
            builder.dispose();
        }
    }

    private String normalized(String address) {
        Instruction instr = program.getListing().getInstructionAt(builder.addr(address));
        return BinaryComparisonService.normalizeInstruction(instr, func.getBody(),
            func.getEntryPoint(), program);
    }

    @Test
    public void largeConstantsOutsideMemoryKeepTheirValue() {
        assertEquals("MOV EAX,IMM:536870911", normalized("0x401000"));
        assertEquals("MOV EAX,IMM:214748364", normalized("0x401005"));
    }

    @Test
    public void aConstantInsideMemoryIsStillNormalized() {
        assertEquals("MOV EAX,IMM_LARGE", normalized("0x40100a"));
    }

    @Test
    public void signatureImmediatesIncludeLargeConstantsButNotAddresses() {
        BinaryComparisonService.FunctionSignature sig =
            BinaryComparisonService.computeFunctionSignature(program, func, TaskMonitor.DUMMY);
        assertTrue(sig.immediateValues.contains(0x1fffffffL));
        assertTrue(sig.immediateValues.contains(0xcccccccL));
        assertFalse(sig.immediateValues.contains(0x401000L));
    }
}
