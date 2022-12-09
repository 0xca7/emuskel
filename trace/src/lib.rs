use std::fmt;
use capstone::prelude::*;
use unicorn_engine::{RegisterARM, Unicorn, RegisterARM64};

/// this trait is used to be able to quickly implement other
/// architectures
pub enum ArmArch {
    Arm32,
    Aarch64,
}

pub trait ArchSpecific {
    fn print_value(&self);
}

/// registers for printing and tracing
struct RegsArm32 {
    r0:  u64,
    r1:  u64,
    r2:  u64,
    r3:  u64,
    r4:  u64,
    r5:  u64,
    r6:  u64,
    r7:  u64,
    r8:  u64,
    r9:  u64,
    r10: u64,
    r11: u64,
    r12: u64,
    r13: u64,
    r14: u64,
    r15: u64,
}

impl RegsArm32 {

    /// read regsters from emulator and save the values
    pub fn new(emu: &mut Unicorn<()>) -> Self {

        let r0 = emu.reg_read(RegisterARM::R0).expect("failed to read R0");
        let r1 = emu.reg_read(RegisterARM::R1).expect("failed to read R1");
        let r2 = emu.reg_read(RegisterARM::R2).expect("failed to read R2");
        let r3 = emu.reg_read(RegisterARM::R3).expect("failed to read R3");
        let r4 = emu.reg_read(RegisterARM::R4).expect("failed to read R4");
        let r5 = emu.reg_read(RegisterARM::R5).expect("failed to read R5");
        let r6 = emu.reg_read(RegisterARM::R6).expect("failed to read R6");
        let r7 = emu.reg_read(RegisterARM::R7).expect("failed to read R7");
        let r8 = emu.reg_read(RegisterARM::R8).expect("failed to read R8");
        let r9 = emu.reg_read(RegisterARM::R9).expect("failed to read R9");
        let r10 = emu.reg_read(RegisterARM::R10).expect("failed to read R10");
        let r11 = emu.reg_read(RegisterARM::R11).expect("failed to read R11");
        let r12 = emu.reg_read(RegisterARM::R12).expect("failed to read R12");
        let r13 = emu.reg_read(RegisterARM::R13).expect("failed to read R13");
        let r14 = emu.reg_read(RegisterARM::R14).expect("failed to read R14");
        let r15 = emu.reg_read(RegisterARM::R15).expect("failed to read R15");

        RegsArm32 {
            r0, r1, r2, r3, r4, r5, r6, r7, r8, r9, r10, r11, r12, r13, r14, r15
        }

    } // new
    
}

impl fmt::Display for RegsArm32 {

    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {

        writeln!(f, "Registers")?;

        writeln!(f, "r{} = {:#08x}  r{} = {:#08x}  r{} = {:#08x}  r{} = {:#08x}",
            0, self.r0, 1, self.r1, 2, self.r2, 3, self.r3
        )?;

        writeln!(f, "r{} = {:#08x}  r{} = {:#08x}  r{} = {:#08x}  r{} = {:#08x}",
            4, self.r4, 5, self.r5, 6, self.r6, 7, self.r7
        )?;

        writeln!(f, "r{} = {:#08x}  r{} = {:#08x}  r{} = {:#08x}  r{} = {:#08x}",
            8, self.r8, 9, self.r9, 10, self.r10, 11, self.r11
        )?;

        writeln!(f, "r{} = {:#08x}  r{} = {:#08x}  r{} = {:#08x}  r{} = {:#08x}",
            12, self.r12, 13, self.r13, 14, self.r14, 15, self.r15
        )?;

        writeln!(f, "------------------------------------------------------------")
    }

}

impl ArchSpecific for RegsArm32 {
    fn print_value(&self) {
        println!("{}", self);
    }
}

/// registers for printing and tracing
struct RegsArm64 {
    x0: u64,
    x1: u64,
    x2: u64,
    x3: u64,
    x4: u64,
    x5: u64,
    x6: u64,
    x7: u64,
    x8: u64,
    x9: u64,
    x10: u64,
    x11: u64,
    x12: u64,
    x13: u64,
    x14: u64,
    x15: u64,
    x16: u64,
    x17: u64,
    x18: u64,
    x19: u64,
    x20: u64,
    x21: u64,
    x22: u64,
    x23: u64,
    x24: u64,
    x25: u64,
    x26: u64,
    x27: u64,
    x28: u64,
    fp: u64, // Frame Pointer
    sp: u64, // Stack Pointer
    pc: u64,
}

impl RegsArm64 {

    /// read regsters from emulator and save the values
    pub fn new(emu: &mut Unicorn<()>) -> Self {

        let x0 = emu.reg_read(RegisterARM64::X0).expect("failed to read X0");
        let x1 = emu.reg_read(RegisterARM64::X1).expect("failed to read X1");
        let x2 = emu.reg_read(RegisterARM64::X2).expect("failed to read X2");
        let x3 = emu.reg_read(RegisterARM64::X3).expect("failed to read X3");
        let x4 = emu.reg_read(RegisterARM64::X4).expect("failed to read X4");
        let x5 = emu.reg_read(RegisterARM64::X5).expect("failed to read X5");
        let x6 = emu.reg_read(RegisterARM64::X6).expect("failed to read X6");
        let x7 = emu.reg_read(RegisterARM64::X7).expect("failed to read X7");
        let x8 = emu.reg_read(RegisterARM64::X8).expect("failed to read X8");
        let x9 = emu.reg_read(RegisterARM64::X9).expect("failed to read X9");
        let x10 = emu.reg_read(RegisterARM64::X10).expect("failed to read X10");
        let x11 = emu.reg_read(RegisterARM64::X11).expect("failed to read X11");
        let x12 = emu.reg_read(RegisterARM64::X12).expect("failed to read X12");
        let x13 = emu.reg_read(RegisterARM64::X13).expect("failed to read X13");
        let x14 = emu.reg_read(RegisterARM64::X14).expect("failed to read X14");
        let x15 = emu.reg_read(RegisterARM64::X15).expect("failed to read X15");
        let x16 = emu.reg_read(RegisterARM64::X16).expect("failed to read X16");
        let x17 = emu.reg_read(RegisterARM64::X17).expect("failed to read X17");
        let x18 = emu.reg_read(RegisterARM64::X18).expect("failed to read X18");
        let x19 = emu.reg_read(RegisterARM64::X19).expect("failed to read X19");
        let x20 = emu.reg_read(RegisterARM64::X20).expect("failed to read X20");
        let x21 = emu.reg_read(RegisterARM64::X21).expect("failed to read X21");
        let x22 = emu.reg_read(RegisterARM64::X22).expect("failed to read X22");
        let x23 = emu.reg_read(RegisterARM64::X23).expect("failed to read X23");
        let x24 = emu.reg_read(RegisterARM64::X24).expect("failed to read X24");
        let x25 = emu.reg_read(RegisterARM64::X25).expect("failed to read X25");
        let x26 = emu.reg_read(RegisterARM64::X26).expect("failed to read X26");
        let x27 = emu.reg_read(RegisterARM64::X27).expect("failed to read X27");
        let x28 = emu.reg_read(RegisterARM64::X28).expect("failed to read X28");
        let x29 = emu.reg_read(RegisterARM64::X29).expect("failed to read X29");
        let x30 = emu.reg_read(RegisterARM64::X30).expect("failed to read X30");
        let pc = emu.reg_read(RegisterARM64::PC).expect("failed to read X30");

        RegsArm64 {
            x0, x1, x2, x3, x4, x5, x6, x7, x8, x9, x10, x11, x12, x13, x14, x15, x16, x17, x18, x19, x20, x21, x22, x23, x24, x25, x26, x27, x28, fp: x29, sp: x30, pc
        }

    } // new
    
}

impl fmt::Display for RegsArm64 {

    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {

        writeln!(f, "Registers")?;

        writeln!(f, "x{} = {:#08x}  x{} = {:#08x}  x{} = {:#08x}  x{} = {:#08x}",
            0, self.x0, 1, self.x1, 2, self.x2, 3, self.x3
        )?;

        writeln!(f, "x{} = {:#08x}  x{} = {:#08x}  x{} = {:#08x}  x{} = {:#08x}",
            4, self.x4, 5, self.x5, 6, self.x6, 7, self.x7
        )?;

        writeln!(f, "x{} = {:#08x}  x{} = {:#08x}  x{} = {:#08x}  x{} = {:#08x}",
            8, self.x8, 9, self.x9, 10, self.x10, 11, self.x11
        )?;

        writeln!(f, "x{} = {:#08x}  x{} = {:#08x}  x{} = {:#08x}  x{} = {:#08x}",
            12, self.x12, 13, self.x13, 14, self.x14, 15, self.x15
        )?;

        writeln!(f, "x{} = {:#08x}  x{} = {:#08x}  x{} = {:#08x}  x{} = {:#08x}",
            16, self.x16, 17, self.x17, 18, self.x18, 19, self.x19
        )?;

        writeln!(f, "x{} = {:#08x}  x{} = {:#08x}  x{} = {:#08x}  x{} = {:#08x}",
            20, self.x20, 21, self.x21, 22, self.x22, 23, self.x23
        )?;

        writeln!(f, "x{} = {:#08x}  x{} = {:#08x}  x{} = {:#08x}  x{} = {:#08x}",
            24, self.x24, 25, self.x25, 26, self.x26, 27, self.x27
        )?;

        writeln!(f, "x{} = {:#08x}  x = {:#08x}  fp = {:#08x}  sp = {:#08x}",
            28, self.x28, self.fp, self.sp, self.pc
        )?;

        writeln!(f, "pc = {:08x}", self.pc)?;

        writeln!(f, "------------------------------------------------------------")
    }

}

impl ArchSpecific for RegsArm64 {
    fn print_value(&self) {
        println!("{}", self);
    }
}


/// get a filled registers struct depending on the architecture
fn get_regs(arch: ArmArch, emu: &mut Unicorn<()>) -> Box<dyn ArchSpecific> {

    // add new archs
    match arch {
        ArmArch::Arm32 => Box::new(RegsArm32::new(emu)),
        ArmArch::Aarch64 => Box::new(RegsArm64::new(emu)),
    }

}

/// use this to hook instructions and trace execution
pub fn hook_trace(emu: &mut Unicorn<()>, addr: u64, size: u32) {

    /* #ARCH */
    // change the arch here to print registers for a different arch
    let regs = get_regs(ArmArch::Aarch64, emu);
    regs.print_value();

    println!("[addr]> {:#x} ({})", addr, size);

    /* #ARCH */
    // change the arch here to disasm for a different arch
    let cs = Capstone::new()
        .arm64()
        .mode(arch::arm64::ArchMode::Arm)
        .detail(true)
        .build()
        .expect("error building capstone object");

    let code = emu.mem_read_as_vec(addr, size as usize)
        .expect("can't read code");

    let instrs = cs.disasm_all(&code, addr)
        .expect("disassembly failed");

    for instr in instrs.as_ref() {
        println!("{}", instr);
    }

}