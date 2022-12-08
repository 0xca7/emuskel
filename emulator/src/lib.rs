
use std::fmt;

/// this is based on the unicorn emulator
/// and the capstone disassembler - thanks to the folks who coded these :)
/// 
/// 
/// TODO: implement the heap memory management
///       https://thecandcppclub.com/deepeshmenon/chapter-23-implementing-a-custom-heap/1860/

use capstone::prelude::*;

use unicorn_engine::{RegisterARM, RegisterARM64};
use unicorn_engine::unicorn_const::{Arch, Mode, Permission, SECOND_SCALE};

/// base address of the stack
const BASE_ADDR_STACK : u64   = 0x0000;
/// stack starts at 0x4000
const SIZE_STACK      : usize = 0x1000;

/// base address of the heap
const BASE_ADDR_HEAP : u64    = 0x2000;
/// size of the heap
const SIZE_HEAP      : usize  = 0x1000;

/// allocation base address
const BASE_ADDR_ALLOC: u64  = 0x10000;
/// max. possible memory that can be allocated
const ALLOC_MAX_MEM  : usize = 4 * 1024 * 1024;

#[derive(Debug)]
pub enum EmulatorError {
    LoadInvalidAddress,
}

#[derive(Debug)]
pub enum MemoryAllocErr {
    OutOfMemory,
    Overlap,
    UnicornError
}

#[derive(Debug)]
pub enum ExecMode {
    Thumb,
    Arm,
}

/// simple memory management for the emulator.
/// with this you can keep track of mapped memory and setup mapped memory
/// it also provides an interface so you don't have to worry about the internals
struct MemoryManagement {
    // this is program memory for loading an ELF etc.
    /// current address that can be allocated 
    cur_alloc: u64,
    /// memory left 
    mem_left: usize,
    /// keep track of allocated memory with this
    /// it's an address + size
    mem: Vec<(u64, usize)>,
}

impl MemoryManagement {

    /// new memory management instance for the emulator
    pub fn new() -> Self {
        MemoryManagement { 
            mem_left: ALLOC_MAX_MEM,
            cur_alloc: BASE_ADDR_ALLOC,
            mem: Vec::new() 
        }
    }

    /// allocate some memory 
    pub fn alloc(&mut self, size: usize) -> Result<u64, MemoryAllocErr> {

        // check if there is enough space available
        if size > self.mem_left {
            return Err(MemoryAllocErr::OutOfMemory);
        }

        let base_addr = self.cur_alloc;
        // if we get here, we can allocate the memory
        self.mem.push((base_addr, size));

        self.cur_alloc += size as u64;
        self.mem_left -= size;

        Ok(base_addr)
    }

    /// check if an address is in an allocated region
    pub fn check_load(&self, addr: u64, size: usize) -> bool {

        for region in &self.mem {
            // address is in a valid region
            if addr >= region.0 && addr <= (region.0 + region.1 as u64) {
                // check if the size exceeds the allocated memory space
                if (addr as usize + size) <= (region.0 as usize + region.1 ) {
                    return true;
                }
            }
        }
        false
    }

}

impl fmt::Display for MemoryManagement {

    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for allocation in &self.mem {
            writeln!(f, "[base: 0x{:x}] {} bytes", allocation.0, allocation.1)?;
        }
        writeln!(f, "[current base: 0x{:x}] {} bytes left", 
            self.cur_alloc, self.mem_left)
    }

}

pub struct Emulator<'a> {
    /// unicorn emulator instance
    emu: unicorn_engine::Unicorn<'a, ()>,
    /// capstone instance for disassembly
    cs: Capstone,
    /// memory of the emulator
    mmu: MemoryManagement
}

impl <'a> Emulator<'a> {

    /// create a new emulator including a capstone instance
    pub fn new() -> Self {
        Emulator { 
            emu: unicorn_engine::Unicorn::new(
                    Arch::ARM64, 
                    Mode::LITTLE_ENDIAN
                ).expect("failed to create emulator"),
            cs: Capstone::new()
                .arm64()
                .mode(arch::arm64::ArchMode::Arm) 
                .detail(true)
                .build()
                .expect("failed to build capstone instance"),
            mmu: MemoryManagement::new()
        } // emulator instance
    } // new 

    /// initialize the stack, heap etc.
    pub fn init(&mut self) {

        // heap memory
        self.emu.mem_map(BASE_ADDR_HEAP as u64, 
            SIZE_HEAP, Permission::ALL)
            .expect("failed to map code page");

        // stack memory
        self.emu.mem_map(BASE_ADDR_STACK as u64, 
            SIZE_STACK, Permission::ALL)
            .expect("failed to map code page");
        
        // set the stack pointer
        let stack_start = BASE_ADDR_STACK + SIZE_STACK as u64;
        self.emu.reg_write(RegisterARM64::SP, stack_start)
            .expect("failed to set stack pointer");
        
        // set the frame pointer
        self.emu.reg_write(RegisterARM64::FP, stack_start)
            .expect("failed to set stack pointer");
       
    }

    /// attempt to allocate `size` bytes of memory in the emulator
    /// on success, return the start address of the allocation
    pub fn alloc(&mut self, size: usize) -> Result<u64, MemoryAllocErr> {

        let base = match self.mmu.alloc(size) { 
            Ok(addr) => addr,
            Err(e) => {
                eprintln!("(alloc) {:?}\n", e);
                return Err(e);
            },
        };

        println!("base: 0x{:x}, {} bytes\n", base, size);

        let res = self.emu.mem_map(base, size, 
            Permission::ALL);

        match res {
            Ok(()) => Ok(base),
            Err(e) => {
                eprintln!("{:?}\n", e);
                Err(MemoryAllocErr::UnicornError)
            }
        }
    } // allocate

    pub fn load(&mut self, addr: u64, code: &[u8]) -> Result<(), EmulatorError> {

        if !self.mmu.check_load(addr, code.len()) {
            return Err(EmulatorError::LoadInvalidAddress);
        }

        self.emu.mem_write(addr, code)
            .expect("writing memory failed");

        let instrs = self.cs.disasm_all(code, addr)
            .expect("can't disassemble code");

        for instr in instrs.as_ref() {
            println!("{}", instr)
        }

        Ok(())
    }

    pub fn run(&mut self, start_addr: u64, end_addr: u64, mode: ExecMode) {

        // set into thumb mode                                                  
        let thumb = match mode {                                             
            ExecMode::Thumb => start_addr | 1,
            ExecMode::Arm => start_addr,
        };                                                                      

        self.emu.add_code_hook(start_addr, end_addr, trace::hook_trace)
            .expect("failed to add trace hook");
                                                                                
        let res = self.emu.emu_start(thumb,                                     
                start_addr + (end_addr - start_addr) as u64,        
            10 * SECOND_SCALE, 1000);                                           
                                                                                
        match res {                                                             
            Ok(()) => println!("emulation ok\n"),                                 
            Err(e) => eprintln!("emulation error {:?}\n", e),                     
        }; 

    }

    /// print memory stats of emulator
    pub fn show_memory(&self) {
        println!("{}\n", self.mmu);
    }

}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn single_alloc() {
        let mut emu = Emulator::new();
        let res = emu.alloc(0x1000);
        assert!(res.is_ok());
    }

    #[test]
    fn print_mmu() {

        let mut emu = Emulator::new();
        let res = emu.alloc(0x1000);
        assert!(res.is_ok());
        let res = emu.alloc(0x1000);
        assert!(res.is_ok());
        
        emu.show_memory();
    }

    #[test]
    fn run_emu() {
        let arm_code32 = [0x17, 0x00, 0x40, 0xe2];

        let mut emu = Emulator::new();
        emu.init();

        let base = emu.alloc(0x1000);

        println!("alloc: {:?}", base);

        assert!(base.is_ok());

        let base = base.unwrap();
        
        let res = emu.load(base, &arm_code32);

        emu.show_memory();

        assert!(res.is_ok());

        emu.run(base, base + arm_code32.len() as u64, ExecMode::Thumb);

    }

}
