/// this is based on the unicorn emulator
/// and the capstone disassembler - thanks to the folks who coded these :)
/// 
/// 
/// TODO: implement heap memory management?
///       https://thecandcppclub.com/deepeshmenon/chapter-23-implementing-a-custom-heap/1860/

use std::fmt;
use conf::Config;

use capstone::prelude::*;

use unicorn_engine::RegisterARM64;
use unicorn_engine::unicorn_const::{Arch, Mode, Permission, SECOND_SCALE};

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
    pub fn new(base: u64) -> Self {
        MemoryManagement { 
            mem_left: ALLOC_MAX_MEM,
            cur_alloc: base,
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

    /// allocate `size` bytes at address `addr`
    pub fn alloc_addr(&mut self, addr: u64, size: usize) -> Result<(), MemoryAllocErr>{

        // check if we can alloc
        for region in &self.mem {
            if addr >= region.0 && addr <= region.0 + region.1 as u64 {
                println!("! error: region at {:#x} already allocated", addr);
                return Err(MemoryAllocErr::Overlap);
            }
        }

        self.mem.push((addr, size));        
        Ok(())
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
    /// unicorn emulator instance, is public so user can access registers,
    /// write to memory etc. without requiring an interface in Emulator
    pub emu: unicorn_engine::Unicorn<'a, ()>,
    /// capstone instance for disassembly
    cs: Capstone,
    /// memory of the emulator
    mmu: MemoryManagement
}

impl <'a> Emulator<'a> {

    /// create a new emulator including a capstone instance
    pub fn new(config: &Config) -> Self {
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
            mmu: MemoryManagement::new(config.base_addr_alloc)
        } // emulator instance
    } // new 

    /// initialize the stack, heap etc.
    pub fn init(&mut self, config: &Config) {

        // heap memory
        self.emu.mem_map(config.heap_addr,
            config.heap_size, Permission::ALL)
            .expect("failed to map code page");

        // stack memory
        self.emu.mem_map(config.stack_addr as u64, 
            config.stack_size, Permission::ALL)
            .expect("failed to map code page");
        
        // set the stack pointer
        let stack_start = config.stack_addr + config.stack_size as u64;
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

    /// attempt to allocate memory at a specific address
    pub fn alloc_addr(&mut self, addr: u64, size: usize) -> Result<u64, MemoryAllocErr> {

        if self.mmu.alloc_addr(addr, size).is_err() {
            return Err(MemoryAllocErr::Overlap);
        }

        let res = self.emu.mem_map(addr, size, 
            Permission::ALL);

        match res {
            Ok(()) => Ok(addr),
            Err(e) => {
                eprintln!("{:?}\n", e);
                Err(MemoryAllocErr::UnicornError)
            }
        }

    }

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

    /// adjust to your specific needs
    pub fn user_setup(&mut self) {

        let data_addr = match self.alloc(0x1000) {
            Ok(addr) => addr,
            Err(e) => {
                eprintln!("{:?}", e);
                std::process::exit(1);
            }
        };

        // target function expects a message and a message length
        let message = vec![
            0x61, 0x62, 0x63, 0x64
        ];
        let message_len = 4;

        self.emu.mem_write(data_addr, &message)
            .expect("error writing memory");
        println!("[emulator]> wrote {:x?} to {:#x}", message, data_addr);

        self.emu.reg_write(RegisterARM64::X0, data_addr)
            .expect("failed to write X0");
        println!("[emulator]> wrote {:#x} to X0", data_addr);

        self.emu.reg_write(RegisterARM64::X1, message_len)
            .expect("failed to write X1");
        println!("[emulator]> wrote {} to X1", message_len);

        // we need some data at this address
        self.alloc_addr(0x21000, 0x1000)
            .expect("failed to allocate at 0x21000");

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
        let conf = Config::default();
        let mut emu = Emulator::new(&conf);
        let res = emu.alloc(0x1000);
        assert!(res.is_ok());
    }

    #[test]
    fn print_mmu() {

        let conf = Config::default();
        let mut emu = Emulator::new(&conf);
        let res = emu.alloc(0x1000);
        assert!(res.is_ok());
        let res = emu.alloc(0x1000);
        assert!(res.is_ok());
        
        emu.show_memory();
    }

    #[test]
    fn run_emu() {
        let arm_code32 = [0x17, 0x00, 0x40, 0xe2];

        let conf = Config::default();
        let mut emu = Emulator::new(&conf);
        emu.init(&conf);

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
