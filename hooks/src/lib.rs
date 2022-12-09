use unicorn_engine;
use unicorn_engine::unicorn_const::{
    Arch, Mode, Permission, SECOND_SCALE, HookType, MemType
};

pub fn callback_mem_error(uc: &mut unicorn_engine::Unicorn<i64>, memtype: MemType, address: u64, size: usize, value: i64) {
    println!("callback_mem_error {:x}", address);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn it_works() {
        let emu = unicorn_engine::Unicorn::<i64>::new(
            Arch::ARM64, 
            Mode::LITTLE_ENDIAN
        );

        assert!(emu.is_ok());
        let mut emu = emu.unwrap();

        // this is the only way to add a memory hook, using a closure, everything
        // else just fails -.- the emulator instance needs a datatype for this to work
        emu.add_mem_hook(HookType::MEM_ALL, 0, 0 + 0x1000, |_, _, addr, sz, _| {
        println!("{:x} {}", addr, sz);
        true
        }).unwrap();

        // if the emulator has a datatype, then we can use this!
        emu.add_mem_hook(HookType::MEM_ALL, 0, 0 + 0x1000, callback_mem_error);

    }
}
