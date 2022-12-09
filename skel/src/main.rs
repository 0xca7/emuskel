use conf::Config;
use loader::load_elf_file;
use emulator::{Emulator, ExecMode};

fn main() {

    let sections = load_elf_file("../testfiles/aarch64_code/crc32_aarch64");
    let mut code = Vec::new();

    for section in sections {
        if &section.0 == ".text" {
            code = section.1;
        }
    }

    let conf = Config::default();

    let mut emu = Emulator::new(&conf);

    emu.init(&conf);

    let base = match emu.alloc(0x4000) {
        Ok(addr) => addr,
        Err(e) => {
            eprintln!("{:?}", e);
            std::process::exit(1);
        }
    };

    // adjust this function to your needs
    emu.user_setup();

    emu.load(base, &code)
        .expect("unable to load code");

    // these offsets are from ghidra, we need to find an alternative to this...
    let start_addr = base + 0x110 + 4;
    let end_addr = base + 0x270;

    emu.run(start_addr, end_addr, ExecMode::Arm);

}
