use ini::Ini;
use std::fmt;
use std::default;

pub struct Config {
    pub base_addr_alloc: u64,
    pub stack_addr: u64,
    pub stack_size: usize,
    pub heap_addr: u64,
    pub heap_size: usize,
    pub start_addr: u64,
    pub end_addr: u64,
}

impl Config {

    fn conv_u64(v: &str) -> u64 {
        match u64::from_str_radix(v.trim_start_matches("0x"), 16) {
            Ok(v) => v,
            Err(e) => {
                eprintln!("{e}");
                std::process::exit(1);
            }
        }
    } 

    fn conv_usize(v: &str) -> usize {
        match usize::from_str_radix(v.trim_start_matches("0x"), 16) {
            Ok(v) => v,
            Err(e) => {
                eprintln!("{e}");
                std::process::exit(1);
            }
        }
    } 

    pub fn parse(&mut self, key: &str, val: &str) {

        match key {
            "base" => self.base_addr_alloc = Self::conv_u64(val),
            "stack_addr" => self.stack_addr = Self::conv_u64(val),
            "heap_addr" => self.heap_addr = Self::conv_u64(val),
            "stack_size" => self.stack_size = Self::conv_usize(val),
            "heap_size" => self.heap_size = Self::conv_usize(val),
            "start_addr" => self.start_addr = Self::conv_u64(val),
            "end_addr" => self.end_addr = Self::conv_u64(val),
            _ => println!("unkown key: {key}"),
        };

    }
}


impl default::Default for Config {
    fn default() -> Self {
        Config {
            base_addr_alloc: 0x10000,
            stack_addr: 0x00,
            stack_size: 0x1000,
            heap_addr: 0x2000,
            heap_size: 0x1000,
            start_addr: 0,
            end_addr: 0,
        }
    }
}

pub fn read_config(path: Option<&str>) -> Config {

    let mut conf= Config::default();

    if let Some(path) = path {
        let i = match Ini::load_from_file(path) {
            Ok(ini) => ini,
            Err(e) => {
                eprintln!("{e}");
                std::process::exit(1);
            },
        };

        for section in &i {
            if let Some(s) = section.0 {
                println!("> parsing config section [{}]", s);
                for (key, val) in section.1.iter() {
                    conf.parse(key, val);
                }
            }
        }
    }

    conf

}

impl fmt::Display for Config {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "> base: {:#x}\n", self.base_addr_alloc)?;
        write!(f, "> stack: {:#x} ({} bytes)\n", 
            self.stack_addr, self.stack_size)?;
        write!(f, "> heap: {:#x} ({} bytes)\n", 
            self.heap_addr, self.heap_size)?;
        write!(f, "> emulation start: {:#x}\n", 
            self.start_addr)?;
        write!(f, "> emulation end: {:#x}\n", 
            self.end_addr)?;
        write!(f, "> emulating {} bytes\n", 
            self.end_addr.checked_sub(self.start_addr)
            .unwrap())
    }
}

#[cfg(test)]
mod tests {

    use super::*;

    #[test]
    fn no_config_file() {
        let conf = read_config(None);
        assert!(conf.base_addr_alloc == 0x10000);
        assert!(conf.stack_addr == 0x00);
        assert!(conf.heap_addr == 0x2000);
        assert!(conf.stack_size == 0x1000);
        assert!(conf.heap_size == 0x1000);
        assert!(conf.start_addr == 0);
        assert!(conf.end_addr == 0);
    }

    #[test]
    fn use_config_file() {
        let conf = read_config(Some("../testfiles/conf.ini"));
        assert!(conf.base_addr_alloc == 0x1000);
        assert!(conf.stack_addr == 0xff000000);
        assert!(conf.heap_addr == 0xfff00000);
        assert!(conf.stack_size == 0x1000);
        assert!(conf.heap_size == 0x1000);
        assert!(conf.start_addr == 0x1000);
        assert!(conf.end_addr == 0x1200);

        println!("{}", conf);
    }
}
