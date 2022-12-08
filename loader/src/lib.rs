use std::fs;                                                                    
use std::io::{BufReader, Read};
use std::fs::File;
use std::path::Path;                                                            
use elf::{ElfBytes, endian::AnyEndian}; 


/// return the first 16 bytes of a file upon a loading error for user to see
/// that way the user can review the returned bytes to determine the error cause 
#[derive(Debug)]
enum FileTypeError {
    HeaderBytes([u8;16])
}

type FileIdentifyError = Result<(), FileTypeError>;


/// parse an elf file, return all sections + section bytes
/// the section name and the bytes of the section are returned as a tuple
fn parse_elf<P: AsRef<Path> + ?Sized>(path: &P) -> Vec<(String, Vec<u8>)> {

    let data = fs::read(path)                                                   
        .expect("file not found");                                              
                                                                                
    let file = ElfBytes::<AnyEndian>::minimal_parse(&data)                      
        .expect("error parsing ELF");                                           
                                                                                
    let (shdrs_opt, strtab_opt) = file
        .section_headers_with_strtab()
        .expect("shdrs offsets should be valid");

    let (shdrs, strtab) = (
        shdrs_opt.expect("Should have shdrs"),
        strtab_opt.expect("Should have strtab")
    );

    let mut section_names = Vec::new();
    for item in shdrs {
        match strtab.get(item.sh_name as usize) {
            Ok(n) => section_names.push(n),
            Err(e) => {
                eprintln!("ELF parse error: {e}");
                std::process::exit(1);
            }
        }
    }

    let mut data = Vec::new();

    for section_name in section_names {
        let shdr = file.section_header_by_name(section_name)                          
            .expect("failed to get section header")                                 
            .expect("section text not found");                                      
        let sdata = file.section_data(&shdr)                                
            .expect("unable to get section data for text section");
        data.push((section_name.to_owned(), sdata.0.to_vec()));
    }

    data
}


/// identify a file by it's header
fn identify_file(path: &str) -> FileIdentifyError {

    // first 16 bytes are enough to get the file magic
    let mut bytes = vec![0u8; 16];

    let f = File::open(path);

    let f = match f {
        Ok(f) => f,
        Err(e) => {
            eprintln!("open: {e}");
            std::process::exit(1);
        }
    };

    let mut reader = BufReader::new(f);

    match reader.read_exact(&mut bytes) {
        Ok(()) => (),
        Err(e) => {
            eprintln!("error reading file: {e}");
            std::process::exit(1);
        }
    };

    const ELFMAGIC: [u8;4] = [
        0x7f, 0x45, 0x4c, 0x46
    ];

    let magic = &bytes[0..4];

    if &ELFMAGIC == magic {
        return Ok(());
    }

    Err(FileTypeError::HeaderBytes(bytes[0..16].try_into().unwrap()))

}


/// try to load the file specified by the user, if it isn't loadable, exit
pub fn load_elf_file(path: &str) -> Vec<(String, Vec<u8>)> {

    match identify_file(path) {
        Ok(()) => parse_elf(path),
        Err(e) => {
            eprintln!("{:?}", e);
            std::process::exit(1);
        }
    }

}

/// load raw bytes from a file. the bytes have the form: 0xff, 0xdd, ...
/// that means bytes are seperated with a comma and prefixed with "0x"
pub fn load_code_file(path: &str) -> Vec<u8> {

    let raw = match fs::read_to_string(path) {
        Ok(data) => data,
        Err(e) => {
            eprintln!("{e}");
            std::process::exit(1);
        }
    };

    // split the string by ","
    raw.split(",")
        .map(|x| 
            // for each item in the split, remove the "0x" and try a conversion
            // to a u8, if it fails, exit, otherwise return a vector with u8
            match u8::from_str_radix(x
                .replace(" ", "")
                .trim_start_matches("0x"), 16)
            {
                Ok(n) => n,
                Err(e) => {
                    eprintln!("{e}: {}", x);
                    //std::process::exit(1);
                    0
                }
            }
        ) 
        .collect()

}


#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn basic_parsing() {
        let res = parse_elf("../testfiles/true_x86-64");
        assert!(res.len() != 0);
    }

    #[test]
    fn file_id() {

        // must be ok, is a valid elf
        let id = identify_file("../testfiles/true_x86-64");
        assert!(id.is_ok());

        let id = identify_file("../testfiles/not_valid");
        assert!(id.is_err());

    }

    #[test]
    fn load_file_elf() {
        let sections = load_elf_file("../testfiles/true_x86-64");

        for section in sections {
            println!("loaded section {} with {} bytes", section.0, section.1.len());
        }

    }

    #[test]
    fn load_file_code() {
        let data = load_code_file("../testfiles/code");
        assert!(data == vec![0x10, 0x20, 0x30])
    }

}