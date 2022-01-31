pub const SHELLCODE_LENGTH: usize = include_bytes!("../resources/shellcode.bin").len();
pub const DEFAULT_SHELLCODE: [u8; SHELLCODE_LENGTH] = *include_bytes!("../resources/shellcode.bin");
pub const MAX_AMOUNT_OF_MODULES: usize = 1024;