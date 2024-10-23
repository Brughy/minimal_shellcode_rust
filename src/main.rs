use std::mem;
use std::ptr;
use libc::{mmap, PROT_EXEC, PROT_READ, PROT_WRITE, MAP_ANON, MAP_PRIVATE};

// Safe shellcode. It is no dangerous.
fn main() {
    // Shellcode execute write(1, "Hello\n", 6) abd then exit(0)
    let shellcode: [u8; 46] = [
        0x48, 0xc7, 0xc0, 0x01, 0x00, 0x00, 0x00,  // mov rax, 1 (syscall write)
        0x48, 0xc7, 0xc7, 0x01, 0x00, 0x00, 0x00,  // mov rdi, 1 (stdout)
        0x48, 0x8d, 0x35, 0x13, 0x00, 0x00, 0x00,  // lea rsi, [rip+0x13] (pointer to message "Hello\n")
        0xba, 0x06, 0x00, 0x00, 0x00,              // mov edx, 6 (message length)
        0x0f, 0x05,                                // syscall
        0x48, 0xc7, 0xc0, 0x3c, 0x00, 0x00, 0x00,  // mov rax, 60 (syscall exit)
        0x48, 0x31, 0xff,                          // xor rdi, rdi (exit code 0)
        0x0f, 0x05,                                // syscall
        // String "Hello\n"
        0x48, 0x65, 0x6c, 0x6c, 0x6f, 0x0a         // "Hello\n"
    ];
    unsafe {
        // Alloc memory 
        let addr = mmap(
            ptr::null_mut(),
            shellcode.len(),
            PROT_READ | PROT_WRITE | PROT_EXEC,
            MAP_PRIVATE | MAP_ANON,
            -1,
            0,
        );

        if addr == libc::MAP_FAILED {
            panic!("Error into memory mapping.");
        }

        // Copy shellcode into memory
        ptr::copy_nonoverlapping(shellcode.as_ptr(), addr as *mut u8, shellcode.len());

        // Convert address into function and execute it
        let exec_shellcode: extern "C" fn() = mem::transmute(addr);
        exec_shellcode();
    }
}
