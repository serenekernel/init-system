#![no_std]
#![no_main]
use core::panic::PanicInfo;
use serenelib::debug_writer::{_print};
use serenelib::syscalls::{
    sys_cap_port_grant, sys_exit, sys_endpoint_create, sys_endpoint_destroy, 
    sys_endpoint_receive, sys_endpoint_free_message, sys_wait_for,
    sys_process_create_empty, sys_memobj_create, sys_map, sys_copy_to, sys_start,
    MemObjPerms, MemObjMapFlags, SyscallError
};
use serenelib::{print, println};

fn test_proccess_creation() -> Result<(), SyscallError> {    
    let process = sys_process_create_empty()?;    
    let page_size = 4096;
    let perms = MemObjPerms::READ | MemObjPerms::WRITE | MemObjPerms::EXEC;
    
    let memobj = sys_memobj_create(page_size, perms)?;
    
    let vaddr = 0x40000000;
    let mapped_addr = sys_map(
        process,
        memobj,
        Some(vaddr),
        MemObjPerms::READ | MemObjPerms::EXEC,
        MemObjMapFlags::FIXED,
    )?;
    
    let simple_code: &[u8] = &[
        0xbf, 0x01, 0x00, 0x00, 0x00,  // mov edi, 1
        0xbe, 0x2a, 0x00, 0x00, 0x00,  // mov esi, 42
        0x0f, 0x05,                    // syscall
    ];  
    
    sys_copy_to(
        process,
        mapped_addr,
        simple_code.as_ptr(),
        simple_code.len(),
    )?;
    
    sys_start(process, mapped_addr)?;    
    Ok(())
}

#[unsafe(no_mangle)]
pub extern "C" fn _start() -> ! {
    sys_cap_port_grant(0xe9, 1).expect("sys_cap_port_grant failed");
    // @note: because of how ass getting a handle to the init proc endpoint is right now
    // this MUST be the first handle created on the whole system
    // @todo: fix that
    let endpoint = sys_endpoint_create().expect("sys_endpoint_create failed");

    test_proccess_creation().expect("test_proccess_creation failed");
    sys_wait_for(endpoint).expect("sys_wait_for failed");
    let (message_ptr, _total_size) = sys_endpoint_receive(endpoint).expect("sys_endpoint_receive failed");
    
    unsafe {
        let message = &*message_ptr;
        let payload = message.payload();

        println!("init_system: recv on {:?}", endpoint);
        println!("init_system: len {}", message.length);
        
        match core::str::from_utf8(&payload[0..message.length as usize]) {
            Ok(text) => println!("init_system: payload: {}", text),
            Err(_) => println!("init_system: payload: {:?}", &payload[0..message.length as usize]),
        }
        
        sys_endpoint_free_message(message_ptr).expect("sys_endpoint_free_message failed");
    }
    sys_endpoint_destroy(endpoint).expect("sys_endpoint_destroy failed");


    println!("init_system: Hello, World!");
    
    sys_exit(0);
}

#[panic_handler]
fn panic(info: &PanicInfo) -> ! {
    println!("panic: {}", info);
    sys_exit(1);
}
