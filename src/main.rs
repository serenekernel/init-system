#![no_std]
#![no_main]
use core::panic::PanicInfo;
use serenelib::debug_writer::{_print};
use serenelib::syscalls::{
    MemObjMapFlags, MemObjPerms, SyscallError, sys_cap_initramfs, sys_cap_port_grant, sys_copy_to, sys_endpoint_create, sys_endpoint_destroy, sys_endpoint_free_message, sys_endpoint_receive, sys_exit, sys_map, sys_memobj_create, sys_process_create_empty, sys_start, sys_wait_for
};
use serenelib::{print, println};

use crate::elf_loader::load_elf;
mod elf_loader;
mod tar;

extern crate alloc;
use alloc::vec::Vec;
pub struct SysAllocator;

fn load_servers() -> Result<(), SyscallError> {
    let initramfs_val = sys_cap_initramfs()?;
    let initramfs = unsafe {
        core::slice::from_raw_parts(initramfs_val as *const u8, 50 *1024 * 1024)
    };

    let tar_archive = tar::TarArchive::new(initramfs);
    let files = tar_archive.list("/");
    for file in files {
        println!("initramfs: {}", file);
    }

    let elf_file = tar_archive.read("/test.elf").expect("failed to read elf binary");
    let (process, entry_point) = load_elf(elf_file)?;
    sys_start(process, entry_point)?;
    
    Ok(())
}

#[unsafe(no_mangle)]
pub extern "C" fn _start() -> ! {
    sys_cap_port_grant(0xe9, 1).expect("sys_cap_port_grant failed");
    // @note: because of how ass getting a handle to the init proc endpoint is right now
    // this MUST be the first handle created on the whole system
    // @todo: fix that
    let endpoint = sys_endpoint_create().expect("sys_endpoint_create failed");

    load_servers().expect("failed to load servers");
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
    println!("panic: {}", info.message());
    println!("at {:?}", info.location());
    
    sys_exit(1);
}
