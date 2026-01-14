#![no_std]
#![no_main]
use core::panic::PanicInfo;
use serenelib::debug_writer::{_print, DebugWriter};
use serenelib::syscalls::{sys_cap_port_grant, sys_exit, sys_endpoint_create, sys_endpoint_destroy, sys_endpoint_send, sys_endpoint_receive, sys_endpoint_free_message, sys_wait_for};
use serenelib::{print, println};
use x86_64::instructions::port::Port;

#[unsafe(no_mangle)]
pub extern "C" fn _start() -> ! {
    sys_cap_port_grant(0xe9, 1).expect("sys_cap_port_grant failed");
    
    let endpoint = sys_endpoint_create().expect("sys_endpoint_create failed");
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
