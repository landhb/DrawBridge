/**
 * Required rust language components
 */

use core;

#[lang = "eh_personality"]
#[no_mangle]
extern fn rust_eh_personality() {}

#[lang = "eh_unwind_resume"]
#[no_mangle]
// note: not sure why this takes an &i8 argument, but core::result::Result::unwrap calls it as such
extern fn rust_eh_unwind_resume(_: &i8) {}

#[lang = "panic_impl"]
extern fn panic_impl(_info: &core::panic::PanicInfo) -> ! {

    // infinitely loops, this is bad
    loop {

    }
}