#![no_std]


#[no_mangle]
pub extern "C" fn validate_packet(c_array: *const u8, length: usize) -> u32 {
	//let rust_array: &[u8] = unsafe { slice::from_raw_parts(c_array, length as usize) };
	return 1;
}

