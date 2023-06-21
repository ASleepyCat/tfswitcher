use std::{os::raw::c_char, ffi::CStr};

#[link(name = "get_version_from_module")]
extern "C" {
    fn GetVersionFromModule() -> *mut c_char;
}

pub fn get_version_from_module() -> Option<String> {
    let version_constraint = unsafe { GetVersionFromModule() };

    // Convert the output to a Rust string slice
    if version_constraint.is_null() {
        None
    } else {
        let output_cstr = unsafe { CStr::from_ptr(version_constraint) };
        let output = output_cstr.to_str().expect("Invalid UTF-8 string").to_owned();
        if output.is_empty() {
            return None;
        }
        Some(output)
    }
}
