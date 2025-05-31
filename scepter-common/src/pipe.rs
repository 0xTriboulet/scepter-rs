#![allow(unused_imports)]
use debug_print::debug_println;
use std::ffi::CString;
use std::ptr;
use std::ptr::null_mut;
use windows_sys::Win32::Foundation::{
    CloseHandle, ERROR_PIPE_CONNECTED, GetLastError, HANDLE, INVALID_HANDLE_VALUE,
};
use windows_sys::Win32::Storage::FileSystem::{
    FlushFileBuffers, PIPE_ACCESS_DUPLEX, PIPE_ACCESS_INBOUND, ReadFile, WriteFile,
};
use windows_sys::Win32::System::Pipes::{
    ConnectNamedPipe, CreateNamedPipeA, DisconnectNamedPipe, PIPE_READMODE_MESSAGE, PIPE_TYPE_BYTE,
    PIPE_TYPE_MESSAGE, PeekNamedPipe,
};

pub const MAX_PIPE_BUFFER_SIZE: usize = 4096;

// PIPE NAMES ARE STOMPED IN BY .CNA
pub static OUTPUT_PIPE_NAME: &[u8; 42] = b"\\\\.\\pipe\\OUTPUT_PIPE_NAME_NO_CHANGE_PLS\0\0\0";
pub static INPUT_PIPE_NAME: &[u8; 42] = b"\\\\.\\pipe\\INPUT_PIPE_NAME_NO_CHANGE_PLS\0\0\0\0";

pub fn read_input(h_input_pipe: HANDLE) -> Option<String> {
    let mut dyn_buffer = Box::new(vec![0u8; MAX_PIPE_BUFFER_SIZE as usize]);
    let mut bytes_read: u32 = 0;

    // Check if client is still connected
    let mut bytes_available: u32 = 0;
    let peek_result = unsafe {
        PeekNamedPipe(
            h_input_pipe,
            null_mut(),
            0,
            null_mut(),
            &mut bytes_available,
            null_mut(),
        )
    };

    // If pipe is broken/disconnected, wait for new connection
    if peek_result == 0 {
        unsafe {
            DisconnectNamedPipe(h_input_pipe);
            ConnectNamedPipe(h_input_pipe, null_mut());
        }
        return None;
    }

    // Only try to read if there's data available
    if bytes_available > 0 {
        let read_result = unsafe {
            ReadFile(
                h_input_pipe,
                dyn_buffer.as_ptr() as *mut u8,
                MAX_PIPE_BUFFER_SIZE as u32,
                &mut bytes_read,
                std::ptr::null_mut(),
            )
        };

        if read_result > 0 && bytes_read > 0 {
            return String::from_utf8(dyn_buffer[..bytes_read as usize].to_vec())
                .ok()
                .map(|s| s.trim().to_string());
        }
    }

    None
}

pub fn initialize_input_pipe() -> Option<HANDLE> {
    let pipe_name = String::from_utf8_lossy(&*INPUT_PIPE_NAME);
    debug_println!("Pipe name: {}", pipe_name);
    let h_pipe = unsafe {
        CreateNamedPipeA(
            pipe_name.as_ptr() as *const u8,
            PIPE_ACCESS_INBOUND,
            PIPE_TYPE_MESSAGE | PIPE_READMODE_MESSAGE,
            1,
            MAX_PIPE_BUFFER_SIZE as u32,
            MAX_PIPE_BUFFER_SIZE as u32,
            0,
            std::ptr::null_mut(),
        )
    };

    if h_pipe == INVALID_HANDLE_VALUE {
        let err = unsafe { GetLastError() };
        debug_println!("CreateNamedPipe failed: {}", err);
        return None;
    }

    // Wait for client connection
    let connected = unsafe { ConnectNamedPipe(h_pipe, std::ptr::null_mut()) };
    if connected == 0 {
        let err = unsafe { GetLastError() };
        if err != ERROR_PIPE_CONNECTED {
            debug_println!("ConnectNamedPipe failed: {}", err);
            unsafe { CloseHandle(h_pipe) };
            return None;
        }
    }

    return Some(h_pipe);
}

pub fn initialize_output_pipe() -> Option<HANDLE> {
    let pipe_name = String::from_utf8_lossy(&*OUTPUT_PIPE_NAME);
    debug_println!("Pipe name: {}", pipe_name);
    let h_pipe = unsafe {
        CreateNamedPipeA(
            pipe_name.as_ptr() as *const u8,
            PIPE_ACCESS_DUPLEX,
            PIPE_TYPE_BYTE,
            1,
            MAX_PIPE_BUFFER_SIZE as u32,
            MAX_PIPE_BUFFER_SIZE as u32,
            0,
            std::ptr::null_mut(),
        )
    };

    if h_pipe == INVALID_HANDLE_VALUE {
        let err = unsafe { GetLastError() };
        debug_println!("CreateNamedPipe failed: {}", err);
        return None;
    }

    Some(h_pipe)
}

#[cfg(not(debug_assertions))]
pub fn write_output(h_output_pipe: HANDLE, data: &str) {
    let message = data.as_bytes();
    let mut bytes_written: u32 = 0;

    let connected = unsafe { ConnectNamedPipe(h_output_pipe, std::ptr::null_mut()) };
    if connected == 0 {
        let err = unsafe { GetLastError() };
        if err != ERROR_PIPE_CONNECTED {
            debug_println!("ConnectNamedPipe failed: {}", err);
            unsafe { CloseHandle(h_output_pipe) };
            return;
        }
    }

    debug_println!("[+] Beacon connected! Sending message...");

    let success = unsafe {
        WriteFile(
            h_output_pipe,
            message.as_ptr(),
            message.len() as u32,
            &mut bytes_written,
            std::ptr::null_mut(),
        )
    };

    if success == 0 {
        let err = unsafe { GetLastError() };
        debug_println!("WriteFile failed: {}", err);
        unsafe { CloseHandle(h_output_pipe) };
        return;
    }

    unsafe {
        FlushFileBuffers(h_output_pipe);
    }
}

/// Debug implementation of write_output.
#[cfg(debug_assertions)]
pub fn write_output(_h_output_pipe: HANDLE, data: &str) {
    debug_println!("{}", data);
}
