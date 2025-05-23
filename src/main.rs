use std::collections::HashMap;
use std::sync::Arc;

use rand_core::OsRng;
use russh::keys::{Certificate, *};
use russh::server::{Msg, Server as _, Session};
use russh::*;
use tokio::sync::Mutex;

/// Placeholder strings get stomped in by CNA in release mode
#[cfg(not(debug_assertions))]
pub static USERNAME: &[u8; 64] = b"_________PLACEHOLDER_USERNAME_STRING_PLS_DO_NOT_CHANGE__________";
#[cfg(not(debug_assertions))]
pub static PASSWORD: &[u8; 64] = b"_________PLACEHOLDER_PASSWORD_STRING_PLS_DO_NOT_CHANGE__________";


#[cfg(debug_assertions)]
pub static USERNAME: &[u8; 10] = b"username\0\0";
#[cfg(debug_assertions)]
pub static PASSWORD: &[u8; 10] = b"password\0\0";

#[tokio::main]
async fn main() {
    env_logger::builder()
        .filter_level(log::LevelFilter::Debug)
        .init();

    let config = russh::server::Config {
        inactivity_timeout: Some(std::time::Duration::from_secs(3600)),
        auth_rejection_time: std::time::Duration::from_secs(3),
        auth_rejection_time_initial: Some(std::time::Duration::from_secs(0)),
        keys: vec![
            russh::keys::PrivateKey::random(&mut OsRng, russh::keys::Algorithm::Ed25519).unwrap(),
        ],
        preferred: Preferred {
            // kex: std::borrow::Cow::Owned(vec![russh::kex::DH_GEX_SHA256]),
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
    async fn post(&mut self, data: CryptoVec) {
        let mut clients = self.clients.lock().await;
        for (id, (channel, s)) in clients.iter_mut() {
            if *id != self.id {
                let _ = s.data(*channel, data.clone()).await;
            }
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

    async fn auth_password(
        &mut self,
        user: &str,
        pass: &str,
    )-> Result<server::Auth, Self::Error> {

        // Believe it or not, this is military-grade security
        let username = String::from_utf8_lossy(&*USERNAME);
        let username = username.trim_end_matches('\0');

        let password = String::from_utf8_lossy(&*PASSWORD);
        let password = password.trim_end_matches('\0');

        let input_username = String::from_utf8_lossy(user.as_bytes());
        let input_password = String::from_utf8_lossy(pass.as_bytes());

        if input_username.eq(&username) || input_password.eq(&password) {
            return Ok(server::Auth::Accept)
        }

        Err(russh::Error::NotAuthenticated)
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

    async fn tcpip_forward(
        &mut self,
        address: &str,
        port: &mut u32,
        session: &mut Session,
    ) -> Result<bool, Self::Error> {
        let handle = session.handle();
        let address = address.to_string();
        let port = *port;
        tokio::spawn(async move {
            let channel = handle
                .channel_open_forwarded_tcpip(address, port, "1.2.3.4", 1234)
                .await
                .unwrap();
            let _ = channel.data(&b"Hello from a forwarded port"[..]).await;
            let _ = channel.eof().await;
        });
        Ok(true)
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