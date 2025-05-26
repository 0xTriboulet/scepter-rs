/// Placeholder strings get stomped in by CNA in release mode
#[cfg(not(debug_assertions))]
pub static USERNAME: &[u8; 64] =
    b"_________PLACEHOLDER_USERNAME_STRING_PLS_DO_NOT_CHANGE__________";
#[cfg(not(debug_assertions))]
pub static PASSWORD: &[u8; 64] =
    b"_________PLACEHOLDER_PASSWORD_STRING_PLS_DO_NOT_CHANGE__________";

#[cfg(not(debug_assertions))]
pub static SSH_INTERFACE_IPV4_ADDRESS: &[u8; 20] = b"999.999.999.999\0\0\0\0\0";
#[cfg(not(debug_assertions))]
pub static SSH_CONNECT_IPV4_ADDRESS: &[u8; 20] = b"888.888.888.888\0\0\0\0\0";
#[cfg(not(debug_assertions))]
pub static SSH_PORT: &[u8; 20] = b"99999\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0";

#[cfg(debug_assertions)]
pub static USERNAME: &[u8; 10] = b"username\0\0";
#[cfg(debug_assertions)]
pub static PASSWORD: &[u8; 10] = b"password\0\0";

#[cfg(debug_assertions)]
pub static SSH_INTERFACE_IPV4_ADDRESS: &[u8; 20] = b"0.0.0.0\0\0\0\0\0\0\0\0\0\0\0\0\0";
#[cfg(debug_assertions)]
pub static SSH_CONNECT_IPV4_ADDRESS: &[u8; 20] = b"127.0.0.1\0\0\0\0\0\0\0\0\0\0\0";

#[cfg(debug_assertions)]
pub static SSH_PORT: &[u8; 20] = b"2222\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0";