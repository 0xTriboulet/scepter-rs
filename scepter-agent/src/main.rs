#![feature(stmt_expr_attributes)]
mod lib;
use lib::dll_main;  // This will import everything public from lib.rs

#[tokio::main]
async fn main() {
    dll_main().await;
}