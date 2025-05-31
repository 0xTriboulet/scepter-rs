#![feature(stmt_expr_attributes)]
extern crate core;

mod lib;
use crate::lib::dll_start;
// This will import everything public from lib.rs

#[tokio::main]
async fn main() {
    unsafe {
        dll_start();
    }
}
