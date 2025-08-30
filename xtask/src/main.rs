use std::process::{Command, exit};

fn main() {
    let path = std::env::current_dir().unwrap();
    println!("[INFO] The current directory is {}", path.display());

    // Build scepter-server -- 64-bit only because I don't care about 32-bit, sorry
    println!("[XTASK] Building scepter-server...");
    let status = Command::new("cargo")
        .args(&[
            "build",
            "--release",
            "--manifest-path",
            "./Cargo.toml",
            "--target",
            "x86_64-pc-windows-gnu",
        ])
        .current_dir("./scepter-server")
        .status()
        .expect("Failed to build");
    if !status.success() {
        exit(1);
    }

    // Copy target/x86_64-pc-windows-gnu/release/scepter_server.dll to bins/x64/scepter_server.x64.dll
    let status = Command::new("cp")
        .args(&[
            "target/x86_64-pc-windows-gnu/release/scepter_server.dll",
            "./bins/x64/scepter_server.windows.x64.dll",
        ])
        .current_dir(".")
        .status()
        .expect("Failed to copy");
    if !status.success() {
        exit(1);
    }

    // Build Win64 scepter-agent
    println!("[XTASK] Building scepter-agent...");
    let status = Command::new("cargo")
        .args(&[
            "build",
            "--release",
            "--manifest-path",
            "./Cargo.toml",
            "--target",
            "x86_64-pc-windows-gnu",
        ])
        .current_dir("./scepter-agent")
        .status()
        .expect("Failed to build");
    if !status.success() {
        exit(1);
    }

    // Copy target/x86_64-pc-windows-gnu/release/scepter_agent.exe/dll to bins/x64/scepter_agent.x64.exe/dll
    let status = Command::new("cp")
        .args(&[
            "target/x86_64-pc-windows-gnu/release/scepter_agent.dll",
            "./bins/x64/scepter_agent.windows.x64.dll",
        ])
        .current_dir(".")
        .status()
        .expect("Failed to copy");
    if !status.success() {
        exit(1);
    }

    let status = Command::new("cp")
        .args(&[
            "target/x86_64-pc-windows-gnu/release/scepter-agent.exe",
            "./bins/x64/scepter_agent.windows.x64.exe",
        ])
        .current_dir(".")
        .status()
        .expect("Failed to copy");
    if !status.success() {
        exit(1);
    }

    // Build Linux 64 scepter-agent
    let status = Command::new("cargo")
        .args(&[
            "build",
            "--release",
            "--manifest-path",
            "./Cargo.toml",
            "--target",
            "x86_64-unknown-linux-musl",
        ])
        .current_dir("./scepter-agent")
        .status()
        .expect("Failed to build");
    if !status.success() {
        exit(1);
    }

    // Copy target/x86_64-unknown-linux-musl/release/scepter_agent to bins/x64/scepter_agent.lin.x64.bin
    let status = Command::new("cp")
        .args(&[
            "target/x86_64-unknown-linux-musl/release/scepter-agent",
            "./bins/x64/scepter_agent.linux.x64.bin",
        ])
        .current_dir(".")
        .status()
        .expect("Failed to copy");
    if !status.success() {
        exit(1);
    }

    // Built Linux aarch64 agent: cargo zigbuild --target aarch64-unknown-linux-gnu -p scepter-agent
    let status = Command::new("cargo")
        .args(&[
            "zigbuild",
            "--release",
            "--manifest-path",
            "./Cargo.toml",
            "--target",
            "aarch64-unknown-linux-gnu",
        ])
        .current_dir("./scepter-agent")
        .status()
        .expect("Failed to build");
    if !status.success() {
        exit(1);
    }

    let status = Command::new("cp")
        .args(&[
            "target/aarch64-unknown-linux-gnu/release/scepter-agent",
            "./bins/aarch64/scepter_agent.linux.aarch64.bin",
        ])
        .current_dir(".")
        .status()
        .expect("Failed to copy");
    if !status.success() {
        exit(1);
    }

    // Built Windows aarch64 agent: cargo build --target aarch64-pc-windows-msvc -p scepter-agent --release
    let status = Command::new("cargo")
        .args(&[
            "build",
            "--release",
            "--manifest-path",
            "./Cargo.toml",
            "--target",
            "aarch64-pc-windows-msvc",
        ])
        .current_dir("./scepter-agent")
        .status()
        .expect("Failed to build");
    if !status.success() {
        exit(1);
    }

    let status = Command::new("cp")
        .args(&[
            "target/aarch64-pc-windows-msvc/release/scepter-agent.exe",
            "./bins/aarch64/scepter_agent.windows.aarch64.exe",
        ])
        .current_dir(".")
        .status()
        .expect("Failed to copy");
    if !status.success() {
        exit(1);
    }

    let status = Command::new("cp")
        .args(&[
            "target/aarch64-pc-windows-msvc/release/scepter_agent.dll",
            "./bins/aarch64/scepter_agent.windows.aarch64.dll",
        ])
        .current_dir(".")
        .status()
        .expect("Failed to copy");
    if !status.success() {
        exit(1);
    }

    // Built Linux aarch64 agent: cargo zigbuild --target aarch64-unknown-linux-gnu -p scepter-agent
    let status = Command::new("cargo")
        .args(&[
            "zigbuild",
            "--release",
            "--manifest-path",
            "./Cargo.toml",
            "--target",
            "aarch64-unknown-linux-gnu",
        ])
        .current_dir("./scepter-agent")
        .status()
        .expect("Failed to build");
    if !status.success() {
        exit(1);
    }

    let status = Command::new("cp")
        .args(&[
            "target/aarch64-unknown-linux-gnu/release/scepter-agent",
            "./bins/aarch64/scepter_agent.linux.aarch64.bin",
        ])
        .current_dir(".")
        .status()
        .expect("Failed to copy");
    if !status.success() {
        exit(1);
    }

    // Built Windows aarch64 agent: cargo build --target aarch64-pc-windows-msvc -p scepter-agent --release
    let status = Command::new("cargo")
        .args(&[
            "build",
            "--release",
            "--manifest-path",
            "./Cargo.toml",
            "--target",
            "aarch64-pc-windows-msvc",
        ])
        .current_dir("./scepter-agent")
        .status()
        .expect("Failed to build");
    if !status.success() {
        exit(1);
    }

    let status = Command::new("cp")
        .args(&[
            "target/aarch64-pc-windows-msvc/release/scepter-agent.exe",
            "./bins/aarch64/scepter_agent.windows.aarch64.exe",
        ])
        .current_dir(".")
        .status()
        .expect("Failed to copy");
    if !status.success() {
        exit(1);
    }

    let status = Command::new("cp")
        .args(&[
            "target/aarch64-pc-windows-msvc/release/scepter_agent.dll",
            "./bins/aarch64/scepter_agent.windows.aarch64.dll",
        ])
        .current_dir(".")
        .status()
        .expect("Failed to copy");
    if !status.success() {
        exit(1);
    }

    // Build Apple aarch64 agent using zigbuild
    if cfg!(target_os = "linux") {
        println!("[XTASK] Building Apple aarch64 scepter-agent...");
        let status = Command::new("cargo")
            .args(&[
                "zigbuild",
                "--release",
                "--manifest-path",
                "./Cargo.toml",
                "--target",
                "aarch64-apple-darwin",
            ])
            .current_dir("./scepter-agent")
            .status()
            .expect("Failed to build Apple aarch64 agent. Is cargo-zigbuild installed?");
        if !status.success() {
            println!("[XTASK] Warning: Failed to build Apple aarch64 agent. Continuing with other builds...");
        } else {
            // Copy the binary to the appropriate location
            let status = Command::new("cp")
                .args(&[
                    "target/aarch64-apple-darwin/release/scepter-agent",
                    "./bins/aarch64/scepter_agent.apple.aarch64.bin",
                ])
                .current_dir(".")
                .status()
                .expect("Failed to copy Apple aarch64 binary");
            if !status.success() {
                println!("[XTASK] Warning: Failed to copy Apple aarch64 binary. Continuing...");
            } else {
                println!("[XTASK] Successfully built and copied Apple aarch64 agent");
            }
        }
    }else{
        println!("[XTASK] Skipping Apple aarch64 build. This is not a Linux machine.");
    }

    // Compile BOF
    println!("[XTASK] Building BOF...");
    let status = Command::new("cc")
        .args(&["bof.c", "-c", "-o", "../bins/x64/bof_write_pipe.x64.o"])
        .current_dir("./bof-write-pipe")
        .status()
        .expect("Failed to build");
    if !status.success() {
        exit(1);
    }

    // Apply pe2shc to bins/x64/scepter_server.x64.dll
    println!("[XTASK] Applying pe2shc...");
    let status = Command::new("pe2shc")
        .args(&["scepter_server.windows.x64.dll", "scepter_server.shc.windows.x64.dll"])
        .current_dir("./bins/x64/")
        .status()
        .expect("Failed to build. Is pe2shc installed and added to your system path? If you're trying to use a different reflective loader, ignore this message.");
    if !status.success() {
        exit(1);
    }

    println!("[XTASK] Done");
}
