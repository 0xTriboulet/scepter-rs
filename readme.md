# scepter-rs

A Rust-based server-agent Command-and-Control designed to maximize compatability with non-standard devices. `scepter-rs` provides a minimal command and control interface that can be leveraged from [your favorite C2 framework](https://www.cobaltstrike.com/).

Based on [rdll-rs](https://github.com/0xTriboulet/rdll-rs) and similar in design to [rssh-rs](https://github.com/0xTriboulet/rssh-rs/tree/master), this project enables external capability to be deployed from a Beacon console, effectively providing (*very*) primitive support for 3rd-party SSH pivot agents from an existing Beacon session. Unlike `rssh-rs`, `scepter-rs` inverts the communication relationship and stands up an SSH server on the Beacon-side of communications, increasing the potential for SSH client-side customization.

![img_4.png](img_4.png)

## Project Components

- **scepter-server**: The command server that manages connections and facilitates communication with agents
- **scepter-agent**: The client-side agent that executes commands on target systems
- **scepter-common**: Shared code and utilities used by both server and agent components
- **bof-write-pipe**: Utility for writing to communication pipes
- **xtask**: Custom build scripts and development tools

## Features

- Cross-platform support for various operating systems
- Encrypted communications between server and agents
- Integration with Cobalt Strike via Aggressor scripts (.cna)
- Customizable command execution and data exfiltration

## Getting Started

### Prerequisites

- Rust toolchain (specified in rust-toolchain.toml)
- Cargo package manager
- [pe2shc](https://github.com/hasherezade/pe_to_shellcode/tree/master)
- [cargo-zigbuild](https://github.com/rust-cross/cargo-zigbuild)

### Building from Source
The project uses a workspace structure to manage multiple related crates. The `xtask` crate provides custom build commands.

1. Clone the repository:
   ```bash
   git clone https://github.com/yourusername/scepter-rs.git
   cd scepter-rs
   cargo run --bin xtask --release
   ```
**Note: Apple aarch64 and x64 were manually built due to shortfalls in cargo-zigbuild's compatibility on Windows environments. The command above will NOT rebuild the Apple binaries.**


### Usage

#### Agent Deployment

Agents can be compiled for a variety of platforms. `scepter-rs.cna` stomps in connection information provided in the `.cna` as well as from the Beacon console as necessary. The `scepter_server` is initialized via the `scepter-init` command in a Beacon console.

This project contains (untested/experimental) pre-built Agent binaries in the `bins/` folder, supporting:
- Windows x64 (tested)
- Windows aarch64
- Linux x64
- Linux aarch64 (tested)
- Apple x64
- Apple aarch64

Static pre-built binaries, and binaries built from source will be placed in the `bin/` directory. Do not modify those binaries unless you're confident in what you're doing. Those binaries are used as the baseline to allow changes to be driven from the `.cna`. You can get very far with customization from the command-line and the `scepter-rs.cna`.

#### Cobalt Strike Integration

The included `scepter-rs.cna` script provides integration with Cobalt Strike:

![img_2.png](img_2.png)

1. Load the script in your Cobalt Strike client
2. Initialize the scepter-server with the `scepter-init` command.
   ```
   beacon> help scepter-init
   scepter-init <target ip> <target-port> <username> <password> <optional: pid>
   ex: scepter-init 192.0.0.1 2222 my_username my_password 12345
   ```
3. The compiled binaries will be available in the `out/` directory.
4. Copy a binary from `out/` to the target system via some other means.
5. Run the binary on the target system.
6. Run commands via `ssh-exec`
   ```bash
   beacon> help scepter-exec
   scepter-exec <user command>
   ex:scepter-exec whoami   
   ```
   ![img_3.png](img_3.png)
#### Applying Other Reflective Loaders

For proof-of-concept functionality, `scepter-rs` applies `pe2shc`'s reflective loader to `scepter_server.windows.x64.dll` -> `scepter_server.shc.windows.x64.dll`. However, one of the really cool capabilities of `pe2shc` is that the output PE retains all functionality of the original. This means that you can apply your own "obfuscation"-enabled reflective loader on-top without any negative effects at run time.
![img.png](img.png)

To facilitate using additional/alternative reflective loaders, `scepter_server.windows.x64.dll` exports `dll_start` as an alternate entry point for loaders that allow for the specification of entry points (for example Donut's `--function` option).

![img_1.png](img_1.png)

This capability is theoretical and untested. Feedback is welcome.

## ToDo
- BOF support for Windows/Linux
- Refactor the code a bit (it's a mess)
- Unit tests :D
- More pre-built Agents???

## License
MIT or Apache 2.0.