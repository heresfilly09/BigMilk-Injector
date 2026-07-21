# BigMilk Injector

A robust, high-performance x64 DLL injector written in Rust. Designed for reliable dynamic library loading and custom module injection into running processes.

## Features

- **Direct Syscalls**: Bypasses standard user-mode API monitoring by resolving and executing NT syscalls directly using the `ntapi` crate, ensuring smooth and uninterrupted injection.
- **Thread Hijacking**: Executes mapping logic via thread hijacking rather than creating a new remote thread. Implements a handcrafted assembly trampoline to ensure strict 16-byte stack alignment during execution, preventing crashes in complex target applications.
- **Dynamic Binary Generation**: The custom `build.rs` script generates unique binary structures and randomized data on every single `cargo build`. This ensures that each compiled build is entirely unique and avoids generic pattern-matching.
- **Manual Mapping**: Loads the DLL completely from memory without relying on the standard Windows Loader (Ldr), preventing the module from showing up in standard process memory queries. 

## Building

You must compile this on a Windows system with MSVC (Visual Studio Build Tools) installed, as the build engine relies on `cl.exe` to compile the C++ mapping logic.

```powershell
cargo build --release
```

## Usage

```powershell
bigmilk-injector <path_to_dll> <target_process.exe>
```

Example:
```powershell
.\target\release\bigmilk-injector.exe .\target\release\test_payload.dll notepad.exe
```

## Testing

A sample payload is included to verify execution. Compile the payload with MSVC, ensuring you use `/MT` to statically link the CRT and avoid dependency issues during manual mapping.

```powershell
cl.exe /LD /MT test_payload.cpp /link /OUT:test_payload.dll User32.lib
```

## Links & Community

- **Website**: [bigmilk.co](https://bigmilk.co)
- **Discord**: [Join the Big Milk Server](https://discord.gg/syPe6chSAR)
