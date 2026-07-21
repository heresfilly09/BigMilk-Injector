mod inject;
mod injector;
mod process;

use std::env;
use std::path::Path;

use inject::inject_dll_into_process;
use process::get_process_id_by_name;

fn run_cli(dll_path: &str, process_name: &str) {
    let pid = match get_process_id_by_name(process_name) {
        Some(pid) => pid,
        None => {
            eprintln!("[!] {} not running.", process_name);
            std::process::exit(1);
        }
    };

    println!("[*] PID: {}", pid);
    println!("[*] Hijacking...");

    match inject_dll_into_process(pid, Path::new(dll_path)) {
        Ok(()) => println!("[+] Injected successfully."),
        Err(err) => {
            eprintln!("[-] Error: {}", err);
            std::process::exit(1);
        }
    }
}

fn main() {
    let mut args = env::args().skip(1).collect::<Vec<_>>();

    if args.len() < 2 {
        eprintln!("usage: bigmilk <payload.dll> <target.exe>");
        std::process::exit(1);
    }

    let dll_path = args.remove(0);
    let process_name = args.remove(0);
    run_cli(&dll_path, &process_name);
}
