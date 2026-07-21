mod pe;
mod types;

use std::ffi::c_void;
use std::mem::{offset_of, size_of, zeroed};
use std::ptr::copy_nonoverlapping;
use std::thread;
use std::time::Duration;

use pe::{image_first_section, validate_pe};
use types::ManualMappingData as MappingData;
use windows::core::w;
use windows::Win32::Foundation::{BOOL, HANDLE, HINSTANCE, STILL_ACTIVE};
use windows::Win32::System::Diagnostics::Debug::{
    IMAGE_SCN_MEM_EXECUTE, IMAGE_SCN_MEM_WRITE,
};
use windows::Win32::System::LibraryLoader::{GetModuleHandleW, GetProcAddress};
use windows::Win32::System::Memory::{
    VirtualFreeEx, VirtualProtectEx, MEM_COMMIT, MEM_RELEASE, MEM_RESERVE,
    PAGE_EXECUTE_READ, PAGE_EXECUTE_READWRITE, PAGE_PROTECTION_FLAGS, PAGE_READONLY,
    PAGE_READWRITE,
};
use windows::Win32::System::SystemInformation::GetTickCount;
use windows::Win32::System::SystemServices::DLL_PROCESS_ATTACH;
use windows::Win32::System::Threading::GetExitCodeProcess;

// Direct NT syscall imports — these bypass user-mode hooks in ntdll
use ntapi::ntmmapi::{NtAllocateVirtualMemory, NtWriteVirtualMemory, NtReadVirtualMemory};
use ntapi::ntpsapi::NtGetNextThread;
use winapi::shared::ntdef::{PVOID, HANDLE as NT_HANDLE, NT_SUCCESS};

unsafe extern "C" {
    fn Shellcode(data: *mut MappingData);
}

const INJECT_TIMEOUT_MS: u32 = 30_000;
const SHELLCODE_SIZE: usize = 0x1000;

// Thread hijacking context constants
const CONTEXT_FULL: u32 = 0x10001F;

// Dynamically resolved function pointers for thread hijacking
type NtSuspendThreadFn = unsafe extern "system" fn(NT_HANDLE, *mut u32) -> i32;
type NtResumeThreadFn = unsafe extern "system" fn(NT_HANDLE, *mut u32) -> i32;
type NtGetContextThreadFn = unsafe extern "system" fn(NT_HANDLE, *mut CONTEXT64) -> i32;
type NtSetContextThreadFn = unsafe extern "system" fn(NT_HANDLE, *const CONTEXT64) -> i32;
type NtFreeVirtualMemoryFn = unsafe extern "system" fn(NT_HANDLE, *mut PVOID, *mut usize, u32) -> i32;
type NtCloseFn = unsafe extern "system" fn(NT_HANDLE) -> i32;

#[repr(C, align(16))]
#[derive(Clone)]
struct CONTEXT64 {
    p1_home: u64,
    p2_home: u64,
    p3_home: u64,
    p4_home: u64,
    p5_home: u64,
    p6_home: u64,
    context_flags: u32,
    mx_csr: u32,
    seg_cs: u16,
    seg_ds: u16,
    seg_es: u16,
    seg_fs: u16,
    seg_gs: u16,
    seg_ss: u16,
    e_flags: u32,
    dr0: u64,
    dr1: u64,
    dr2: u64,
    dr3: u64,
    dr6: u64,
    dr7: u64,
    rax: u64,
    rcx: u64,
    rdx: u64,
    rbx: u64,
    rsp: u64,
    rbp: u64,
    rsi: u64,
    rdi: u64,
    r8: u64,
    r9: u64,
    r10: u64,
    r11: u64,
    r12: u64,
    r13: u64,
    r14: u64,
    r15: u64,
    rip: u64,
    _flt_save: [u8; 512],
    vector_register: [u128; 26],
    vector_control: u64,
    debug_control: u64,
    last_branch_to_rip: u64,
    last_branch_from_rip: u64,
    last_exception_to_rip: u64,
    last_exception_from_rip: u64,
}

#[derive(Debug)]
pub enum InjectError {
    InvalidFile,
    InvalidPlatform,
    TargetAllocFailed(u32),
    WriteHeaderFailed(u32),
    WriteSectionFailed(u32),
    MappingAllocFailed(u32),
    WriteMappingFailed(u32),
    ShellcodeAllocFailed(u32),
    WriteShellcodeFailed(u32),
    ThreadCreateFailed(u32),
    ThreadHijackFailed(u32),
    ProcessCrashed(u32),
    TimedOut,
    WrongMappingPtr,
}

impl std::fmt::Display for InjectError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::InvalidFile => write!(f, "invalid PE file"),
            Self::InvalidPlatform => write!(f, "invalid platform"),
            Self::TargetAllocFailed(code) => {
                write!(f, "target process memory allocation failed: 0x{code:X}")
            }
            Self::WriteHeaderFailed(code) => write!(f, "can't write file header: 0x{code:X}"),
            Self::WriteSectionFailed(code) => write!(f, "can't map sections: 0x{code:X}"),
            Self::MappingAllocFailed(code) => {
                write!(f, "target process mapping allocation failed: 0x{code:X}")
            }
            Self::WriteMappingFailed(code) => write!(f, "can't write mapping: 0x{code:X}"),
            Self::ShellcodeAllocFailed(code) => {
                write!(f, "shellcode memory allocation failed: 0x{code:X}")
            }
            Self::WriteShellcodeFailed(code) => write!(f, "can't write shellcode: 0x{code:X}"),
            Self::ThreadCreateFailed(code) => write!(f, "thread creation failed: 0x{code:X}"),
            Self::ThreadHijackFailed(code) => write!(f, "thread hijack failed: 0x{code:X}"),
            Self::ProcessCrashed(code) => write!(f, "process crashed, exit code: 0x{code:08X}"),
            Self::TimedOut => write!(f, "injection timed out"),
            Self::WrongMappingPtr => write!(f, "wrong mapping pointer"),
        }
    }
}

unsafe fn resolve_nt_fn(name: &[u8]) -> Option<*const ()> {
    unsafe {
        let ntdll = GetModuleHandleW(w!("ntdll.dll")).ok()?;
        let addr = GetProcAddress(ntdll, windows::core::PCSTR(name.as_ptr()))?;
        Some(addr as *const ())
    }
}

unsafe fn nt_alloc(h_proc: HANDLE, size: usize, protect: u32) -> Result<*mut c_void, i32> {
    unsafe {
        let mut base: PVOID = std::ptr::null_mut();
        let mut region_size: usize = size;
        let status = NtAllocateVirtualMemory(
            h_proc.0 as NT_HANDLE,
            &mut base,
            0,
            &mut region_size,
            MEM_COMMIT.0 | MEM_RESERVE.0,
            protect,
        );
        if NT_SUCCESS(status) {
            Ok(base as *mut c_void)
        } else {
            Err(status)
        }
    }
}

unsafe fn nt_write(h_proc: HANDLE, dest: *mut c_void, src: *const u8, len: usize) -> Result<(), i32> {
    unsafe {
        let mut written: usize = 0;
        let status = NtWriteVirtualMemory(
            h_proc.0 as NT_HANDLE,
            dest as PVOID,
            src as PVOID,
            len,
            &mut written,
        );
        if NT_SUCCESS(status) {
            Ok(())
        } else {
            Err(status)
        }
    }
}

unsafe fn nt_read(h_proc: HANDLE, src: *const c_void, dest: *mut u8, len: usize) -> Result<(), i32> {
    unsafe {
        let mut read: usize = 0;
        let status = NtReadVirtualMemory(
            h_proc.0 as NT_HANDLE,
            src as PVOID,
            dest as PVOID,
            len,
            &mut read,
        );
        if NT_SUCCESS(status) {
            Ok(())
        } else {
            Err(status)
        }
    }
}

unsafe fn nt_free(h_proc: HANDLE, base: *mut c_void) {
    unsafe {
        let free_fn: Option<NtFreeVirtualMemoryFn> = resolve_nt_fn(b"NtFreeVirtualMemory\0")
            .map(|p| std::mem::transmute(p));
        if let Some(f) = free_fn {
            let mut addr = base as PVOID;
            let mut size: usize = 0;
            let _ = f(h_proc.0 as NT_HANDLE, &mut addr, &mut size, MEM_RELEASE.0);
        } else {
            let _ = VirtualFreeEx(h_proc, base, 0, MEM_RELEASE);
        }
    }
}

fn build_hijack_trampoline(shellcode_addr: u64, param_addr: u64, original_rip: u64) -> Vec<u8> {
    let mut tramp: Vec<u8> = Vec::with_capacity(128);

    tramp.extend_from_slice(&[0x9C]);
    tramp.extend_from_slice(&[0x50]);
    tramp.extend_from_slice(&[0x51]);
    tramp.extend_from_slice(&[0x52]);
    tramp.extend_from_slice(&[0x41, 0x50]);
    tramp.extend_from_slice(&[0x41, 0x51]);
    tramp.extend_from_slice(&[0x41, 0x52]);
    tramp.extend_from_slice(&[0x41, 0x53]);
    tramp.extend_from_slice(&[0x41, 0x57]);

    tramp.extend_from_slice(&[0x49, 0x89, 0xE7]);
    tramp.extend_from_slice(&[0x48, 0x83, 0xE4, 0xF0]);
    tramp.extend_from_slice(&[0x48, 0x83, 0xEC, 0x20]);

    tramp.extend_from_slice(&[0x48, 0xB9]);
    tramp.extend_from_slice(&param_addr.to_le_bytes());

    tramp.extend_from_slice(&[0x48, 0xB8]);
    tramp.extend_from_slice(&shellcode_addr.to_le_bytes());

    tramp.extend_from_slice(&[0xFF, 0xD0]);

    tramp.extend_from_slice(&[0x4C, 0x89, 0xFC]);

    tramp.extend_from_slice(&[0x41, 0x5F]);
    tramp.extend_from_slice(&[0x41, 0x5B]);
    tramp.extend_from_slice(&[0x41, 0x5A]);
    tramp.extend_from_slice(&[0x41, 0x59]);
    tramp.extend_from_slice(&[0x41, 0x58]);
    tramp.extend_from_slice(&[0x5A]);
    tramp.extend_from_slice(&[0x59]);
    tramp.extend_from_slice(&[0x58]);
    tramp.extend_from_slice(&[0x9D]);

    tramp.extend_from_slice(&[0x48, 0xB8]);
    tramp.extend_from_slice(&original_rip.to_le_bytes());
    tramp.extend_from_slice(&[0x50]);
    tramp.extend_from_slice(&[0xC3]);

    tramp
}

unsafe fn hijack_thread(
    h_proc: HANDLE,
    shellcode_remote: *mut c_void,
    mapping_alloc: *mut c_void,
) -> Result<(), InjectError> {
    unsafe {
    let suspend_fn: NtSuspendThreadFn = resolve_nt_fn(b"NtSuspendThread\0")
        .map(|p| std::mem::transmute(p))
        .ok_or(InjectError::ThreadHijackFailed(0xDEAD0001))?;
    let resume_fn: NtResumeThreadFn = resolve_nt_fn(b"NtResumeThread\0")
        .map(|p| std::mem::transmute(p))
        .ok_or(InjectError::ThreadHijackFailed(0xDEAD0002))?;
    let get_ctx_fn: NtGetContextThreadFn = resolve_nt_fn(b"NtGetContextThread\0")
        .map(|p| std::mem::transmute(p))
        .ok_or(InjectError::ThreadHijackFailed(0xDEAD0003))?;
    let set_ctx_fn: NtSetContextThreadFn = resolve_nt_fn(b"NtSetContextThread\0")
        .map(|p| std::mem::transmute(p))
        .ok_or(InjectError::ThreadHijackFailed(0xDEAD0004))?;
    let close_fn: NtCloseFn = resolve_nt_fn(b"NtClose\0")
        .map(|p| std::mem::transmute(p))
        .ok_or(InjectError::ThreadHijackFailed(0xDEAD0005))?;

    let mut h_thread: NT_HANDLE = std::ptr::null_mut();
    let status = NtGetNextThread(
        h_proc.0 as NT_HANDLE,
        std::ptr::null_mut(),
        0x001F03FF,
        0,
        0,
        &mut h_thread,
    );

    if !NT_SUCCESS(status) || h_thread.is_null() {
        return Err(InjectError::ThreadHijackFailed(status as u32));
    }

    let mut suspend_count: u32 = 0;
    let status = suspend_fn(h_thread, &mut suspend_count);
    if !NT_SUCCESS(status) {
        close_fn(h_thread);
        return Err(InjectError::ThreadHijackFailed(status as u32));
    }

    let mut ctx: CONTEXT64 = zeroed();
    ctx.context_flags = CONTEXT_FULL;
    let status = get_ctx_fn(h_thread, &mut ctx);
    if !NT_SUCCESS(status) {
        resume_fn(h_thread, &mut suspend_count);
        close_fn(h_thread);
        return Err(InjectError::ThreadHijackFailed(status as u32));
    }

    let original_rip = ctx.rip;

    let trampoline = build_hijack_trampoline(
        shellcode_remote as u64,
        mapping_alloc as u64,
        original_rip,
    );

    let tramp_remote = nt_alloc(h_proc, trampoline.len() + 0x100, PAGE_EXECUTE_READWRITE.0)
        .map_err(|s| InjectError::ThreadHijackFailed(s as u32))?;

    nt_write(h_proc, tramp_remote, trampoline.as_ptr(), trampoline.len())
        .map_err(|s| InjectError::ThreadHijackFailed(s as u32))?;

    ctx.rip = tramp_remote as u64;
    let status = set_ctx_fn(h_thread, &ctx);
    if !NT_SUCCESS(status) {
        resume_fn(h_thread, &mut suspend_count);
        close_fn(h_thread);
        return Err(InjectError::ThreadHijackFailed(status as u32));
    }

    let status = resume_fn(h_thread, &mut suspend_count);
    if !NT_SUCCESS(status) {
        close_fn(h_thread);
        return Err(InjectError::ThreadHijackFailed(status as u32));
    }

    close_fn(h_thread);

    Ok(())
    }
}

pub fn manual_map_dll(
    h_proc: HANDLE,
    src: &[u8],
    clear_header: bool,
    clear_non_needed_sections: bool,
    adjust_protections: bool,
    seh_exception_support: bool,
) -> Result<(), InjectError> {
    let nt = validate_pe(src).ok_or(InjectError::InvalidFile)?;
    let opt = &nt.OptionalHeader;
    let file_header = &nt.FileHeader;

    let target_base = unsafe {
        nt_alloc(h_proc, opt.SizeOfImage as usize, PAGE_READWRITE.0)
    }.map_err(|s| InjectError::TargetAllocFailed(s as u32))?;

    let mut old_protect = PAGE_PROTECTION_FLAGS(0);
    unsafe {
        let _ = VirtualProtectEx(
            h_proc,
            target_base,
            opt.SizeOfImage as usize,
            PAGE_EXECUTE_READWRITE,
            &mut old_protect,
        );
    }

    let h_k32 = unsafe { GetModuleHandleW(w!("kernel32.dll")) }
        .map_err(|e| InjectError::TargetAllocFailed(e.code().0 as u32))?;
    let load_library = unsafe { GetProcAddress(h_k32, windows::core::s!("LoadLibraryA")) }
        .ok_or(InjectError::InvalidPlatform)?;
    let get_proc_address = unsafe { GetProcAddress(h_k32, windows::core::s!("GetProcAddress")) }
        .ok_or(InjectError::InvalidPlatform)?;

    #[cfg(target_arch = "x86_64")]
    let rtl = unsafe { GetProcAddress(h_k32, windows::core::s!("RtlAddFunctionTable")) }
        .ok_or(InjectError::InvalidPlatform)?;

    #[cfg(target_arch = "x86_64")]
    let cxx_throw_stub = if seh_exception_support {
        write_cxx_throw_stub(h_proc, target_base, h_k32)?
    } else {
        std::ptr::null_mut()
    };

    let data = MappingData {
        p_load_library_a: unsafe { std::mem::transmute(load_library) },
        p_get_proc_address: unsafe { std::mem::transmute(get_proc_address) },
        #[cfg(target_arch = "x86_64")]
        p_rtl_add_function_table: unsafe { std::mem::transmute(rtl) },
        pbase: target_base as *mut u8,
        h_mod: HINSTANCE::default(),
        fdw_reason_param: DLL_PROCESS_ATTACH,
        reserved_param: std::ptr::null_mut(),
        seh_support: BOOL::from(seh_exception_support),
        #[cfg(target_arch = "x86_64")]
        p_cxx_throw_stub: cxx_throw_stub,
    };

    unsafe {
        nt_write(h_proc, target_base, src.as_ptr(), 0x1000)
    }.map_err(|s| {
        unsafe { nt_free(h_proc, target_base); }
        InjectError::WriteHeaderFailed(s as u32)
    })?;

    let section_count = file_header.NumberOfSections as usize;
    let mut section = unsafe { image_first_section(nt) };
    for _ in 0..section_count {
        let header = unsafe { &*section };
        if header.SizeOfRawData != 0 {
            let dest = (target_base as usize + header.VirtualAddress as usize) as *mut c_void;
            let section_src = src
                .get(
                    header.PointerToRawData as usize
                        ..header.PointerToRawData as usize + header.SizeOfRawData as usize,
                )
                .ok_or(InjectError::InvalidFile)?;

            unsafe {
                nt_write(h_proc, dest, section_src.as_ptr(), section_src.len())
            }.map_err(|s| {
                unsafe { nt_free(h_proc, target_base); }
                InjectError::WriteSectionFailed(s as u32)
            })?;
        }
        section = unsafe { section.add(1) };
    }

    let mapping_alloc = unsafe {
        nt_alloc(h_proc, size_of::<MappingData>(), PAGE_READWRITE.0)
    }.map_err(|s| {
        cleanup_partial(h_proc, target_base, std::ptr::null_mut(), None);
        InjectError::MappingAllocFailed(s as u32)
    })?;

    unsafe {
        nt_write(
            h_proc,
            mapping_alloc,
            &data as *const MappingData as *const u8,
            size_of::<MappingData>(),
        )
    }.map_err(|s| {
        cleanup_partial(h_proc, target_base, mapping_alloc, None);
        InjectError::WriteMappingFailed(s as u32)
    })?;

    let shellcode_remote = unsafe {
        nt_alloc(h_proc, SHELLCODE_SIZE, PAGE_EXECUTE_READWRITE.0)
    }.map_err(|s| {
        cleanup_partial(h_proc, target_base, mapping_alloc, None);
        InjectError::ShellcodeAllocFailed(s as u32)
    })?;

    let shellcode_local = read_local_shellcode();
    unsafe {
        nt_write(h_proc, shellcode_remote, shellcode_local.as_ptr(), SHELLCODE_SIZE)
    }.map_err(|s| {
        cleanup_partial(h_proc, target_base, mapping_alloc, Some(shellcode_remote));
        InjectError::WriteShellcodeFailed(s as u32)
    })?;

    unsafe {
        hijack_thread(h_proc, shellcode_remote, mapping_alloc)?;
    }

    let _ = wait_for_mapping(h_proc, mapping_alloc)?;

    let empty_buffer = vec![0u8; 1024 * 1024 * 20];

    // --- Clear header via NtWriteVirtualMemory ---
    if clear_header {
        if unsafe { nt_write(h_proc, target_base, empty_buffer.as_ptr(), 0x1000) }.is_err() {
            println!("[!] WARNING: Can't clear HEADER");
        }
    }

    // --- Clear unneeded sections via NtWriteVirtualMemory ---
    if clear_non_needed_sections {
        let mut section = unsafe { image_first_section(nt) };
        for _ in 0..section_count {
            let header = unsafe { &*section };
            let virtual_size = section_virtual_size(header);
            if virtual_size != 0 {
                let name = section_name(header);
                let should_clear = (if seh_exception_support {
                    false
                } else {
                    name == ".pdata"
                }) || name == ".rsrc" || name == ".reloc";

                if should_clear {
                    println!("[+] Clearing section: {name}");
                    let dest =
                        (target_base as usize + header.VirtualAddress as usize) as *mut c_void;
                    if unsafe {
                        nt_write(h_proc, dest, empty_buffer.as_ptr(), virtual_size as usize)
                    }.is_err() {
                        println!("[!] Can't clear section {name}");
                    }
                }
            }
            section = unsafe { section.add(1) };
        }
    }

    if adjust_protections {
        let mut section = unsafe { image_first_section(nt) };
        for _ in 0..section_count {
            let header = unsafe { &*section };
            let virtual_size = section_virtual_size(header);
            if virtual_size != 0 {
                let mut old = PAGE_PROTECTION_FLAGS(0);
                let characteristics = header.Characteristics;
                let new_protect = if characteristics.0 & IMAGE_SCN_MEM_WRITE.0 != 0 {
                    PAGE_READWRITE
                } else if characteristics.0 & IMAGE_SCN_MEM_EXECUTE.0 != 0 {
                    PAGE_EXECUTE_READ
                } else {
                    PAGE_READONLY
                };

                let dest = (target_base as usize + header.VirtualAddress as usize) as *const c_void;
                if unsafe {
                    VirtualProtectEx(
                        h_proc,
                        dest,
                        virtual_size as usize,
                        new_protect,
                        &mut old,
                    )
                    .is_ok()
                } {
                    println!(
                        "[+] Section {} -> {new_protect:?}",
                        section_name(header)
                    );
                } else {
                    println!(
                        "[!] Section {} protection change failed",
                        section_name(header)
                    );
                }
            }
            section = unsafe { section.add(1) };
        }

        let first = unsafe { image_first_section(nt) };
        let first_header = unsafe { &*first };
        let mut old = PAGE_PROTECTION_FLAGS(0);
        let _ = unsafe {
            VirtualProtectEx(
                h_proc,
                target_base,
                first_header.VirtualAddress as usize,
                PAGE_READONLY,
                &mut old,
            )
        };
    }

    // --- Cleanup shellcode and mapping via NtWriteVirtualMemory + NtFreeVirtualMemory ---
    if unsafe { nt_write(h_proc, shellcode_remote, empty_buffer.as_ptr(), SHELLCODE_SIZE) }.is_err() {
        println!("[!] WARNING: Can't clear shellcode");
    }
    unsafe { nt_free(h_proc, shellcode_remote); }
    unsafe { nt_free(h_proc, mapping_alloc); }

    println!("[+] Injection complete, artifacts cleaned up");
    Ok(())
}

fn read_local_shellcode() -> [u8; SHELLCODE_SIZE] {
    let start = Shellcode as *const () as usize;
    // Hardcode size to 4KB to avoid underflow if MSVC reorders the shellcode_end function before Shellcode
    let shellcode_size = 0x1000;
    println!("[+] Using fixed Shellcode Size: 0x{:X}", shellcode_size);

    let len = shellcode_size.min(SHELLCODE_SIZE);

    let mut buf = [0u8; SHELLCODE_SIZE];
    unsafe {
        copy_nonoverlapping(start as *const u8, buf.as_mut_ptr(), len);
    }
    buf
}

fn wait_for_mapping(h_proc: HANDLE, mapping_alloc: *mut c_void) -> Result<HINSTANCE, InjectError> {
    let start = unsafe { GetTickCount() };

    loop {
        let mut exit_code = 0u32;
        unsafe {
            let _ = GetExitCodeProcess(h_proc, &mut exit_code);
        }
        if exit_code != STILL_ACTIVE.0 as u32 {
            return Err(InjectError::ProcessCrashed(exit_code));
        }

        if unsafe { GetTickCount() }.saturating_sub(start) > INJECT_TIMEOUT_MS {
            return Err(InjectError::TimedOut);
        }

        // Read h_mod field from remote mapping data via NtReadVirtualMemory
        let mut h_mod = HINSTANCE::default();
        let h_mod_addr =
            (mapping_alloc as usize + offset_of!(MappingData, h_mod)) as *const c_void;
        unsafe {
            let _ = nt_read(
                h_proc,
                h_mod_addr,
                std::ptr::addr_of_mut!(h_mod).cast(),
                size_of::<HINSTANCE>(),
            );
        }
        if h_mod.0 as usize == 0x404040 {
            return Err(InjectError::WrongMappingPtr);
        }
        if !h_mod.0.is_null() {
            return Ok(h_mod);
        }

        thread::sleep(Duration::from_millis(10));
    }
}

fn cleanup_partial(
    h_proc: HANDLE,
    target_base: *mut c_void,
    mapping_alloc: *mut c_void,
    shellcode: Option<*mut c_void>,
) {
    unsafe {
        nt_free(h_proc, target_base);
        if !mapping_alloc.is_null() {
            nt_free(h_proc, mapping_alloc);
        }
        if let Some(sc) = shellcode {
            nt_free(h_proc, sc);
        }
    }
}

fn section_virtual_size(
    header: &windows::Win32::System::Diagnostics::Debug::IMAGE_SECTION_HEADER,
) -> u32 {
    unsafe { header.Misc.VirtualSize }
}

fn section_name(header: &windows::Win32::System::Diagnostics::Debug::IMAGE_SECTION_HEADER) -> String {
    header.Name.iter()
        .take_while(|&&b| b != 0)
        .map(|&b| b as char)
        .collect()
}

#[cfg(target_arch = "x86_64")]
fn write_cxx_throw_stub(
    h_proc: HANDLE,
    target_base: *mut c_void,
    h_k32: windows::Win32::Foundation::HMODULE,
) -> Result<*mut c_void, InjectError> {
    let raise_exception = unsafe { GetProcAddress(h_k32, windows::core::s!("RaiseException")) };

    let Some(raise_exception) = raise_exception else {
        println!("[!] WARNING: couldn't resolve RaiseException; typed catches may fail");
        return Ok(std::ptr::null_mut());
    };

    let stub_mem = unsafe {
        nt_alloc(h_proc, 0x1000, PAGE_EXECUTE_READWRITE.0)
    }.map_err(|s| InjectError::TargetAllocFailed(s as u32))?;

    let mut blob = [0u8; 0xB0];
    let mut stub = [
        0x48, 0x83, 0xEC, 0x48, 0xC7, 0x44, 0x24, 0x20, 0x20, 0x05, 0x93, 0x19, 0xC7, 0x44, 0x24,
        0x24, 0x00, 0x00, 0x00, 0x00, 0x48, 0x89, 0x4C, 0x24, 0x28, 0x48, 0x89, 0x54, 0x24, 0x30,
        0x48, 0xB8, 0, 0, 0, 0, 0, 0, 0, 0, 0x48, 0x89, 0x44, 0x24, 0x38, 0xB9, 0x63, 0x73, 0x6D,
        0xE0, 0xBA, 0x01, 0x00, 0x00, 0x00, 0x41, 0xB8, 0x04, 0x00, 0x00, 0x00, 0x4C, 0x8D, 0x4C,
        0x24, 0x20, 0x48, 0xB8, 0, 0, 0, 0, 0, 0, 0, 0, 0xFF, 0xD0, 0xCC,
    ];

    let image_base = target_base as u64;
    let raise_exception_addr = raise_exception as usize as u64;
    stub[32..40].copy_from_slice(&image_base.to_le_bytes());
    stub[68..76].copy_from_slice(&raise_exception_addr.to_le_bytes());
    blob[..stub.len()].copy_from_slice(&stub);

    blob[0x80] = 0x01;
    blob[0x81] = 0x04;
    blob[0x82] = 0x01;
    blob[0x83] = 0x00;
    blob[0x84] = 0x04;
    blob[0x85] = 0x82;

    let begin_addr = 0u32;
    let end_addr = stub.len() as u32;
    let unwind_rva = 0x80u32;
    blob[0xA0..0xA4].copy_from_slice(&begin_addr.to_le_bytes());
    blob[0xA4..0xA8].copy_from_slice(&end_addr.to_le_bytes());
    blob[0xA8..0xAC].copy_from_slice(&unwind_rva.to_le_bytes());

    if unsafe { nt_write(h_proc, stub_mem, blob.as_ptr(), blob.len()) }.is_ok() {
        Ok(stub_mem)
    } else {
        println!("[!] WARNING: couldn't write CxxThrow stub");
        Ok(std::ptr::null_mut())
    }
}
