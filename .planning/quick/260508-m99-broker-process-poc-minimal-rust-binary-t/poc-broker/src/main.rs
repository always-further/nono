//! poc-broker: Broker-process pattern PoC — validates RESEARCH.md Assumption A1.
//! A1: KernelBase ConClntInitialize skips CSRSS ALPC when child inherits broker console.
//! Build: cd poc-broker && cargo build --release --target x86_64-pc-windows-msvc
//! Run:   .\target\release\poc-broker.exe  (normal Medium-IL PS/cmd window)

#[cfg(windows)]
use std::{ffi::OsStr, mem::size_of, os::windows::ffi::OsStrExt};

#[cfg(windows)]
use windows_sys::Win32::Foundation::{CloseHandle, GetLastError, HANDLE};
#[cfg(windows)]
use windows_sys::Win32::Security::{
    CreateWellKnownSid, DuplicateTokenEx, OpenProcessToken, SecurityAnonymous,
    SetTokenInformation, TokenIntegrityLevel, TokenPrimary, WinLowLabelSid,
    SECURITY_IMPERSONATION_LEVEL, SECURITY_MAX_SID_SIZE, SE_GROUP_INTEGRITY,
    TOKEN_ADJUST_DEFAULT, TOKEN_ASSIGN_PRIMARY, TOKEN_DUPLICATE, TOKEN_MANDATORY_LABEL,
    TOKEN_QUERY,
};
#[cfg(windows)]
use windows_sys::Win32::System::Console::AllocConsole;
#[cfg(windows)]
use windows_sys::Win32::System::Threading::{
    CreateProcessAsUserW, GetCurrentProcess, GetExitCodeProcess, WaitForSingleObject,
    INFINITE, PROCESS_INFORMATION, STARTUPINFOW,
};

#[cfg(not(windows))]
fn main() {
    eprintln!("[POC] Windows-only binary. Build with: cargo build --release --target x86_64-pc-windows-msvc");
    eprintln!("[POC] Skeleton compiled OK — Win32 wiring activates only on Windows targets.");
}

#[cfg(windows)]
fn main() {
    // 1. AllocConsole — attach to a console at Medium IL. Returns 0 if one already
    //    exists (non-fatal; inherited console satisfies the mechanism equally).
    let alloc_rc = unsafe {
        // SAFETY: AllocConsole takes no arguments and is safe to call unconditionally.
        AllocConsole()
    };
    println!(
        "[POC] AllocConsole rc={alloc_rc} (0=inherited parent console, non-zero=new console)"
    );

    // 2. Open current process token for duplication.
    let mut h_token: HANDLE = std::ptr::null_mut();
    let ok = unsafe {
        // SAFETY: GetCurrentProcess() is a pseudo-handle; h_token is a valid out-pointer.
        OpenProcessToken(GetCurrentProcess(), TOKEN_DUPLICATE | TOKEN_QUERY | TOKEN_ASSIGN_PRIMARY | TOKEN_ADJUST_DEFAULT, &mut h_token)
    };
    fatal_if_zero(ok, "OpenProcessToken");

    // 3. Duplicate into a new primary token.
    // ImpersonationLevel is ignored for TokenPrimary (Win32 docs). SecurityAnonymous
    // is the conventional marker — mirrors launch.rs:1103-1108 (CR-01 hygiene).
    let mut h_new_token: HANDLE = std::ptr::null_mut();
    let ok = unsafe {
        // SAFETY: h_token is valid; h_new_token is a valid out-pointer.
        DuplicateTokenEx(
            h_token,
            TOKEN_ASSIGN_PRIMARY | TOKEN_DUPLICATE | TOKEN_QUERY | TOKEN_ADJUST_DEFAULT,
            std::ptr::null(),
            SecurityAnonymous as SECURITY_IMPERSONATION_LEVEL,
            TokenPrimary,
            &mut h_new_token,
        )
    };
    fatal_if_zero(ok, "DuplicateTokenEx");

    // 4. Build the Low Mandatory Level SID.
    let mut sid_buf = [0u8; SECURITY_MAX_SID_SIZE as usize];
    let mut sid_size = sid_buf.len() as u32;
    let ok = unsafe {
        // SAFETY: sid_buf is sized to SECURITY_MAX_SID_SIZE — sufficient for any well-known SID.
        CreateWellKnownSid(
            WinLowLabelSid,
            std::ptr::null_mut(),
            sid_buf.as_mut_ptr() as *mut _,
            &mut sid_size,
        )
    };
    fatal_if_zero(ok, "CreateWellKnownSid(WinLowLabelSid)");

    // 5. Construct TOKEN_MANDATORY_LABEL: [header | SID bytes] in a single allocation.
    let label_size = size_of::<TOKEN_MANDATORY_LABEL>() + sid_size as usize;
    let mut label_buf = vec![0u8; label_size];
    let label_ptr = label_buf.as_mut_ptr() as *mut TOKEN_MANDATORY_LABEL;
    unsafe {
        // SAFETY: label_buf has exactly label_size bytes; SID follows the header inline.
        let sid_ptr = label_buf.as_mut_ptr().add(size_of::<TOKEN_MANDATORY_LABEL>()) as *mut _;
        std::ptr::copy_nonoverlapping(sid_buf.as_ptr(), sid_ptr as *mut u8, sid_size as usize);
        (*label_ptr).Label.Sid = sid_ptr;
        (*label_ptr).Label.Attributes = SE_GROUP_INTEGRITY as u32;
    }

    // 6. Lower the duplicate token to Low Mandatory Level.
    let ok = unsafe {
        // SAFETY: h_new_token is valid; label_ptr points to a correctly built TOKEN_MANDATORY_LABEL.
        SetTokenInformation(h_new_token, TokenIntegrityLevel, label_ptr as *mut _, label_size as u32)
    };
    fatal_if_zero(ok, "SetTokenInformation(TokenIntegrityLevel, Low)");

    // 7. Build UTF-16 command line. No CREATE_NEW_CONSOLE, no DETACHED_PROCESS — the
    //    child inherits the broker's already-attached console. This is the critical flag
    //    combination that tests Assumption A1.
    let mut cmd_wide: Vec<u16> = OsStr::new("powershell.exe -NoLogo")
        .encode_wide()
        .chain(Some(0))
        .collect();
    let mut si: STARTUPINFOW = unsafe { std::mem::zeroed() };
    si.cb = size_of::<STARTUPINFOW>() as u32;
    let mut pi: PROCESS_INFORMATION = unsafe { std::mem::zeroed() };

    println!("[POC] Mechanism: AllocConsole + DuplicateTokenEx(SecurityAnonymous,TokenPrimary) + SetTokenInformation(Low) + CreateProcessAsUserW(dwCreationFlags=0)");

    // 8. Spawn PowerShell at Low IL, inheriting the broker's console.
    //    bInheritHandles=0 (FALSE) — console inheritance is via the console-attachment
    //    mechanism, not file-handle inheritance. dwCreationFlags=0 means no new console.
    let ok = unsafe {
        // SAFETY: h_new_token is a valid primary token; cmd_wide is null-terminated UTF-16;
        // si and pi are correctly sized zero-initialised structs.
        CreateProcessAsUserW(
            h_new_token,
            std::ptr::null(),      // lpApplicationName: derive from cmd line
            cmd_wide.as_mut_ptr(), // lpCommandLine: mutable per Win32 ABI
            std::ptr::null(),      // lpProcessAttributes
            std::ptr::null(),      // lpThreadAttributes
            0,                     // bInheritHandles = FALSE
            0,                     // dwCreationFlags = 0 (no CREATE_NEW_CONSOLE)
            std::ptr::null(),      // lpEnvironment: inherit parent
            std::ptr::null(),      // lpCurrentDirectory: inherit parent
            &si,
            &mut pi,
        )
    };
    fatal_if_zero(ok, "CreateProcessAsUserW");

    println!("[POC] Child PID: {}", pi.dwProcessId);
    println!("[POC] Waiting for child...");

    // 9. Wait for child to exit.
    let wait_rc = unsafe {
        // SAFETY: pi.hProcess is a valid process handle from CreateProcessAsUserW.
        WaitForSingleObject(pi.hProcess, INFINITE)
    };
    if wait_rc != 0 {
        eprintln!("[POC] FATAL: WaitForSingleObject failed (rc={wait_rc})");
        std::process::exit(1);
    }

    // 10. Read and interpret exit code.
    let mut exit_code: u32 = 0;
    let ok = unsafe {
        // SAFETY: pi.hProcess is still valid; exit_code is a valid out-pointer.
        GetExitCodeProcess(pi.hProcess, &mut exit_code)
    };
    fatal_if_zero(ok, "GetExitCodeProcess");

    println!("[POC] Child exit code: {exit_code:#010x} ({exit_code})");
    match exit_code {
        0 => println!("[POC] PASS — broker pattern viable; child survived KernelBase DllMain at Low-IL"),
        // STATUS_DLL_INIT_FAILED = 0xC0000142 = 3221225794u32
        // Exit code when KernelBase DllMain fails CSRSS ALPC attach at Low IL.
        3_221_225_794 => println!(
            "[POC] FAIL variant A — CSRSS still denies Low-IL child even with inherited console; \
            broker pattern NOT viable without further mechanism"
        ),
        other => println!(
            "[POC] FAIL variant B — unexpected exit code {other:#010x}; \
            capture ProcMon trace and analyze"
        ),
    }

    // 11. Cleanup all handles.
    unsafe {
        // SAFETY: All four handles are valid and owned by this process; each is closed exactly once.
        CloseHandle(pi.hThread);
        CloseHandle(pi.hProcess);
        CloseHandle(h_new_token);
        CloseHandle(h_token);
    }
}

/// Exit the process with a descriptive FATAL message if `result` is zero.
/// This is acceptable in PoC code whose sole purpose is pass/fail detection.
#[cfg(windows)]
fn fatal_if_zero(result: i32, ctx: &str) {
    if result == 0 {
        eprintln!(
            "[POC] FATAL: {} failed (GetLastError={})",
            ctx,
            unsafe { GetLastError() }
        );
        std::process::exit(1);
    }
}
