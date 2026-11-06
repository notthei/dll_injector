# Rust製のシンプルなDllInjector
CreateRemoteThread + LoadLibraryA

# 処理フロー
   
1. `CreateToolhelp32Snapshot` でプロセス名→PIDを解決
2. `OpenProcess(PROCESS_ALL_ACCESS)` でターゲットをオープン
3. `VirtualAllocEx` でリモートプロセスのアドレス空間にメモリ確保
4. `WriteProcessMemory` でDLLパス文字列を書き込み
5. `GetProcAddress("LoadLibraryA")` でアドレス取得
6. `CreateRemoteThread(LoadLibraryA, dll_path_ptr)` でDLLをロード

## プロセス名指定
`dll_injector.exe notepad.exe C:\path\to\payload.dll`

## PID直接指定
`dll_injector.exe 1234 C:\path\to\payload.dll`

