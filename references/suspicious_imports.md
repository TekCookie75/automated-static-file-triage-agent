# Suspicious Windows API Imports Reference

This file is used by the malware-triage skill to flag imports commonly associated with malicious behavior.
You can extend or trim any category to suit your environment.

---

## Process Injection & Memory Manipulation

| Function | Notes |
|---|---|
| VirtualAlloc | Allocate executable memory — common in shellcode loaders |
| VirtualAllocEx | Remote process memory allocation |
| VirtualProtect | Change memory permissions (e.g. RWX) |
| VirtualProtectEx | Remote memory permission change |
| WriteProcessMemory | Write into another process — classic injection |
| ReadProcessMemory | Read from another process |
| CreateRemoteThread | Launch thread in remote process |
| CreateRemoteThreadEx | Extended remote thread creation |
| NtCreateThreadEx | NT-level remote thread (often used to evade hooks) |
| RtlCreateUserThread | Undocumented thread creation |
| QueueUserAPC | APC injection |
| NtQueueApcThread | NT-level APC injection |
| SetThreadContext | Hijack thread context |
| SuspendThread | Suspend thread (used in process hollowing) |
| ResumeThread | Resume thread after hollowing/injection |

---

## Process Hollowing & Unmapping

| Function | Notes |
|---|---|
| NtUnmapViewOfSection | Unmap legitimate process image — process hollowing |
| ZwUnmapViewOfSection | Alias of above |
| NtMapViewOfSection | Map malicious image into hollowed process |
| CreateProcessInternalW | Internal process creation, used in hollowing |

---

## Shellcode & Dynamic Code Execution

| Function | Notes |
|---|---|
| LoadLibrary | Dynamic DLL loading |
| LoadLibraryA | ANSI variant |
| LoadLibraryW | Unicode variant |
| LoadLibraryEx | Extended dynamic loading |
| GetProcAddress | Resolve API address at runtime — used to hide imports |
| LdrLoadDll | NT-level DLL loading |
| LdrGetProcedureAddress | NT-level GetProcAddress |

---

## Persistence Mechanisms

| Function | Notes |
|---|---|
| RegSetValueEx | Write registry key — common for Run key persistence |
| RegCreateKeyEx | Create new registry key |
| RegOpenKeyEx | Open registry key |
| CreateService | Install a Windows service |
| ChangeServiceConfig | Modify an existing service |
| StartService | Start a service |
| SHFileOperation | Copy/move files (used in dropper persistence) |
| CopyFile | File copying |
| MoveFileEx | Move/rename with reboot option |

---

## Privilege Escalation & Token Manipulation

| Function | Notes |
|---|---|
| AdjustTokenPrivileges | Elevate process privileges |
| OpenProcessToken | Access a process token |
| DuplicateToken | Duplicate a security token |
| DuplicateTokenEx | Extended token duplication |
| ImpersonateLoggedOnUser | Impersonate another user |
| SetThreadToken | Assign token to thread |
| LookupPrivilegeValue | Resolve privilege names |

---

## Defense Evasion

| Function | Notes |
|---|---|
| IsDebuggerPresent | Anti-debug check |
| CheckRemoteDebuggerPresent | Anti-debug check |
| NtQueryInformationProcess | Used to detect debuggers / check process info |
| OutputDebugString | Anti-debug timing trick |
| GetTickCount | Timing-based anti-debug / sandbox detection |
| QueryPerformanceCounter | Timing-based sandbox evasion |
| Sleep | Sandbox evasion via time delay |
| NtDelayExecution | NT-level sleep |
| GetSystemTime | Sandbox time check |
| SetFileTime | Timestomping |

---

## Network Communication (C2 / Exfiltration)

| Function | Notes |
|---|---|
| WSAStartup | Winsock initialization |
| socket | Raw socket creation |
| connect | Outbound TCP connection |
| send | Send data over socket |
| recv | Receive data |
| InternetOpen | WinINet HTTP init |
| InternetConnect | WinINet connection |
| HttpOpenRequest | HTTP request |
| HttpSendRequest | Send HTTP request |
| URLDownloadToFile | Download file from URL |
| WinHttpOpen | WinHTTP init |
| WinHttpConnect | WinHTTP connection |
| WinHttpSendRequest | WinHTTP send |
| WSASend | Async socket send |
| WSARecv | Async socket receive |
| getaddrinfo | DNS resolution |
| gethostbyname | Legacy DNS resolution |

---

## Credential Theft & Sensitive Data Access

| Function | Notes |
|---|---|
| CryptAcquireContext | Crypto context (also used in ransomware) |
| CryptEncrypt | Encryption (ransomware) |
| CryptDecrypt | Decryption |
| CryptGenKey | Key generation |
| CryptExportKey | Export key material |
| NtReadVirtualMemory | Read process memory (LSASS dumping) |
| MiniDumpWriteDump | Dump process memory — LSASS credential theft |
| SamQueryInformationUser | SAM database access |
| LsaOpenPolicy | LSA access |

---

## File System & Payload Dropping

| Function | Notes |
|---|---|
| CreateFile | Open/create file |
| WriteFile | Write file contents |
| DeleteFile | Delete file (cleanup after drop) |
| FindFirstFile | File enumeration |
| FindNextFile | File enumeration |
| GetTempPath | Get temp directory — common dropper location |
| GetWindowsDirectory | Get Windows dir |
| GetSystemDirectory | Get System32 path |
| ShellExecute | Execute a file |
| WinExec | Legacy execution |
| CreateProcess | Spawn a new process |

---

## Anti-Analysis & Sandbox Evasion

| Function | Notes |
|---|---|
| GetCursorPos | Mouse movement check (sandbox has no mouse) |
| GetForegroundWindow | Check for active user desktop |
| GetSystemMetrics | Screen resolution — detect VM/sandbox |
| EnumWindows | Check for analysis tool windows |
| FindWindow | Search for debugger/AV windows by title |
| GetUserName | Check username for sandbox indicators |
| GetComputerName | Check hostname for sandbox indicators |
