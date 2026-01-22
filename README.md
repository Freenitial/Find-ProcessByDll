# Find-ProcessByDll 🔎🧩

Scanner to identify **which running processes have loaded specific DLLs**, locally or on remote Windows machines.  
It is recommended to copy-paste only the function in PowerShell console, then call it when needed.  
Also available as .ps1 or .bat

---

## ✨ Features

* ⚡ **Fast module enumeration** using native Win32 APIs  
  (`EnumProcesses`, `EnumProcessModulesEx`, `GetModuleFileNameEx`)
* 🧠 **Flexible matching**
  * Filename only: `ntdll.dll`
  * Full path with wildcards: `C:\Windows\System32\msp*.dll`
* 🖥️ **Local and remote scanning**
  * PowerShell Remoting for execution
  * Fast reachability check via **TCP 445 (SMB)** before connecting
* 🧵 **Parallel execution**
* 🗂️ **Sorted output**, readable directly in console
* 🧱 **Single file**: runnable as `.bat`, `.cmd`, or `.ps1`

---

## 🧾 Output

<img width="979" height="512" alt="image" src="https://github.com/user-attachments/assets/3918560b-a354-4184-8eb0-b95ddf639d65" />

---

## 🔧 Parameters

### `-DllPatterns <string[]>` (mandatory)
One or more wildcard patterns describing DLLs to search for.

Accepted forms:
* Filename only  
  `bcrypt.dll`
* Full or partial path with wildcards  
  `C:\Windows\System32\api-ms-win-*.dll`

Matching logic automatically switches between filename-only and full-path mode.

---

### `-ComputerNames <string[]>` (optional)
List of computers to scan.

* Defaults to the **local machine**
* Supports hostnames and IP addresses
* Each target is first tested on **TCP port 445**
  * Unreachable hosts are reported and skipped
* Order is preserved in output

---

### `-Credential <PSCredential>` (optional)
Credentials used for remote execution.

* Automatically prompted **only if needed**
  * Triggered when at least one target is an IP address
* Reused across hosts
* Reset automatically if access is denied on a remote system

---

### `-MaxThreads <int>` (optional, default: `10`)
Maximum number of parallel runspaces.

* Controls how many computers are scanned simultaneously
* Higher values increase speed but also CPU and memory usage
* Safe default for mixed local / remote environments

---

### `-SortingTimeout <int>` (optional, default: `6`)
Maximum time (in seconds) to wait before forcing ordered output.

* Results are displayed **in the same order as `-ComputerNames`**
* If some hosts are slow, output continues once the timeout is reached
* Prevents the console from blocking on long-running machines

---

## 🧪 Examples

**Search multiple DLL patterns locally**
```powershell
Find-ProcessByDll -DllPatterns dbghelp*.dll,api-ms-win-*.dll
````

**Scan multiple remote computers**

```powershell
Find-ProcessByDll -DllPatterns bcrypt.dll -ComputerNames PC01,PC02
```

**Limit concurrency**

```powershell
Find-ProcessByDll -DllPatterns ntdll.dll -MaxThreads 4
```

---

## 📦 Requirements

* PowerShell 3.0+
* **Remote scans** require WinRM / PowerShell Remoting enabled
* Best results when run **as Administrator**
  (some processes hide loaded modules otherwise)

---

## 🧠 Notes

* Uses native APIs instead of `Get-Process -Module` for performance and reliability
* Works without external tools, WMI dependencies are minimized
* Designed for troubleshooting, incident response, and low-level diagnostics

---
