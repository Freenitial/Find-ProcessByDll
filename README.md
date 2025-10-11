# Find-ProcessByDll 🔎🧩

Scanner to find **which running processes have loaded specific DLLs** — locally or across remote Windows machines. Hybrid **BAT+PowerShell single file**, zero dependencies, pure Win32 P/Invoke for speed.

---

## ✨ Features

* ⚡ **Blazing fast** process & module enumeration via Win32: `EnumProcesses`, `EnumProcessModulesEx`, `GetModuleFileNameEx`
* 🧠 **Smart matching**: filename-only (`mspmsnsv.dll`) **or** full-path wildcards (`C:\Windows\System32\msp*.dll`)
* 🖥️ **Local & Remote** scanning (PowerShell Remoting). Connectivity is fast checked on **SMB 445** first
* 🗂️ **Deduplicated, sorted output** readable in console
* 🧱 **Single file** (hybrid launcher). Run it as `.cmd` or `.ps1` — same tool, your call

---

## 🧾 Output

<img width="979" height="512" alt="image" src="https://github.com/user-attachments/assets/3918560b-a354-4184-8eb0-b95ddf639d65" />

---

## 🔧 Usage

```batch
Find-ProcessByDll.bat -DllPatterns <string[]> [-TargetComputerNames <string[]>]
```

```powershell
.\Find-ProcessByDll.ps1 -DllPatterns <string[]> [-TargetComputerNames <string[]>]
```

```
Or just copy paste the function in your console, then call directly Find-ProcessByDll
```

---

## 🧪 Examples

**Multiple patterns at once**

```powershell
.\Find-ProcessByDll.ps1 -DllPatterns dbghelp*.dll,api-ms-win-*.dll
```

**Scan multiple remote hosts**

```powershell
.\Find-ProcessByDll.ps1 -DllPatterns bcrypt.dll -TargetComputerNames PC01,PC02
```

---

## 📦 Requirements

* PowerShell 3.0+ recommended
* **Remote** scans: PowerShell Remoting/WinRM enabled on targets
* Best run **as Administrator** for complete module visibility

---



