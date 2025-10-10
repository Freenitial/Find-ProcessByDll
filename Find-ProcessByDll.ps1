[CmdletBinding()]
param(
    [Parameter(Mandatory=$true, Position=0)][string[]]$DllPatterns,
    [Parameter(Mandatory=$false, Position=1)][string[]]$TargetComputerNames = @($env:COMPUTERNAME)
)

function Find-ProcessByDll {
    <#
    .SYNOPSIS
        Scan local or remote computers to detect running processes 
        that have loaded DLLs matching specified patterns.
    .PARAMETER DllPatterns
        One or more wildcard patterns representing DLL paths or filenames
        Example: -DllPatterns mspmsnsv.dll,"C:\Windows\System32\*.dll"
    .PARAMETER TargetComputerNames
        Optional. Array of computer names to scan. Defaults to the 
        current machine. Uses port 445 (SMB) to test connectivity 
        before attempting remote execution.
    .NOTES
        - Uses low-level API calls for performance (EnumProcesses, EnumProcessModulesEx).
        - Requires administrative rights on target machines for full results.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true, Position=0)][string[]]$DllPatterns,
        [Parameter(Mandatory=$false, Position=1)][string[]]$TargetComputerNames = @($env:COMPUTERNAME)
    )
    function Test-ComputerAvailable {
        param([Parameter(Mandatory=$true)][string]$ComputerName,[int]$TimeoutMilliseconds=500)
        $tcpClient = New-Object Net.Sockets.TcpClient
        try {
            $asyncConnect = $tcpClient.BeginConnect($ComputerName,445,$null,$null)
            if (-not $asyncConnect.AsyncWaitHandle.WaitOne($TimeoutMilliseconds,$false)) { $tcpClient.Close(); return $false }
            $null = $tcpClient.EndConnect($asyncConnect)
            $tcpClient.Close(); return $true
        } catch { $tcpClient.Close(); return $false }
    }
    if (-not $DllPatterns) { return }
    # --- C# code block with P/Invoke signatures for process/module enumeration ---
    $cSharpCode = @"
using System;
using System.Text;
using System.Runtime.InteropServices;
public static class Win32Api
{
    [Flags] public enum ProcessAccessFlags : uint { PROCESS_QUERY_INFORMATION=0x0400, PROCESS_VM_READ=0x0010 }
    [Flags] public enum ListModulesOptions : uint { LIST_MODULES_ALL=0x03 }
    [DllImport("kernel32.dll", SetLastError = true)] public static extern IntPtr OpenProcess(ProcessAccessFlags processAccess, bool bInheritHandle, int processId);
    [DllImport("kernel32.dll", SetLastError = true)] [return: MarshalAs(UnmanagedType.Bool)] public static extern bool CloseHandle(IntPtr hObject);
    [DllImport("psapi.dll", SetLastError = true)] public static extern bool EnumProcesses([MarshalAs(UnmanagedType.LPArray, ArraySubType = UnmanagedType.U4)] int[] processIds, int size, [MarshalAs(UnmanagedType.U4)] out int bytesReturned);
    [DllImport("psapi.dll", SetLastError = true)] public static extern bool EnumProcessModulesEx(IntPtr hProcess, [Out] IntPtr[] lphModule, int cb, [MarshalAs(UnmanagedType.U4)] out int lpcbNeeded, ListModulesOptions dwFilterFlag);
    [DllImport("psapi.dll", CharSet = CharSet.Auto, SetLastError = true)] public static extern uint GetModuleFileNameEx(IntPtr hProcess, IntPtr hModule, [Out] StringBuilder lpBaseName, uint nSize);
    [DllImport("kernel32.dll", CharSet = CharSet.Auto, SetLastError = true)] public static extern bool QueryFullProcessImageName(IntPtr hProcess, int flags, StringBuilder exeName, ref int size);
}
"@
    if (-not ([System.Management.Automation.PSTypeName]'Win32Api').Type) { 
        try { Add-Type -TypeDefinition $cSharpCode -ReferencedAssemblies 'System','System.Core' -ErrorAction Stop } catch { return } 
    }
    # --- ScriptBlock executed locally or remotely to perform the DLL scan ---
    $scanScript = {
        param([string[]]$DllPatternsLocal,[string]$CSharpSourceLocal)
        # Ensure Win32Api type is loaded inside remote sessions as well
        if (-not ([System.Management.Automation.PSTypeName]'Win32Api').Type) { 
            Add-Type -TypeDefinition $CSharpSourceLocal -ReferencedAssemblies 'System','System.Core' -ErrorAction Stop 
        }
        # Normalize patterns (decide if filename-only or full path matching)
        $dllPatternInfos = foreach ($pattern in $DllPatternsLocal) {
            if ($pattern) { 
                $trimmed=$pattern.Trim()
                if ($trimmed) { [pscustomobject]@{PatternLower=$trimmed.ToLowerInvariant();UseFileNameOnly=(-not ($trimmed -match '[\\/]' ))} } 
            }
        }
        if (-not $dllPatternInfos) { return @() }
        # Buffers and reusable objects for performance
        $modulePathSB=New-Object System.Text.StringBuilder 1024; $procPathSB=New-Object System.Text.StringBuilder 1024
        $pointerSize=[IntPtr]::Size; $moduleHandles=New-Object IntPtr[] 256; $processPathCache=@{}; $processIds=New-Object int[] 2048; $bytesReturned=0
        # Get all process IDs from system
        if (-not [Win32Api]::EnumProcesses($processIds,$processIds.Length*4,[ref]$bytesReturned)) { return }
        $processCount=[int]($bytesReturned/4)
        # Iterate processes
        for ($processIndex=0; $processIndex -lt $processCount; $processIndex++) {
            $processId=$processIds[$processIndex]; if ($processId -eq 0) { continue }
            $processHandle=[IntPtr]::Zero
            try {
                # Open process with query + VM read rights
                $accessRights=[Win32Api+ProcessAccessFlags]::PROCESS_QUERY_INFORMATION -bor [Win32Api+ProcessAccessFlags]::PROCESS_VM_READ
                $processHandle=[Win32Api]::OpenProcess($accessRights,$false,$processId)
                if ($processHandle -eq [IntPtr]::Zero) { continue }
                # Enumerate loaded modules
                $requiredBytes=0; $filterOption=[Win32Api+ListModulesOptions]::LIST_MODULES_ALL; $bufferBytes=$moduleHandles.Length*$pointerSize
                if (-not [Win32Api]::EnumProcessModulesEx($processHandle,$moduleHandles,$bufferBytes,[ref]$requiredBytes,$filterOption)) { continue }
                if ($requiredBytes -gt $bufferBytes) {
                    # Resize buffer if initial allocation insufficient
                    $moduleHandles=New-Object IntPtr[] ([int][math]::Ceiling($requiredBytes/[double]$pointerSize))
                    $bufferBytes=$moduleHandles.Length*$pointerSize
                    if (-not [Win32Api]::EnumProcessModulesEx($processHandle,$moduleHandles,$bufferBytes,[ref]$requiredBytes,$filterOption)) { continue }
                }
                $moduleCount=[int]($requiredBytes/$pointerSize)
                # Iterate all modules of this process
                for ($moduleIndex=0; $moduleIndex -lt $moduleCount; $moduleIndex++) {
                    $moduleHandle=$moduleHandles[$moduleIndex]
                    [void]$modulePathSB.Remove(0,$modulePathSB.Length)
                    [void][Win32Api]::GetModuleFileNameEx($processHandle,$moduleHandle,$modulePathSB,[uint32]$modulePathSB.Capacity)
                    $modulePath=$modulePathSB.ToString(); if ([string]::IsNullOrEmpty($modulePath)) { continue }
                    $modulePathLower=$modulePath.ToLowerInvariant(); $moduleFileLower=[System.IO.Path]::GetFileName($modulePathLower)
                    # Pattern matching (filename-only or full path)
                    $isMatch=$false
                    foreach ($info in $dllPatternInfos) {
                        if ($info.UseFileNameOnly) { if ($moduleFileLower -like $info.PatternLower) { $isMatch=$true; break } }
                        else                       { if ($modulePathLower -like $info.PatternLower) { $isMatch=$true; break } }
                    }
                    if (-not $isMatch) { continue }
                    # Retrieve cached process path or resolve via API/WMI
                    $processFullPath = $processPathCache[$processId]
                    if (-not $processFullPath) {
                        [void]$procPathSB.Remove(0,$procPathSB.Length)
                        $len = $procPathSB.Capacity
                        if ([Environment]::OSVersion.Version.Major -ge 6 -and [Win32Api]::QueryFullProcessImageName($processHandle, 0, $procPathSB, [ref]$len)) {
                            $processFullPath = $procPathSB.ToString()
                        } else {
                            try {
                                $wmi = Get-WmiObject -Class Win32_Process -Filter "ProcessId=$processId" -ErrorAction Stop
                                $processFullPath = if ($wmi.ExecutablePath) { $wmi.ExecutablePath } else { $wmi.Name }
                            } catch { $processFullPath = 'N/A' }
                        }
                        $processPathCache[$processId] = $processFullPath
                    }
                    # Output result as object
                    [pscustomobject]@{ ProcessFullPath=$processFullPath; DllFullPath=$modulePath }
                }
            } finally { if ($processHandle -ne [IntPtr]::Zero) { [void][Win32Api]::CloseHandle($processHandle) } }
        }
    }
    foreach ($computerName in $TargetComputerNames) {
        $results = $null
        if ($computerName -eq $env:COMPUTERNAME -or $computerName -eq 'localhost' -or $computerName -eq '.') {
            # Local execution
            $results = & $scanScript -DllPatternsLocal $DllPatterns -CSharpSourceLocal $cSharpCode
        } else {
            # Remote execution via PowerShell Remoting
            if (-not (Test-ComputerAvailable $computerName)) { continue }
            try {$results=Invoke-Command -ComputerName $computerName -ErrorAction Stop -ScriptBlock $scanScript -ArgumentList (,$DllPatterns),$cSharpCode} catch{continue}
        }
        # Display results
        Write-Host "`n`n========= $computerName ========="
        if ($results) {
            $index = 0
            foreach ($r in ($results | Sort-Object ProcessFullPath, DllFullPath -Unique)) {
                if ($index -gt 0) { Write-Host "-------" }
                Write-Host ("DLL     = {0}" -f $r.DllFullPath) -ForegroundColor Yellow
                Write-Host ("Process = {0}" -f $r.ProcessFullPath) -ForegroundColor Cyan
                $index++
            }
        } else { Write-Host "No matches." -ForegroundColor Gray }
    }
    Write-Host "`n"
}


Find-ProcessByDll $DllPatterns $TargetComputerNames
