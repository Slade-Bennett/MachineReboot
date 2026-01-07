# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

This repository contains BitLocker management scripts for Windows disk encryption. The primary script is `SuspendBitlocker.ps1`, which suspends BitLocker protection on local or remote computers for a specified number of reboots.

## Script Architecture

### SuspendBitlocker.ps1 Structure

The script follows a modular function-based architecture:

1. **Parameter Sets**: Uses PowerShell parameter sets to handle single computer (`-ComputerName`) or multiple computers (`-ComputerList`)
2. **Helper Functions**: Organized into validation, logging, and execution functions
3. **Validation Pipeline**: Each computer goes through multiple validation checks before BitLocker suspension
4. **Comprehensive Logging**: All actions are logged to timestamped files with color-coded console output

### Key Functions

**Display & Logging**
- `Show-Help`: Custom formatted help display with color-coded sections
- `Write-Log`: Centralized logging with timestamps and level-based color coding (Info/Warning/Error/Success)

**Validation Functions**
- `Test-Administrator`: Verifies script is running with admin privileges
- `Test-HostnameValid`: DNS resolution check for target computers
- `Test-Connectivity`: Network ping test to verify host is reachable
- `Test-RemoteConnection`: WinRM/PowerShell remoting availability check
- `Test-BitLockerCapability`: Verifies BitLocker is available on target system
- `Test-PendingReboot`: Detects pending system reboots (warning only, non-blocking)

**Core Functionality**
- `Suspend-BitLockerProtection`: Main function that suspends BitLocker on all protected volumes

### Validation Pipeline

For each target computer, the script performs checks in this order:
1. Hostname validation (DNS resolution)
2. Network connectivity (ping test)
3. Remote connection capability (WinRM for remote computers)
4. BitLocker availability
5. Pending reboot detection (warning only)
6. BitLocker suspension execution

If any blocking check fails, the computer is skipped with detailed error logging.

## Common Usage Patterns

### Running the Script

Display help:
```powershell
.\SuspendBitlocker.ps1
.\SuspendBitlocker.ps1 -Help
```

Suspend BitLocker on local computer:
```powershell
.\SuspendBitlocker.ps1 -RebootCount 2
```

Suspend on remote computer:
```powershell
.\SuspendBitlocker.ps1 -ComputerName "SERVER01" -RebootCount 1
```

Suspend on multiple computers:
```powershell
.\SuspendBitlocker.ps1 -ComputerList "PC01","PC02","PC03" -RebootCount 2
```

Suspend from file list:
```powershell
.\SuspendBitlocker.ps1 -ComputerList "C:\computers.txt" -RebootCount 1
```

With delay:
```powershell
.\SuspendBitlocker.ps1 -ComputerName "SERVER01" -DelaySeconds 300 -RebootCount 1
```

## Code Conventions

### Error Handling
- All BitLocker operations use `try/catch` blocks with `-ErrorAction Stop`
- Unused command outputs are assigned to `$null` to suppress output
- Failed operations log detailed error messages and continue processing remaining computers

### Remote vs Local Execution
- Functions check if target is local computer (`$Computer -eq $env:COMPUTERNAME`)
- Local operations execute commands directly
- Remote operations use `Invoke-Command` with scriptblocks

### Logging
- Log files created automatically with timestamp format: `SuspendBitlocker_yyyyMMdd_HHmmss.log`
- All log entries include timestamp, level, and message
- Console output uses color coding for better visibility

### Parameter Validation
- `RebootCount`: 1-15 reboots (PowerShell ValidateRange)
- `DelaySeconds`: 0-86400 seconds / 24 hours max (PowerShell ValidateRange)
- Parameter sets prevent conflicting parameters (`-ComputerName` vs `-ComputerList`)

## Requirements

- PowerShell 4.0 or higher (Windows PowerShell 4.0/5.0/5.1 or PowerShell 7+ on Windows)
- Windows operating system (BitLocker is Windows-only)
- Administrator privileges required
- For remote computers: WinRM/PowerShell remoting must be enabled
- BitLocker must be available on target systems (Windows 8/Server 2012 or later)
- Network connectivity to remote systems

### Version Compatibility Notes

The script includes automatic version checking:
- Minimum version: PowerShell 4.0
- Works with both Windows PowerShell (powershell.exe) and PowerShell 7+ (pwsh.exe) on Windows
- Blocks execution on non-Windows platforms (Linux/macOS) since BitLocker is Windows-only
- All cmdlets and parameters used are compatible across PowerShell 4.0 through 7+

## File Formats

### Computer List File Format
Plain text file with one hostname per line:
```
WORKSTATION01
WORKSTATION02
SERVER01
```

Empty lines are automatically skipped.