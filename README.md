# BitLocker Suspension Script

A PowerShell script for suspending BitLocker protection on local or remote Windows computers for a specified number of reboots.

## Features

- **Single or Multiple Computers**: Suspend BitLocker on one computer or batch process multiple systems
- **File-Based Input**: Process computer lists from text files
- **Comprehensive Validation**: Performs 6 validation checks before suspending BitLocker
- **Detailed Logging**: Timestamped logs with color-coded console output
- **Delay Support**: Optional delay before suspension for scheduled operations
- **Remote Execution**: Supports remote computers via PowerShell remoting

## Requirements

- PowerShell 4.0 or higher (Windows PowerShell or PowerShell 7+ on Windows)
- Administrator privileges
- Windows operating system
- For remote computers: WinRM/PowerShell remoting enabled
- BitLocker must be available on target systems

## Installation

1. Clone this repository or download `SuspendBitlocker.ps1`
2. Ensure PowerShell execution policy allows script execution:
   ```powershell
   Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope CurrentUser
   ```

## Usage

### Display Help
```powershell
.\SuspendBitlocker.ps1
.\SuspendBitlocker.ps1 -Help
```

### Suspend BitLocker on Local Computer
```powershell
.\SuspendBitlocker.ps1 -RebootCount 2
```

### Suspend BitLocker on Remote Computer
```powershell
.\SuspendBitlocker.ps1 -ComputerName "SERVER01" -RebootCount 1
```

### Suspend BitLocker on Multiple Computers
```powershell
.\SuspendBitlocker.ps1 -ComputerList "PC01","PC02","PC03" -RebootCount 2
```

### Suspend BitLocker from File List
Create a text file with one hostname per line, then run:
```powershell
.\SuspendBitlocker.ps1 -ComputerList "C:\computers.txt" -RebootCount 1
```

### Suspend with Delay
```powershell
.\SuspendBitlocker.ps1 -ComputerName "SERVER01" -DelaySeconds 300 -RebootCount 1
```

## Parameters

| Parameter | Type | Description | Default |
|-----------|------|-------------|---------|
| `-ComputerName` | string | Single computer hostname or IP | Local computer |
| `-ComputerList` | string[] | Array of computers or file path | N/A |
| `-RebootCount` | int | Number of reboots to suspend (1-15) | 1 |
| `-DelaySeconds` | int | Delay before suspension (0-86400) | 0 |
| `-LogPath` | string | Directory for log files | Script directory |
| `-Help` | switch | Display help message | N/A |

## Validation Checks

The script performs these checks for each computer:

1. **Administrator Privileges** - Verifies script is running as admin
2. **Hostname Validation** - DNS resolution check
3. **Network Connectivity** - Ping test
4. **Remote Connection** - WinRM/PowerShell remoting check (remote only)
5. **BitLocker Capability** - Verifies BitLocker is available
6. **Pending Reboot** - Detects pending reboots (warning only)

## Logging

Log files are automatically created with timestamps:
- Format: `SuspendBitlocker_yyyyMMdd_HHmmss.log`
- Location: Script directory (or specified via `-LogPath`)
- Includes: Timestamp, log level, and detailed messages

## Examples

### Example 1: Suspend on Local Computer for 3 Reboots
```powershell
.\SuspendBitlocker.ps1 -RebootCount 3
```

### Example 2: Suspend on Multiple Servers with 5-Minute Delay
```powershell
.\SuspendBitlocker.ps1 -ComputerList "SRV01","SRV02" -RebootCount 1 -DelaySeconds 300
```

### Example 3: Process Large Computer List from File
```powershell
.\SuspendBitlocker.ps1 -ComputerList "C:\IT\workstations.txt" -RebootCount 2
```

## Computer List File Format

Plain text file with one hostname per line:
```
WORKSTATION01
WORKSTATION02
SERVER01
```

Empty lines are automatically skipped.

## Error Handling

- Failed computers are skipped with detailed error logging
- Script continues processing remaining computers after failures
- Exit codes: 0 (success), 1 (failure)
- Summary report shows success/failure counts

## Security Notes

- Requires administrator privileges
- Suspending BitLocker temporarily disables drive encryption protection
- Only suspend BitLocker when necessary (e.g., BIOS updates, hardware changes)
- All operations are logged for audit purposes

## License

This project is provided as-is for IT administration purposes.

## Contributing

Feel free to submit issues or pull requests for improvements.

## Author

IT Administrator
