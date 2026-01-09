<#
.SYNOPSIS
    Suspends BitLocker protection on a specified computer or list of computers.

.DESCRIPTION
    This script suspends BitLocker protection for a specified number of reboots on target computer(s).
    Requires administrative privileges to execute.

.PARAMETER ComputerName
    The hostname or IP address of the target computer. Defaults to local computer.

.PARAMETER ComputerList
    An array of computer names or a file path containing computer names (one per line).

.PARAMETER RebootCount
    The number of reboots to suspend BitLocker protection for. Defaults to 1.

.PARAMETER DelaySeconds
    Optional delay (in seconds) before suspending BitLocker. Useful for scheduled operations.

.PARAMETER EnableLogging
    Enables detailed logging to file. Without this flag, only brief console messages are shown.

.PARAMETER LogPath
    The path where the log file will be saved. Defaults to user's Documents folder.

.EXAMPLE
    .\SuspendBitlocker.ps1 -ComputerName "WORKSTATION01" -RebootCount 2
    Suspends BitLocker on WORKSTATION01 for 2 reboots.

.EXAMPLE
    .\SuspendBitlocker.ps1 -RebootCount 3
    Suspends BitLocker on the local computer for 3 reboots.

.EXAMPLE
    .\SuspendBitlocker.ps1 -ComputerList "PC01","PC02","PC03" -RebootCount 1
    Suspends BitLocker on multiple computers for 1 reboot.

.EXAMPLE
    .\SuspendBitlocker.ps1 -ComputerList "C:\computers.txt" -RebootCount 2
    Suspends BitLocker on all computers listed in the file for 2 reboots.

.EXAMPLE
    .\SuspendBitlocker.ps1 -ComputerName "SERVER01" -RebootCount 1 -DelaySeconds 300
    Waits 5 minutes before suspending BitLocker on SERVER01.

.NOTES
    Author: IT Administrator
    Requires: PowerShell 4.0+, Administrative privileges, BitLocker enabled system, Windows OS
    Compatible: Windows PowerShell 4.0, 5.0, 5.1 and PowerShell 7+ on Windows
#>

[CmdletBinding(DefaultParameterSetName='Single')]
param(
    [Parameter(Mandatory=$false, ParameterSetName='Single')]
    [string]$ComputerName = $env:COMPUTERNAME,

    [Parameter(Mandatory=$true, ParameterSetName='Multiple')]
    [string[]]$ComputerList,

    [Parameter(Mandatory=$false)]
    [ValidateRange(1,15)]
    [int]$RebootCount = 1,

    [Parameter(Mandatory=$false)]
    [ValidateRange(0,86400)]
    [int]$DelaySeconds = 0,

    [Parameter(Mandatory=$false)]
    [switch]$EnableLogging,

    [Parameter(Mandatory=$false)]
    [string]$LogPath = [Environment]::GetFolderPath('MyDocuments'),

    [Parameter(Mandatory=$false)]
    [switch]$Help
)

# ============================================================================
# Functions
# ============================================================================

function Show-Help {
    <#
    .SYNOPSIS
        Displays custom formatted help information for the script.
    #>

    Write-Host ""
    Write-Host "================================================================================" -ForegroundColor Cyan
    Write-Host "  BitLocker Suspension Script" -ForegroundColor Cyan
    Write-Host "================================================================================" -ForegroundColor Cyan
    Write-Host ""
    Write-Host "DESCRIPTION:" -ForegroundColor Yellow
    Write-Host "  Suspends BitLocker protection for a specified number of reboots on target"
    Write-Host "  computer(s). Requires administrative privileges to execute."
    Write-Host ""

    Write-Host "PARAMETERS:" -ForegroundColor Yellow
    Write-Host "  -ComputerName <string>" -ForegroundColor Green
    Write-Host "      The hostname or IP address of the target computer."
    Write-Host "      Default: Local computer"
    Write-Host ""
    Write-Host "  -ComputerList <string[]>" -ForegroundColor Green
    Write-Host "      An array of computer names or a file path containing computer names"
    Write-Host "      (one per line). Mutually exclusive with -ComputerName."
    Write-Host ""
    Write-Host "  -RebootCount <int>" -ForegroundColor Green
    Write-Host "      The number of reboots to suspend BitLocker protection for."
    Write-Host "      Valid range: 1-15"
    Write-Host "      Default: 1"
    Write-Host ""
    Write-Host "  -DelaySeconds <int>" -ForegroundColor Green
    Write-Host "      Optional delay (in seconds) before suspending BitLocker."
    Write-Host "      Valid range: 0-86400 (up to 24 hours)"
    Write-Host "      Default: 0 (no delay)"
    Write-Host ""
    Write-Host "  -EnableLogging" -ForegroundColor Green
    Write-Host "      Enables detailed logging to file. Without this flag, only brief"
    Write-Host "      console messages are shown."
    Write-Host ""
    Write-Host "  -LogPath <string>" -ForegroundColor Green
    Write-Host "      The path where the log file will be saved."
    Write-Host "      Default: User's Documents folder"
    Write-Host ""
    Write-Host "  -Help" -ForegroundColor Green
    Write-Host "      Displays this help message."
    Write-Host ""

    Write-Host "EXAMPLES:" -ForegroundColor Yellow
    Write-Host "  Example 1: Display help" -ForegroundColor Cyan
    Write-Host "    .\SuspendBitlocker.ps1"
    Write-Host "    .\SuspendBitlocker.ps1 -Help"
    Write-Host ""
    Write-Host "  Example 2: Suspend BitLocker on local computer" -ForegroundColor Cyan
    Write-Host "    .\SuspendBitlocker.ps1 -RebootCount 2"
    Write-Host ""
    Write-Host "  Example 3: Suspend BitLocker on a remote computer" -ForegroundColor Cyan
    Write-Host "    .\SuspendBitlocker.ps1 -ComputerName ""SERVER01"" -RebootCount 1"
    Write-Host ""
    Write-Host "  Example 4: Suspend BitLocker on multiple computers" -ForegroundColor Cyan
    Write-Host "    .\SuspendBitlocker.ps1 -ComputerList ""PC01"",""PC02"",""PC03"" -RebootCount 2"
    Write-Host ""
    Write-Host "  Example 5: Suspend BitLocker from a file list" -ForegroundColor Cyan
    Write-Host "    .\SuspendBitlocker.ps1 -ComputerList ""C:\computers.txt"" -RebootCount 1"
    Write-Host ""
    Write-Host "  Example 6: Suspend BitLocker with a delay" -ForegroundColor Cyan
    Write-Host "    .\SuspendBitlocker.ps1 -ComputerName ""SERVER01"" -DelaySeconds 300"
    Write-Host ""

    Write-Host "VALIDATION CHECKS:" -ForegroundColor Yellow
    Write-Host "  The script performs the following checks before suspending BitLocker:"
    Write-Host "    1. Administrator privileges"
    Write-Host "    2. Hostname validation (DNS resolution)"
    Write-Host "    3. Network connectivity (ping test)"
    Write-Host "    4. Remote PowerShell connection (WinRM)"
    Write-Host "    5. BitLocker capability"
    Write-Host "    6. Pending reboot detection (warning only)"
    Write-Host ""

    Write-Host "NOTES:" -ForegroundColor Yellow
    Write-Host "  - Requires PowerShell 4.0 or higher (Windows PowerShell or PowerShell 7+ on Windows)"
    Write-Host "  - This script must be run with administrator privileges"
    Write-Host "  - Remote computers require PowerShell remoting (WinRM) to be enabled"
    Write-Host "  - Brief console messages by default; use -EnableLogging for detailed file logs"
    Write-Host "  - Log files saved to Documents folder (customize with -LogPath)"
    Write-Host "  - Use Ctrl+C to cancel during the delay countdown"
    Write-Host ""
    Write-Host "================================================================================" -ForegroundColor Cyan
    Write-Host ""
}

function Write-Log {
    <#
    .SYNOPSIS
        Writes a message to the log file and console.
    #>
    param(
        [Parameter(Mandatory=$true)]
        [string]$Message,

        [Parameter(Mandatory=$false)]
        [ValidateSet('Info','Warning','Error','Success')]
        [string]$Level = 'Info',

        [Parameter(Mandatory=$false)]
        [switch]$Silent
    )

    # Write to log file if logging is enabled
    if ($script:EnableLogging) {
        $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
        $logMessage = "[$timestamp] [$Level] $Message"
        Add-Content -Path $script:LogFile -Value $logMessage
    }

    # Write to console with brief format (unless Silent)
    if (-not $Silent) {
        switch ($Level) {
            'Info'    { Write-Host $Message -ForegroundColor White }
            'Warning' { Write-Host $Message -ForegroundColor Yellow }
            'Error'   { Write-Host $Message -ForegroundColor Red }
            'Success' { Write-Host $Message -ForegroundColor Green }
        }
    }
}

function Test-Administrator {
    <#
    .SYNOPSIS
        Checks if the current user has administrator privileges.
    #>
    $currentUser = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = New-Object Security.Principal.WindowsPrincipal($currentUser)
    return $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

function Test-HostnameValid {
    <#
    .SYNOPSIS
        Validates that the hostname is reachable.
    #>
    param(
        [Parameter(Mandatory=$true)]
        [string]$Hostname
    )

    Write-Log "Validating hostname: $Hostname" -Level Info -Silent

    # Check if hostname resolves
    try {
        $null = [System.Net.Dns]::GetHostEntry($Hostname)
        Write-Log "Hostname '$Hostname' is valid and reachable" -Level Success -Silent
        return $true
    }
    catch {
        Write-Log "Hostname '$Hostname' could not be resolved: $($_.Exception.Message)" -Level Error -Silent
        return $false
    }
}

function Test-Connectivity {
    <#
    .SYNOPSIS
        Tests network connectivity to the target computer using ping.
    #>
    param(
        [Parameter(Mandatory=$true)]
        [string]$Computer
    )

    # Skip check for local computer
    if ($Computer -eq $env:COMPUTERNAME) {
        return $true
    }

    Write-Log "Testing network connectivity to $Computer" -Level Info -Silent

    try {
        $pingResult = Test-Connection -ComputerName $Computer -Count 2 -Quiet -ErrorAction Stop

        if ($pingResult) {
            Write-Log "Network connectivity to $Computer confirmed" -Level Success -Silent
            return $true
        }
        else {
            Write-Log "Cannot ping $Computer - host may be offline or blocking ICMP" -Level Error -Silent
            return $false
        }
    }
    catch {
        Write-Log "Network connectivity test to $Computer failed: $($_.Exception.Message)" -Level Error -Silent
        return $false
    }
}

function Test-BitLockerCapability {
    <#
    .SYNOPSIS
        Checks if BitLocker is available on the target system.
    #>
    param(
        [Parameter(Mandatory=$true)]
        [string]$Computer
    )

    Write-Log "Checking BitLocker capability on $Computer" -Level Info -Silent

    try {
        if ($Computer -eq $env:COMPUTERNAME) {
            $null = Get-BitLockerVolume -ErrorAction Stop
        }
        else {
            $null = Invoke-Command -ComputerName $Computer -ScriptBlock {
                Get-BitLockerVolume
            } -ErrorAction Stop
        }

        Write-Log "BitLocker is available on $Computer" -Level Success -Silent
        return $true
    }
    catch {
        Write-Log "BitLocker is not available on $Computer`: $($_.Exception.Message)" -Level Error -Silent
        return $false
    }
}

function Test-RemoteConnection {
    <#
    .SYNOPSIS
        Tests if remote PowerShell connection is available for remote computers.
    #>
    param(
        [Parameter(Mandatory=$true)]
        [string]$Computer
    )

    # Skip check for local computer
    if ($Computer -eq $env:COMPUTERNAME) {
        return $true
    }

    Write-Log "Testing remote connection to $Computer" -Level Info -Silent

    try {
        $null = Test-WSMan -ComputerName $Computer -ErrorAction Stop
        Write-Log "Remote connection to $Computer is available" -Level Success -Silent
        return $true
    }
    catch {
        Write-Log "Remote connection to $Computer failed: $($_.Exception.Message)" -Level Error -Silent
        Write-Log "Ensure WinRM is enabled on the remote computer" -Level Warning -Silent
        return $false
    }
}

function Test-PendingReboot {
    <#
    .SYNOPSIS
        Checks if the system has a pending reboot.
    #>
    param(
        [Parameter(Mandatory=$true)]
        [string]$Computer
    )

    Write-Log "Checking for pending reboot on $Computer" -Level Info -Silent

    try {
        if ($Computer -eq $env:COMPUTERNAME) {
            $cbsReboot = Test-Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Component Based Servicing\RebootPending"
            $wuReboot = Test-Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\RebootRequired"
        }
        else {
            $cbsReboot = Invoke-Command -ComputerName $Computer -ScriptBlock {
                Test-Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Component Based Servicing\RebootPending"
            } -ErrorAction Stop
            $wuReboot = Invoke-Command -ComputerName $Computer -ScriptBlock {
                Test-Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\RebootRequired"
            } -ErrorAction Stop
        }

        if ($cbsReboot -or $wuReboot) {
            Write-Log "Pending reboot detected on $Computer" -Level Warning -Silent
            return $true
        }
        else {
            Write-Log "No pending reboot on $Computer" -Level Info -Silent
            return $false
        }
    }
    catch {
        Write-Log "Could not check pending reboot status: $($_.Exception.Message)" -Level Warning -Silent
        return $false
    }
}

function Suspend-BitLockerProtection {
    <#
    .SYNOPSIS
        Suspends BitLocker protection for the specified number of reboots.
    #>
    param(
        [Parameter(Mandatory=$true)]
        [string]$Computer,

        [Parameter(Mandatory=$true)]
        [int]$Reboots
    )

    Write-Log "Attempting to suspend BitLocker on $Computer for $Reboots reboot(s)" -Level Info -Silent

    try {
        # Get BitLocker volumes
        if ($Computer -eq $env:COMPUTERNAME) {
            $volumes = Get-BitLockerVolume -ErrorAction Stop
        }
        else {
            $volumes = Invoke-Command -ComputerName $Computer -ScriptBlock {
                Get-BitLockerVolume
            } -ErrorAction Stop
        }

        $suspended = $false

        foreach ($volume in $volumes) {
            if ($volume.ProtectionStatus -eq 'On') {
                Write-Log "Processing volume: $($volume.MountPoint)" -Level Info -Silent

                if ($Computer -eq $env:COMPUTERNAME) {
                    Suspend-BitLocker -MountPoint $volume.MountPoint -RebootCount $Reboots -ErrorAction Stop
                }
                else {
                    Invoke-Command -ComputerName $Computer -ScriptBlock {
                        param($mountPoint, $rebootCount)
                        Suspend-BitLocker -MountPoint $mountPoint -RebootCount $rebootCount
                    } -ArgumentList $volume.MountPoint, $Reboots -ErrorAction Stop
                }

                Write-Log "Successfully suspended BitLocker on volume $($volume.MountPoint) for $Reboots reboot(s)" -Level Success -Silent
                $suspended = $true
            }
            else {
                Write-Log "BitLocker is not active on volume $($volume.MountPoint), skipping" -Level Warning -Silent
            }
        }

        if (-not $suspended) {
            Write-Log "No active BitLocker volumes found to suspend" -Level Warning -Silent
            return $false
        }

        return $true
    }
    catch {
        Write-Log "Failed to suspend BitLocker: $($_.Exception.Message)" -Level Error -Silent
        return $false
    }
}

# ============================================================================
# Main
# ============================================================================

# Show help if no parameters provided or -Help specified
if ($PSBoundParameters.Count -eq 0 -or $Help) {
    Show-Help
    exit 0
}

# Check PowerShell version compatibility
$requiredVersion = [Version]"4.0"
$currentVersion = $PSVersionTable.PSVersion

if ($currentVersion -lt $requiredVersion) {
    Write-Host "ERROR: This script requires PowerShell version $requiredVersion or higher." -ForegroundColor Red
    Write-Host "Current version: $currentVersion" -ForegroundColor Red
    Write-Host "Please upgrade PowerShell to continue." -ForegroundColor Yellow
    exit 1
}

# Check if running on Windows (BitLocker is Windows-only)
# The $IsWindows variable only exists in PowerShell Core 6+
if ($PSVersionTable.PSVersion.Major -ge 6 -and (Get-Variable -Name IsWindows -ErrorAction SilentlyContinue)) {
    if (-not $IsWindows) {
        Write-Host "ERROR: This script requires Windows operating system." -ForegroundColor Red
        Write-Host "BitLocker is only available on Windows." -ForegroundColor Yellow
        exit 1
    }
}

# Set script-level logging flag
$script:EnableLogging = $EnableLogging

# Initialize logging if enabled
if ($EnableLogging) {
    $script:LogFile = Join-Path -Path $LogPath -ChildPath "SuspendBitlocker_$(Get-Date -Format 'yyyyMMdd_HHmmss').log"
    Write-Host "Logging enabled: $($script:LogFile)" -ForegroundColor Cyan
    Write-Log "========================================" -Level Info -Silent
    Write-Log "BitLocker Suspension Script Started" -Level Info -Silent
    Write-Log "========================================" -Level Info -Silent
}

Write-Host "BitLocker Suspension Script" -ForegroundColor Cyan

# Check if user is administrator
if (-not (Test-Administrator)) {
    Write-Log "This script must be run with administrator privileges" -Level Error
    exit 1
}

Write-Log "Administrator check: OK" -Level Success

# Build list of computers to process
$computersToProcess = @()

if ($PSCmdlet.ParameterSetName -eq 'Multiple') {
    # Check if ComputerList is a file path
    if ($ComputerList.Count -eq 1 -and (Test-Path $ComputerList[0] -PathType Leaf)) {
        Write-Log "Loading computer list from file..." -Level Info
        try {
            $computersToProcess = Get-Content -Path $ComputerList[0] | Where-Object { $_.Trim() -ne '' }
            Write-Log "Loaded $($computersToProcess.Count) computer(s)" -Level Success
        }
        catch {
            Write-Log "Failed to read computer list: $($_.Exception.Message)" -Level Error
            exit 1
        }
    }
    else {
        $computersToProcess = $ComputerList
        Write-Log "Processing $($computersToProcess.Count) computer(s)" -Level Info
    }
}
else {
    $computersToProcess = @($ComputerName)
    Write-Log "Target: $ComputerName | Reboots: $RebootCount" -Level Info
}

# Apply delay if specified
if ($DelaySeconds -gt 0) {
    Write-Log "Waiting $DelaySeconds seconds..." -Level Warning
    $endTime = (Get-Date).AddSeconds($DelaySeconds)

    while ((Get-Date) -lt $endTime) {
        $remaining = [math]::Round(($endTime - (Get-Date)).TotalSeconds)
        Write-Progress -Activity "Waiting before BitLocker suspension" -Status "$remaining seconds remaining" -PercentComplete ((($DelaySeconds - $remaining) / $DelaySeconds) * 100)
        Start-Sleep -Seconds 1
    }
    Write-Progress -Activity "Waiting before BitLocker suspension" -Completed
    Write-Log "Delay complete" -Level Success
}

# Track results
$successCount = 0
$failureCount = 0
$results = @()

# Process each computer
foreach ($computer in $computersToProcess) {
    $computer = $computer.Trim()

    if ([string]::IsNullOrWhiteSpace($computer)) {
        continue
    }

    Write-Log "Processing: $computer" -Level Info

    # Check to make sure the hostname is valid
    if (-not (Test-HostnameValid -Hostname $computer)) {
        Write-Log "  FAILED: Invalid hostname" -Level Error
        $failureCount++
        $results += [PSCustomObject]@{
            ComputerName = $computer
            Status = "Failed"
            Reason = "Invalid hostname"
        }
        continue
    }

    # Test network connectivity
    if (-not (Test-Connectivity -Computer $computer)) {
        Write-Log "  FAILED: No network connectivity" -Level Error
        $failureCount++
        $results += [PSCustomObject]@{
            ComputerName = $computer
            Status = "Failed"
            Reason = "Network connectivity failed"
        }
        continue
    }

    # Check remote connection for non-local computers
    if (-not (Test-RemoteConnection -Computer $computer)) {
        Write-Log "  FAILED: Remote connection unavailable" -Level Error
        $failureCount++
        $results += [PSCustomObject]@{
            ComputerName = $computer
            Status = "Failed"
            Reason = "Remote connection unavailable"
        }
        continue
    }

    # Check BitLocker capability
    if (-not (Test-BitLockerCapability -Computer $computer)) {
        Write-Log "  FAILED: BitLocker not available" -Level Error
        $failureCount++
        $results += [PSCustomObject]@{
            ComputerName = $computer
            Status = "Failed"
            Reason = "BitLocker not available"
        }
        continue
    }

    # Check for pending reboot (warning only, does not block)
    $pendingReboot = Test-PendingReboot -Computer $computer
    if ($pendingReboot) {
        Write-Log "  WARNING: Pending reboot detected" -Level Warning
    }

    # Disable BitLocker (for a given number of reboots)
    $result = Suspend-BitLockerProtection -Computer $computer -Reboots $RebootCount

    if ($result) {
        Write-Log "  SUCCESS: BitLocker suspended for $RebootCount reboot(s)" -Level Success
        $successCount++
        $results += [PSCustomObject]@{
            ComputerName = $computer
            Status = "Success"
            Reason = "BitLocker suspended for $RebootCount reboot(s)"
        }
    }
    else {
        Write-Log "  FAILED: Could not suspend BitLocker" -Level Error
        $failureCount++
        $results += [PSCustomObject]@{
            ComputerName = $computer
            Status = "Failed"
            Reason = "BitLocker suspension failed or no action taken"
        }
    }
}

# Write summary
Write-Host ""
Write-Log "Summary: $successCount succeeded, $failureCount failed" -Level $(if ($failureCount -gt 0) { "Warning" } else { "Success" })

# Exit with appropriate code
if ($failureCount -gt 0) {
    exit 1
}
else {
    exit 0
}
