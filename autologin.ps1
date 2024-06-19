$logPath = "$env:TEMP\autologin_debug.log"
function Write-Log {
    param (
        [string]$message
    )
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    Add-Content -Path $logPath -Value "$timestamp - $message"
}

function Test-Admin {
    $currentPrincipal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
    $currentPrincipal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

Write-Log "Starting autologin script..."

if (-not (Test-Admin)) {
    Write-Log "Script was not run with administrative privileges."
    Write-Log "Please try running the script again with administrative privileges."
    exit 1
} else {
    Write-Log "Script is running with administrative privileges."
}

try {
    $currentUser = (Get-WmiObject -Class Win32_ComputerSystem | Select-Object -ExpandProperty UserName).Split('\')[1]
    Write-Log "Current user: $currentUser"

    $RegPath = "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon"
    Write-Log "Setting registry values for autologin"

    Set-ItemProperty -Path $RegPath -Name "DefaultUserName" -Value $currentUser -Type String
    Write-Log "Set DefaultUserName to $currentUser"

    Set-ItemProperty -Path $RegPath -Name "AutoAdminLogon" -Value "1" -Type String
    Write-Log "Set AutoAdminLogon to 1"

    if (Test-Path "$RegPath\DefaultPassword") {
        Remove-ItemProperty -Path $RegPath -Name "DefaultPassword"
        Write-Log "Removed DefaultPassword"
    }

    if (Test-Path "$RegPath\AutoLogonCount") {
        Remove-ItemProperty -Path $RegPath -Name "AutoLogonCount"
        Write-Log "Removed AutoLogonCount"
    }

    Write-Log "Autologin successfully set for current user $currentUser."

    Write-Log "Disabling password policies"
    secedit /export /cfg "C:\Windows\Temp\secpol.cfg"
    (Get-Content "C:\Windows\Temp\secpol.cfg") -replace 'MinimumPasswordLength = \d+', 'MinimumPasswordLength = 0' | Set-Content "C:\Windows\Temp\secpol.cfg"
    secedit /configure /db secedit.sdb /cfg "C:\Windows\Temp\secpol.cfg" /areas SECURITYPOLICY
    Remove-Item "C:\Windows\Temp\secpol.cfg"
    Write-Log "Minimum password length disabled"

    secedit /export /cfg "C:\Windows\Temp\secpol.cfg"
    (Get-Content "C:\Windows\Temp\secpol.cfg") -replace 'PasswordComplexity = \d+', 'PasswordComplexity = 0' | Set-Content "C:\Windows\Temp\secpol.cfg"
    secedit /configure /db secedit.sdb /cfg "C:\Windows\Temp\secpol.cfg" /areas SECURITYPOLICY
    Remove-Item "C:\Windows\Temp\secpol.cfg"
    Write-Log "Password complexity requirement disabled"

    Write-Log "Removing user password"
    net user $currentUser "" | Out-Null
    Write-Log "User password removed"

    Write-Log "Autologin script completed successfully."

} catch {
    Write-Log "An error occurred: $_"
    throw $_
}
