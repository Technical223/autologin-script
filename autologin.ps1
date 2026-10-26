<#
  Windows autologin without a password (local account).
    .\autologin.ps1          enable
    .\autologin.ps1 -Undo    disable autologin again
  Log: %TEMP%\autologin.log
#>
param([switch]$Undo, [switch]$Pause)

# Relaunch as administrator if needed
$me = [Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()
if (-not $me.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    $argList = "-NoProfile -ExecutionPolicy Bypass -File `"$PSCommandPath`" -Pause"
    if ($Undo) { $argList += ' -Undo' }
    Start-Process powershell -Verb RunAs -ArgumentList $argList
    exit
}

$ErrorActionPreference = 'Stop'
$log = "$env:TEMP\autologin.log"
function Say($msg) { Write-Host $msg; Add-Content $log "$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss') $msg" }

$reg = 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon'

try {
    if ($Undo) {
        Set-ItemProperty $reg AutoAdminLogon '0'
        Say 'Autologin disabled. Set a password again: Ctrl+Alt+Del > Change a password.'
        return
    }

    # Logged-in user (console session), falls back to the user running the script
    $user = (Get-CimInstance Win32_ComputerSystem).UserName
    $user = if ($user) { $user.Split('\')[-1] } else { $env:USERNAME }
    Say "User: $user"

    # 1) Allow an empty password (min. length 0, no complexity)
    $cfg = "$env:TEMP\secpol.cfg"; $db = "$env:TEMP\secpol.sdb"
    secedit /export /cfg $cfg | Out-Null
    (Get-Content $cfg) -replace 'MinimumPasswordLength = \d+', 'MinimumPasswordLength = 0' -replace 'PasswordComplexity = \d+', 'PasswordComplexity = 0' |
        Set-Content $cfg
    secedit /configure /db $db /cfg $cfg /areas SECURITYPOLICY | Out-Null
    Remove-Item $cfg, $db -ErrorAction SilentlyContinue
    Say 'Password policy: empty password allowed'

    # 2) Remove the user's password
    ([ADSI]"WinNT://$env:COMPUTERNAME/$user,user").SetPassword('')
    Say 'Password removed'

    # 3) Autologin
    Set-ItemProperty $reg DefaultUserName   $user
    Set-ItemProperty $reg DefaultDomainName $env:COMPUTERNAME
    Set-ItemProperty $reg AutoAdminLogon    '1'
    Remove-ItemProperty $reg DefaultPassword, AutoLogonCount -ErrorAction SilentlyContinue
    Say "Done. $user will be logged in automatically after restart."
}
catch {
    Say "ERROR: $_"
    exit 1
}
finally {
    if ($Pause) { Read-Host 'Press Enter to close' | Out-Null }
}
