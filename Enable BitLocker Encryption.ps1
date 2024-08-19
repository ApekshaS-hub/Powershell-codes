<#
.SYNOPSIS
Enables BitLocker encryption in the system drive.

.DESCRIPTION
Enables BitLocker encryption in the drive where the OS is installed. By using inputs parameters, you can choose the drive encryption type and the encryption method.
Take a look at the [https://docs.microsoft.com/en-us/windows/security/information-protection/bitlocker/bitlocker-overview official Microsoft documentation] to get more information about BitLocker capabilities.

.FUNCTIONALITY
Remediation

.INPUTS
ID  Label                           Description
1   EnforceADBackup                 If set to 'true' it will not trigger the encryption unless Active Directory backup GPO is enabled. If set to false it will always trigger the encryption and it will display a warning in case the GPO is disabled. Acceptable values are 'true' or 'false'
2   UsedSpaceOnly                   Defines drive encryption type used by BitLocker. To encrypt entire drive set to 'false'. Acceptable values are 'true' or 'false'. For more information, please visit [https://docs.microsoft.com/en-us/windows/security/information-protection/bitlocker/bitlocker-device-encryption-overview-windows-10 this link]
3   EncryptionMethod                Defines encryption method used by BitLocker. Acceptable values are 'Aes128', 'Aes256', 'XtsAes128' or 'XtsAes256'

.FURTHER INFORMATION
The TPM key protector is added automatically to the BitLocker volume once the encryption is enabled.
Furthermore, the script adds a random 48-digit recovery password which can be backed up and used for recovery data purposes in case of issues.
More information about key protectors at the [https://docs.microsoft.com/en-us/powershell/module/bitlocker/add-bitlockerkeyprotector?view=win10-ps official Microsoft page].
The encryption starts after device's reboot.

.RESTRICTIONS
- The device must have [https://docs.microsoft.com/en-us/windows/security/information-protection/tpm/trusted-platform-module-overview TPM] activated, enabled and owned.
- The encryption is only performed in the system drive.
- The system drive must be formatted with [https://docs.microsoft.com/en-us/windows-server/storage/file-server/ntfs-overview NTFS].

.NOTES
Context:            LocalSystem
Version:            3.0.1.0 - Fixed bug when the device is not fully decrypted
                    3.0.0.0 - Added new input called 'EncryptionMethod'
                    2.0.0.0 - Added new input called 'EnforceADBackup'
                    1.0.1.0 - Fixed documentation
                    1.0.0.0 - Initial release
Last Generated:     01 Jul 2022 - 10:54:38
Copyright (C) 2022 Nexthink SA, Switzerland
#>

#
# Input parameters definition
#
param(
    [Parameter(Mandatory = $true)][string]$EnforceADBackup,
    [Parameter(Mandatory = $true)][string]$UsedSpaceOnly,
    [Parameter(Mandatory = $true)][string]$EncryptionMethod
)
# End of parameters definition

$env:Path = "$env:SystemRoot\system32;$env:SystemRoot;$env:SystemRoot\System32\Wbem;$env:SystemRoot\System32\WindowsPowerShell\v1.0\"

#
# Constants definition
#
New-Variable -Name 'ERROR_EXCEPTION_TYPE' `
    -Value @{Environment = '[Environment error]'
             Input = '[Input error]'
             Internal = '[Internal error]'} `
    -Option ReadOnly -Scope Script
New-Variable -Name 'LOCAL_SYSTEM_IDENTITY' `
    -Value 'S-1-5-18' -Option ReadOnly -Scope Script
New-Variable -Name 'WINDOWS_VERSIONS' `
    -Value @{Windows7 = '6.1'
             Windows8 = '6.2'
             Windows81 = '6.3'
             Windows10 = '10.0'
             Windows11 = '10.0'} `
    -Option ReadOnly -Scope Script

$TPM_NAMESPACE = 'Root\CIMV2\Security\MicrosoftTpm'
Set-Variable -Name 'TPM_NAMESPACE' -Option ReadOnly -Scope Script -Force

$TPM_CLASS = 'Win32_Tpm'
Set-Variable -Name 'TPM_CLASS' -Option ReadOnly -Scope Script -Force

$ENCRYPTION_METHOD = @('Aes256', 'Aes128', 'XtsAes256', 'XtsAes128')
Set-Variable -Name 'ENCRYPTION_METHOD' -Option ReadOnly -Scope Script -Force

$AD_BACKUP_POLICY_KEY = 'OSActiveDirectoryBackup'
Set-Variable -Name 'AD_BACKUP_POLICY_KEY' -Option ReadOnly -Scope Script -Force

$AD_BACKUP_POLICY_PROPERTY = 'HKLM:\SOFTWARE\Policies\Microsoft\FVE'
Set-Variable -Name 'AD_BACKUP_POLICY_PROPERTY' -Option ReadOnly -Scope Script -Force

$AD_BACKUP_POLICY_ENABLED_VALUE = 1
Set-Variable -Name 'AD_BACKUP_POLICY_ENABLED_VALUE' -Option ReadOnly -Scope Script -Force

#
# Invoke Main
#
function Invoke-Main ([hashtable]$InputParameters) {
    $exitCode = 0
    try {
        Test-RunningAsLocalSystem
        Test-MinimumSupportedOSVersion -WindowsVersion 'Windows10'

        Test-InputParameters -InputParameters $InputParameters
        Test-BitlockerStatus

        Invoke-BitLockerEncryption -InputParameters $InputParameters
    } catch {
        Write-StatusMessage -Message $_
        $exitCode = 1
    }

    return $exitCode
}

#
# Template functions
#
function Test-RunningAsLocalSystem {

    if (-not (Confirm-CurrentUserIsLocalSystem)) {
        throw "$($ERROR_EXCEPTION_TYPE.Environment) This script must be run as LocalSystem. "
    }
}

function Confirm-CurrentUserIsLocalSystem {

    $currentIdentity = Get-CurrentIdentity
    return $currentIdentity -eq $LOCAL_SYSTEM_IDENTITY
}

function Get-CurrentIdentity {

    return [security.principal.windowsidentity]::GetCurrent().User.ToString()
}

function Test-MinimumSupportedOSVersion ([string]$WindowsVersion, [switch]$SupportedWindowsServer) {
    $currentOSInfo = Get-OSVersionType
    $OSVersion = $currentOSInfo.Version -as [version]

    $supportedWindows = $WINDOWS_VERSIONS.$WindowsVersion -as [version]

    if (-not ($currentOSInfo)) {
        throw "$($ERROR_EXCEPTION_TYPE.Environment) This script could not return OS version. "
    }

    if ( $SupportedWindowsServer -eq $false -and $currentOSInfo.ProductType -ne 1) {
        throw "$($ERROR_EXCEPTION_TYPE.Environment) This script is not compatible with Windows Servers. "
    }

    if ( $OSVersion -lt $supportedWindows) {
        throw "$($ERROR_EXCEPTION_TYPE.Environment) This script is compatible with $WindowsVersion and later only. "
    }
}

function Get-OSVersionType {

    return Get-WindowsManagementData -Class Win32_OperatingSystem | Select-Object -Property Version,ProductType
}

function Get-WindowsManagementData ([string]$Class, [string]$Namespace = 'root/cimv2') {
    try {
        $query = [wmisearcher] "Select * from $Class"
        $query.Scope.Path = "$Namespace"
        $query.Get()
    } catch {
        throw "$($ERROR_EXCEPTION_TYPE.Environment) Error getting CIM/WMI information. Verify WinMgmt service status and WMI repository consistency. "
    }
}

function Write-StatusMessage ([psobject]$Message) {
    $exceptionMessage = $Message.ToString()

    if ($Message.InvocationInfo.ScriptLineNumber) {
        $version = Get-ScriptVersion
        if (-not [string]::IsNullOrEmpty($version)) {
            $scriptVersion = "Version: $version. "
        }

        $errorMessageLine = $scriptVersion + "Line '$($Message.InvocationInfo.ScriptLineNumber)': "
    }

    $host.ui.WriteErrorLine($errorMessageLine + $exceptionMessage)
}

function Get-ScriptVersion {

    $scriptContent = Get-Content $MyInvocation.ScriptName | Out-String
    if ($scriptContent -notmatch '<#[\r\n]{2}.SYNOPSIS[^\#\>]*(.NOTES[^\#\>]*)\#>') { return }

    $helpBlock = $Matches[1].Split([environment]::NewLine)

    foreach ($line in $helpBlock) {
        if ($line -match 'Version:') {
            return $line.Split(':')[1].Split('-')[0].Trim()
        }
    }
}

function Test-BooleanParameter ([string]$ParamName, [string]$ParamValue) {
    $value = $ParamValue.ToLower()
    if ($value -ne 'true' -and $value -ne 'false') {
        throw "$($ERROR_EXCEPTION_TYPE.Input) Error in parameter '$ParamName'. It must be 'true' or 'false'. "
    }
}

function Test-StringSet ([string]$ParamName, $ParamValue, [string[]]$ValidValues) {
    if ([string]::IsNullOrEmpty($ParamValue) -or -not ($ParamValue -is [string])) {
        throw "$($ERROR_EXCEPTION_TYPE.Input) Error in parameter '$ParamName'. It is not a string. "
    }

    foreach ($value in $ValidValues) {
        if ($ParamValue -eq $value) { return }
    }

    $expectedValues = $ValidValues -join ', '
    throw "$($ERROR_EXCEPTION_TYPE.Input) Error in parameter '$ParamName'. Accepted values are $expectedValues. "
}

function Test-RegistryKeyProperty ([string]$Key, [string]$Property) {
    if ([string]::IsNullOrEmpty($Key)) { return $false }
    if (Test-WOW6432Process) {
        $regSubkey = Get-WOW64RegistrySubKey -Key $Key -Property $Property -ReadOnly
        return $null -ne $regSubkey.GetValue($Property)
    } else {
        return $null -ne (Get-ItemProperty -Path $Key `
                                           -Name $Property `
                                           -ErrorAction SilentlyContinue)
    }
}

function Test-WOW6432Process {

    return (Test-Path Env:\PROCESSOR_ARCHITEW6432)
}

function Get-WOW64RegistrySubKey ([string]$Key, [switch]$ReadOnly) {
    switch -Regex ($Key) {
        '^HKLM:\\(.*)' { $hive = "LocalMachine" }
        '^HKCU:\\(.*)' { $hive = "CurrentUser" }
    }

    try {
        $regKey = [Microsoft.Win32.RegistryKey]::OpenBaseKey($hive,[Microsoft.Win32.RegistryView]::Registry64)

        switch ($ReadOnly) {
            $true { return $regKey.OpenSubKey($Matches[1]) }
            $false { return $regKey.OpenSubKey($Matches[1],$true) }
        }
    }
    catch {
         throw 'Error opening registry hive. '
    }
}

function Get-RegistryKeyProperty ([string]$Key, [string]$Property) {
    if ([string]::IsNullOrEmpty($Key)) { return }
    if (Test-WOW6432Process) {
        $regSubkey = Get-WOW64RegistrySubKey -Key $Key -Property $Property -ReadOnly
        return $regSubkey.GetValue($Property)
    } else {
        return (Get-ItemProperty -Path $Key `
                                 -Name $Property `
                                 -ErrorAction SilentlyContinue) |
                    Select-Object -ExpandProperty $Property
    }
}

#
# Input parameter validation
#
function Test-InputParameters ([hashtable]$InputParameters) {
    Test-BooleanParameter `
        -ParamName 'EnforceADBackup' `
        -ParamValue $InputParameters.EnforceADBackup
    Test-BooleanParameter `
        -ParamName 'UsedSpaceOnly' `
        -ParamValue $InputParameters.UsedSpaceOnly
    Test-StringSet `
        -ParamName 'EncryptionMethod' `
        -ParamValue $InputParameters.EncryptionMethod `
        -ValidValues $ENCRYPTION_METHOD
}

#
# BitLocker management
#
function Test-BitlockerStatus {
    $bitlockerStatus = (Get-BitLockerVolume -MountPoint $env:SystemDrive).VolumeStatus

    if ($bitlockerStatus -ne 'FullyDecrypted') {
        throw "$($ERROR_EXCEPTION_TYPE.Environment) The device cannot be encrypted, the current status is $bitlockerStatus"
    }
}

function Invoke-BitLockerEncryption ([hashtable]$InputParameters) {
    Test-TPM
    Test-FileSystem
    Test-ADGPOStatus -EnforceADBackup ([bool]::parse($InputParameters.EnforceADBackup))

    Invoke-BitLocker -UsedSpaceOnly ([bool]::parse($InputParameters.UsedSpaceOnly)) -EncryptionMethod $InputParameters.EncryptionMethod
    Write-StatusMessage -Message 'BitLocker enabled for the system drive. The encryption will start after rebooting the device. '
}

function Test-TPM {
    $tpmStatus = Get-WmiObject -Namespace $TPM_NAMESPACE `
                               -Class $TPM_CLASS `
                               -ErrorAction Stop

    if ($null -eq $tpmStatus) {
        throw "$($ERROR_EXCEPTION_TYPE.Environment) TPM status cannot be retrieved. "
    }

    if ($tpmStatus.IsActivated().IsActivated -and `
        $tpmStatus.IsEnabled().IsEnabled -and `
        $tpmStatus.IsOwned().IsOwned) { return }

        throw "$($ERROR_EXCEPTION_TYPE.Environment) BitLocker needs to have TPM activated, enabled and owned. "
}

function Test-FileSystem {
    $systemVolume = Get-Volume -DriveLetter $env:SystemDrive.Replace(':', '')
    if ('NTFS' -ne $systemVolume.FileSystemType) {
        throw "$($ERROR_EXCEPTION_TYPE.Environment) '$env:SystemDrive' has $($systemVolume.FileSystemType) filesystem and it must have NTFS to allow encryption. "
    }
}

function Test-ADGPOStatus ([bool]$EnforceADBackup) {
    if (Test-RegistryKeyProperty -Key $AD_BACKUP_POLICY_KEY -Property $AD_BACKUP_POLICY_PROPERTY) {
        [int]$policyValue = Get-RegistryKeyProperty -Key $AD_BACKUP_POLICY_KEY -Property $AD_BACKUP_POLICY_PROPERTY
        if ($policyValue -eq $AD_BACKUP_POLICY_ENABLED_VALUE) { return }
    }

    $message = 'The Active Directory Backup group policy is disabled. '
    if ($EnforceADBackup) { throw "$($ERROR_EXCEPTION_TYPE.Environment) '$message'" }
    Write-StatusMessage -Message $message
}

function Invoke-BitLocker ([bool]$UsedSpaceOnly, [string]$EncryptionMethod) {
    [void](Enable-BitLocker -MountPoint $env:SystemDrive -EncryptionMethod $EncryptionMethod `
                            -RecoveryPasswordProtector -UsedSpaceOnly:$UsedSpaceOnly `
                            -WarningAction SilentlyContinue)
}

#
# Main script flow
#
[environment]::Exit((Invoke-Main -InputParameters $MyInvocation.BoundParameters))

