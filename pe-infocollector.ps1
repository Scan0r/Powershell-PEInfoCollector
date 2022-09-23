# Powershell Script

<#
.SYNOPSIS
    Collects a set of useful information about the system it is running on and creates 
    an object with it, and can return it.

.DESCRIPTION
    PE-InfoCollector is a script designed for the post-exploitation phase that allows the 
    collection of a diverse set of information about the victim system. It creates an object 
    with this information, being able to return it to a variable at the end. In addition, it 
    dumps this information into different files within the current directory.

.PARAMETER OS
    Flag to collect information about the operating system version of the system..

.PARAMETER SystemInfo
    Flag to collect information about the system name.

.PARAMETER Revisiones
    Flag to collect information about the IDs of the system security checks.

.PARAMETER UsersAdmin
    Flag to collect information about users belonging to the system administrators group.

.PARAMETER Procesos
    Flag for collecting information on system process names.

.PARAMETER All
    Switches on all previous data collection flags.

.PARAMETER Silent
    Suppresses all writing to the standard output.

.PARAMETER RerturnObject
    Specifies that the object created during data collection should be returned.

.EXAMPLE
    pe-infocollector -OS -SystemInfo -UsersAdmin

.EXAMPLE
    pe-infocollector -All

.EXAMPLE
    pe-infocollector -All -Silent -ReturnObject

.OUTPUTS
    PEInfoCollectorObject

.NOTES
    Author:  Scan0r
    Version: 0.1
    Date:    07-02-2022
#>


# Script configuration

param(
  [Parameter(Mandatory = $false,HelpMessage = "OS")]
  [switch]$OS,
  [Parameter(Mandatory = $false,HelpMessage = "SystemInfo")]
  [switch]$SystemInfo,
  [Parameter(Mandatory = $false,HelpMessage = "Revisiones")]
  [switch]$Revisiones,
  [Parameter(Mandatory = $false,HelpMessage = "UsersAdmin")]
  [switch]$UsersAdmin,
  [Parameter(Mandatory = $false,HelpMessage = "Procesos")]
  [switch]$Procesos,
  [Parameter(Mandatory = $false,HelpMessage = "All")]
  [switch]$All,
  [Parameter(Mandatory = $false,HelpMessage = "Silent")]
  [switch]$Silent,
  [Parameter(Mandatory = $false,HelpMessage = "ReturnObject")]
  [switch]$ReturnObject
)


# Auxiliary functions

function Log-Output {
  param(
    [Parameter(Mandatory = $true,HelpMessage = "Message")]
    $Message,
    [Parameter(Mandatory = $true,HelpMessage = "MessageType")]
    [string]$MessageType,
    [Parameter(Mandatory = $false,HelpMessage = "IsObject")]
    [switch]$IsObject
  )

  if (-not $Silent) {
    if ($MessageType -eq "Log") {
      if ($IsObject) {
        $(Write-Output $Message | Out-String).Trim()
      } else {
        Write-Host "$Message"
      }
    } elseif ($MessageType -eq "Verbose") {
      Write-Host -ForegroundColor Cyan "$Message"
    } elseif ($MessageType -eq "Inform") {
      Write-Host -ForegroundColor Yellow "$Message"
    } elseif ($MessageType -eq "Error") {
      Write-Host -ForegroundColor Red "$Message"
    } else {
      throw "Error: Unknown MessageType '$MessageType'"
    }
  }
}

function Get-OS {
  Log-Output -Message "[+] Scanning for OS Version data...`n" -MessageType "Verbose"

  $obj = (Get-WmiObject win32_operatingsystem)
  $value = $($obj | Select-Object -Property Caption,Version,OSArchitecture | Format-List)
  $PEInfoCollectorObject | Add-Member -MemberType NoteProperty -Name 'OS' -Value $value

  if (-not $PEInfoCollectorObject.OS) {
    Log-Output -Message "Error: OS version data couldn't be found!" -MessageType "Error"
  } else {
    Log-Output -Message "=================" -MessageType "Log"
    Log-Output -Message "       OS        " -MessageType "Log"
    Log-Output -Message "=================" -MessageType "Log"
    Log-Output -Message $PEInfoCollectorObject.OS -MessageType "Log" -IsObject

    Log-Output -Message "`n[*] Saving output to file: '.\Get-OS.txt'" -MessageType "Inform"
    Log-Output -Message "-----------------------------------------`n" -MessageType "Log"
    Log-Output -Message $PEInfoCollectorObject.OS -MessageType "Log" -IsObject > ".\Get-OS.txt"
  }
}

function Get-SystemInfo {
  Log-Output -Message "[+] Scanning for System Info data...`n" -MessageType "Verbose"

  $obj = (Get-WmiObject win32_operatingsystem)
  $value = $($obj | Select-Object -Property PSComputerName | Format-List)
  $PEInfoCollectorObject | Add-Member -MemberType NoteProperty -Name 'SystemInfo' -Value $value

  if (-not $PEInfoCollectorObject.SystemInfo) {
    Log-Output -Message "Error: System Info data couldn't be found!" -MessageType "Error"
  } else {
    Log-Output -Message "=================" -MessageType "Log"
    Log-Output -Message "    SystemInfo   " -MessageType "Log"
    Log-Output -Message "=================" -MessageType "Log"
    Log-Output -Message $PEInfoCollectorObject.SystemInfo -MessageType "Log" -IsObject

    Log-Output -Message "`n[*] Saving output to file: '.\Get-SystemInfo.txt'" -MessageType "Inform"
    Log-Output -Message "-------------------------------------------------`n" -MessageType "Log"
    Log-Output -Message $PEInfoCollectorObject.SystemInfo -MessageType "Log" -IsObject > ".\Get-SystemInfo.txt"
  }
}

function Get-Revisiones {
  Log-Output -Message "[+] Scanning for Revisiones (HotFix) data...`n" -MessageType "Verbose"

  $value = $(Get-HotFix | Select-Object -Property HotFixID | Format-List)
  $PEInfoCollectorObject | Add-Member -MemberType NoteProperty -Name 'Revisiones' -Value $value

  if (-not $PEInfoCollectorObject.Revisiones) {
    Log-Output -Message "Error: Revisiones (HotFix) data couldn't be found!" -MessageType "Log"
  } else {
    Log-Output -Message "=================" -MessageType "Log"
    Log-Output -Message "    Revisiones   " -MessageType "Log"
    Log-Output -Message "=================" -MessageType "Log"
    Log-Output -Message $PEInfoCollectorObject.Revisiones -MessageType "Log" -IsObject

    Log-Output -Message "`n[*] Saving output to file: '.\Get-Revisiones.txt'" -MessageType "Log"
    Log-Output -Message "-------------------------------------------------`n" -MessageType "Log"
    Log-Output -Message $PEInfoCollectorObject.Revisiones -MessageType "Log" -IsObject > ".\Get-Revisiones.txt"
  }
}

function Get-UsersAdmin {
  Log-Output -Message "[+] Scanning for UsersAdmin data...`n" -MessageType "Verbose"

  $group = $(Get-LocalGroup | Select-Object -First 1 | Select-Object -Property name)
  $value = $(Get-LocalGroupMember -Group $group.Name | Format-List)
  $PEInfoCollectorObject | Add-Member -MemberType NoteProperty -Name 'UsersAdmin' -Value $value

  if (-not $PEInfoCollectorObject.UsersAdmin) {
    Log-Output -Message "Error: Users Admin data couldn't be found!" -MessageType "Error"
  } else {
    Log-Output -Message "=================" -MessageType "Log"
    Log-Output -Message "    UsersAdmin   " -MessageType "Log"
    Log-Output -Message "=================" -MessageType "Log"
    Log-Output -Message $PEInfoCollectorObject.UsersAdmin -MessageType "Log" -IsObject

    Log-Output -Message "`n[*] Saving output to file: '.\Get-UsersAdmin.txt'" -MessageType "Inform"
    Log-Output -Message "-------------------------------------------------`n" -MessageType "Log"
    Log-Output -Message $PEInfoCollectorObject.UsersAdmin -MessageType "Log" -IsObject > ".\Get-UsersAdmin.txt"
  }
}

function Get-Procesos {
  Log-Output -Message "[+] Scanning for Procesos data...`n" -MessageType "Verbose"

  $value = $(Get-Process | Select-Object name -Unique | Format-List)
  $PEInfoCollectorObject | Add-Member -MemberType NoteProperty -Name 'Procesos' -Value $value

  if (-not $PEInfoCollectorObject.Procesos) {
    Log-Output -Message "Error: Procesos data couldn't be found!" -MessageType "Error"
  } else {
    Log-Output -Message "=================" -MessageType "Log"
    Log-Output -Message "     Procesos    " -MessageType "Log"
    Log-Output -Message "=================" -MessageType "Log"
    Log-Output -Message $PEInfoCollectorObject.Procesos -MessageType "Log" -IsObject

    Log-Output -Message "`n[*] Saving output to file: '.\Get-Procesos.txt'" -MessageType "Inform"
    Log-Output -Message "-----------------------------------------------`n" -MessageType "Log"
    Log-Output -Message $PEInfoCollectorObject.Procesos -MessageType "Log" -IsObject > ".\Get-Procesos.txt"
  }
}


# Post-Exploitation Information Collector Object

$PEInfoCollectorObject = [pscustomobject]@{}


# Cli parsing and main logic

if ($All -eq $true) {
  $OS = $true
  $SystemInfo = $true
  $Revisiones = $true
  $UsersAdmin = $true
  $Procesos = $true
}

if ($OS -eq $true) {
  Get-OS
}

if ($SystemInfo -eq $true) {
  Get-SystemInfo
}

if ($Revisiones -eq $true) {
  Get-Revisiones
}

if ($UsersAdmin -eq $true) {
  Get-UsersAdmin
}

if ($Procesos -eq $true) {
  Get-Procesos
}

if ($ReturnObject) {
  return $PEInfoCollectorObject
}

# End

