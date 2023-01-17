<#
    MIT License

    Copyright (c) Microsoft Corporation.

    Permission is hereby granted, free of charge, to any person obtaining a copy
    of this software and associated documentation files (the "Software"), to deal
    in the Software without restriction, including without limitation the rights
    to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
    copies of the Software, and to permit persons to whom the Software is
    furnished to do so, subject to the following conditions:

    The above copyright notice and this permission notice shall be included in all
    copies or substantial portions of the Software.

    THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
    IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
    FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
    AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
    LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
    OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
    SOFTWARE
#>

<#

For information about this tool, including data it stores to understand effectiveness, go to https://aka.ms/ASR_shortcuts_deletion_FAQ

#>

<#
# script to add deleted shortcuts back for common application.
# Credits: https://github.com/InsideTechnologiesSrl/DefenderBug/blob/main/W11-RestoreLinks.ps1
#           https://p0w3rsh3ll.wordpress.com/2014/06/21/mount-and-dismount-volume-shadow-copies/
#
         
Help:

Param Telemetry: enable or disable having telemetry logging, default: true
Param ForceRepair: repair is done irrespective of machine being considered affected or not, default: false
Param VssRecovery: Use VSS recovery to restore lnk files, default: false
Param Verbose: 
    Value 0: No stdout and no log file
    Value 1: Only stdout (default)
    Value 2: both stdout and log file output
    Value 3: detailed stdout along with log file output

#>

param ([bool] $Telemetry = $true, [switch] $ForceRepair = $false, [switch] $VssRecovery = $true, [int] $Verbose = 1)

$ScriptVersion = 2
$ScriptVersionStr = "v" + $ScriptVersion.ToString()
$doesCFANeedsReset = $false

<#
#  programs table below is a key=value pair, with [] are used to denote programs that have version year info, like [Visual Studio 2022]
#  for such entries with [], we will lookup file description in file version info and use that, if it doesnt exists, we will falback using generic name.
#>

$programs = @{
    "Adobe Acrobat"                = "Acrobat.exe"
    "[Adobe Photoshop]"            = "photoshop.exe"
    "[Adobe Illustrator]"          = "illustrator.exe"
    "Adobe Creative Cloud"         = "Creative Cloud.exe"
    "Adobe Substance 3D Painter"   = "Adobe Substance 3D Painter.exe"
    "Firefox Private Browsing"     = "private_browsing.exe"
    "Firefox"                      = "firefox.exe"
    "Google Chrome"                = "chrome.exe"
    "Microsoft Edge"               = "msedge.exe"
    "Notepad++"                    = "notepad++.exe"
    "Parallels Client"             = "APPServerClient.exe"
    "Remote Desktop"               = "msrdcw.exe"
    "TeamViewer"                   = "TeamViewer.exe"
    "[Royal TS]"                   = "royalts.exe"
    "Elgato StreamDeck"            = "StreamDeck.exe"
    "[Visual Studio]"              = "devenv.exe"
    "Visual Studio Code"           = "code.exe"
    "Camtasia Studio"              = "CamtasiaStudio.exe"
    "Camtasia Recorder"            = "CamtasiaRecorder.exe"
    "Jabra Direct"                 = "jabra-direct.exe"
    "7-Zip File Manager"           = "7zFM.exe"
    "Access"                       = "MSACCESS.EXE"
    "Excel"                        = "EXCEL.EXE"
    "OneDrive"                     = "onedrive.exe"
    "OneNote"                      = "ONENOTE.EXE"
    "Outlook"                      = "OUTLOOK.EXE"
    "PowerPoint"                   = "POWERPNT.EXE"
    "Project"                      = "WINPROJ.EXE"
    "Publisher"                    = "MSPUB.EXE"
    "Visio"                        = "VISIO.EXE"
    "Word"                         = "WINWORD.exe"
    "[PowerShell 7]"               = "pwsh.exe"
    "SQL Server Management Studio" = "ssms.exe"
    "Azure Data Studio"            = "azuredatastudio.exe"
    "Zoom"                         = "zoom.exe"
    "Internet Explorer"            = "IEXPLORE.EXE"
    "Skype for Business"           = "Skype.exe"
    "VLC Player"                   = "vlc.exe"   
    "Cisco Jabber"                 = "CiscoJabber.exe"
    "Microsoft Teams"              = "msteams.exe"
    "PuTTY"                        = "putty.exe"
    "wordpad"                      = "WORDPAD.EXE"
    "[AutoCAD]"                    = "acad.exe"
}

$LogFileName = [string]::Format("ShortcutRepairs{0}.log", (Get-Random -Minimum 0 -Maximum 99))
$LogFilePath = "$env:temp\$LogFileName";

Function Log {
    param($message);
    if ($Verbose -ge 2) {    
        $currenttime = Get-Date -format u;
        $outputstring = "[" + $currenttime + "] " + $message;
        $outputstring | Out-File $LogFilepath -Append;
    }
}

Function LogAndConsole($message) {
    if ($Verbose -ge 1) {
        Write-Host $message -ForegroundColor Green
    }
    if ($Verbose -ge 2) {
        Log $message
    }
}

Function LogErrorAndConsole($message) {
    if ($Verbose -ge 1) {
        Write-Host $message -ForegroundColor Red
    }
    if ($Verbose -ge 2) {
        Log $message
    }
}

function Get-PSVersion {
    if ($PSVersionTable.PSVersion -like '7*') {
        [string]$PSVersionTable.PSVersion.Major + '.' + [string]$PSVersionTable.PSVersion.Minor + '.' + [string]$PSVersionTable.PSVersion.Patch
    }
    else {
        [string]$PSVersionTable.PSVersion.Major + '.' + [string]$PSVersionTable.PSVersion.Minor + '.' + [string]$PSVersionTable.PSVersion.Build
    }
}

# Saves the result of the script in the registry.  
# If you don't want this information to be saved use the -Telemetry $false option
Function SaveResult() {

    param(
        [parameter(ParameterSetName = "Failure")][switch][Alias("Failed")]$script_failed = $false,
        [parameter(ParameterSetName = "Failure")][string][Alias("ScriptError")]$script_error = "Generic Error",
        [parameter(ParameterSetName = "Failure")][parameter(ParameterSetName = "Success")][int32][Alias("NumLinksFound")]$links_found = 0,
        [parameter(ParameterSetName = "Failure")][parameter(ParameterSetName = "Success")][int32][Alias("HKUAppsSuccess")]$hku_success = 0,
        [parameter(ParameterSetName = "Failure")][parameter(ParameterSetName = "Success")][int32][Alias("HKUAppsFailure")]$hku_failure = 0,
        [parameter(ParameterSetName = "Failure")][parameter(ParameterSetName = "Success")][int32][Alias("HKLMAppsSuccess")]$hklm_success = 0,
        [parameter(ParameterSetName = "Failure")][parameter(ParameterSetName = "Success")][int32][Alias("HKLMAppsFailure")]$hklm_failure = 0,
        [parameter(ParameterSetName = "Success")][switch][Alias("Succeeded")]$script_succeeded = $false,
        [parameter(ParameterSetName = "Success")][parameter(ParameterSetName = "Failure")][Alias("User")][switch]$use_hkcu = $false
    )

    if ($use_hkcu) {
        $registry_hive = "HKCU:"     
    }
    else {
        $registry_hive = "HKLM:"
    }
    $registry_hive += "Software\Microsoft"
    $registry_name = "ASRFix"

    if ($Telemetry) {
         
        $registry_full_path = $registry_hive + "\" + $registry_name

        if (Test-Path -Path $registry_full_path) {
            #Registry Exists
        }
        else {
            #Registry does not Exist, create it
            New-Item -Path $registry_hive -Name $registry_name -Force | Out-Null
           
        }

        #Create a timestamp
        $timestamp = [DateTime]::UtcNow.ToString('o')

        #If its a success, make sure there is no error left over from last run
        if ($PsCmdlet.ParameterSetName -eq "Success") {
            $script_error = "None"
            $result = "Success"
            $script_result = 0
        }
        else {
            $result = "Failure"
            $script_result = 1
        }
 
        #Save the result in the registry
        New-ItemProperty -Path $registry_full_path -Name Version -Value $ScriptVersion -Force | Out-Null 
        New-ItemProperty -Path $registry_full_path -Name ScriptResult -Value $script_result -Force -PropertyType DWORD | Out-Null
        New-ItemProperty -Path $registry_full_path -Name Timestamp -Value $timestamp -Force | Out-Null
        New-ItemProperty -Path $registry_full_path -Name NumLinksFound -Value $links_found -PropertyType DWORD -Force | Out-Null
        New-ItemProperty -Path $registry_full_path -Name HKUAppSuccess -Value $hku_success -PropertyType DWORD -Force | Out-Null
        New-ItemProperty -Path $registry_full_path -Name HKUAppFailure -Value $hku_failure -PropertyType DWORD -Force | Out-Null
        New-ItemProperty -Path $registry_full_path -Name HKLMSuccess -Value $hklm_success -PropertyType DWORD -Force | Out-Null
        New-ItemProperty -Path $registry_full_path -Name HKLMFailure -Value $hklm_failure -PropertyType DWORD -Force | Out-Null
        New-ItemProperty -Path $registry_full_path -Name ScriptError -Value $script_error -Force | Out-Null

        if ($Verbose -ge 1) {
            LogAndConsole "[+] Saved Result:  ScriptResult=$result ($script_result), TimeStamp=$timestamp, NumLinksFound=$links_found, HKUAppSuccess=$hku_success, HKUAppFailure=$hku_failure,  HKLMSuccess=$hklm_success, HKLMFailure=$hklm_failure,  ScriptError=$script_error in registry $registry_full_path"
        }
    }  
}

#If there is any error, save the result as a failure
trap {

    if ($doesCFANeedsReset) {
        # turn it back on
        LogAndConsole "[+] Turn CFA back ON to its original state"
        Set-MpPreference -EnableControlledFolderAccess 1
        $doesCFANeedsReset = $false
    }

    $id = [System.Security.Principal.WindowsIdentity]::GetCurrent()
    $p = New-Object System.Security.Principal.WindowsPrincipal($id)
    if (!($p.IsInRole([System.Security.Principal.WindowsBuiltInRole]::Administrator) -Or ($id.Name -like "NT AUTHORITY\SYSTEM"))) {
        SaveResult -Failed -User -ScriptError $_
    }
    else {
        SaveResult -Failed -ScriptError $_
    }

    exit
}

Function Mount-VolumeShadowCopy {
    <#
    .SYNOPSIS
        Mount a volume shadow copy.
     
    .DESCRIPTION
        Mount a volume shadow copy.
      
    .PARAMETER ShadowPath
        Path of volume shadow copies submitted as an array of strings
      
    .PARAMETER Destination
        Target folder that will contain mounted volume shadow copies
              
    .EXAMPLE
        Get-CimInstance -ClassName Win32_ShadowCopy | 
        Mount-VolumeShadowCopy -Destination C:\VSS -Verbose
 
#>
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory, ValueFromPipeline, ValueFromPipelineByPropertyName)]
        [ValidatePattern('\\\\\?\\GLOBALROOT\\Device\\HarddiskVolumeShadowCopy\d{1,}')]
        [Alias("DeviceObject")]
        [String[]]$ShadowPath,
 
        [Parameter(Mandatory)]
        [ValidateScript({
                Test-Path -Path $_ -PathType Container
            }
        )]
        [String]$Destination
    )
    Begin {
        Try {
            $null = [mklink.symlink]
        }
        Catch {
            Add-Type @"
        using System;
        using System.Runtime.InteropServices;
  
        namespace mklink
        {
            public class symlink
            {
                [DllImport("kernel32.dll")]
                public static extern bool CreateSymbolicLink(string lpSymlinkFileName, string lpTargetFileName, int dwFlags);
            }
        }
"@
        }
    }
    Process {
 
        $ShadowPath | ForEach-Object -Process {
 
            if ($($_).EndsWith("\")) {
                $sPath = $_
            }
            else {
                $sPath = "$($_)\"
            }
        
            $tPath = Join-Path -Path $Destination -ChildPath (
                '{0}-{1}' -f (Split-Path -Path $sPath -Leaf), [GUID]::NewGuid().Guid
            )
         
            try {
                if (
                    [mklink.symlink]::CreateSymbolicLink($tPath, $sPath, 1)
                ) {
                    LogAndConsole "`tSuccessfully mounted $sPath to $tPath"
                    return $tPath
                }
                else {
                    LogAndConsole "[!] Failed to mount $sPath"
                }
            }
            catch {
                LogAndConsole "[!] Failed to mount $sPath because $($_.Exception.Message)"
            }
        }
 
    }
    End {}
}


Function Dismount-VolumeShadowCopy {
    <#
    .SYNOPSIS
        Dismount a volume shadow copy.
     
    .DESCRIPTION
        Dismount a volume shadow copy.
      
    .PARAMETER Path
        Path of volume shadow copies mount points submitted as an array of strings
      
    .EXAMPLE
        Get-ChildItem -Path C:\VSS | Dismount-VolumeShadowCopy -Verbose
         
 
#>
 
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory, ValueFromPipeline, ValueFromPipelineByPropertyName)]
        [Alias("FullName")]
        [string[]]$Path
    )
    Begin {
    }
    Process {
        $Path | ForEach-Object -Process {
            $sPath = $_
            if (Test-Path -Path $sPath -PathType Container) {
                if ((Get-Item -Path $sPath).Attributes -band [System.IO.FileAttributes]::ReparsePoint) {
                    try {
                        [System.IO.Directory]::Delete($sPath, $false) | Out-Null
                        LogAndConsole "`tSuccessfully dismounted $sPath"
                    }
                    catch {
                        LogAndConsole "[!] Failed to dismount $sPath because $($_.Exception.Message)"
                    }
                }
                else {
                    LogAndConsole "[!] The path $sPath isn't a reparsepoint"
                }
            }
            else {
                LogAndConsole "[!] The path $sPath isn't a directory"
            }
        }
    }
    End {}
}

Function GetTimeRangeOfVersion() {

    $versions = "1.381.2140.0", "1.381.2152.0", "1.381.2160.0"

    $properties2000 = @(
        'TimeCreated',
        'ProductName',
        'ProductVersion',
        @{n = 'CurrentVersion'; e = { $_.Properties[2].Value } },
        @{n = 'PreviousVersion'; e = { $_.Properties[3].Value } })


    $installTime = $null
    $removalTime = $null
    $foundVersion = $null
    foreach ($version in $versions) {

        if ($null -eq $installTime) {
            $lgp_events = (Get-WinEvent -LogName "Microsoft-Windows-Windows Defender/Operational" | where { $_.Id -eq 2000 } | Select $properties2000 | Where-Object { $_.CurrentVersion -eq $($version) } )
            if ($lgp_events) {
                $installTime = @($lgp_events[0]).TimeCreated
                $foundVersion = $version
            }
        }
        $rgp_events = (Get-WinEvent -LogName "Microsoft-Windows-Windows Defender/Operational" | where { $_.Id -eq 2000 } | Select $properties2000 | Where-Object { $_.PreviousVersion -eq $($version) } )
        if ($rgp_events) {
            $removalTime = @($rgp_events[0]).TimeCreated
        }
    }
    if ($installTime ) {
        if ($removalTime) {
            if ($Verbose -gt 2) {
                LogAndConsole "`tInstall time $installTime, removal time $removalTime for build $foundVersion"
            }
            return $installTime, $removalTime , $foundVersion
        }
        else {
            if ($Verbose -gt 2) {
                LogAndConsole "[!] Broken build version $foundVersion is still installed! First update to a build >= 1.381.2164.0 and run again."
            }
            return $null
        }
    }
    else {
        LogAndConsole "[+] No Broken Builds installed on the machine"
        return $null
    }

}

#check if Server SKU or not
Function IsServerSKU {
    return ((Get-WmiObject -Class Win32_OperatingSystem).ProductType -ne 1)
}

#find shadow copy before bad update
Function GetShadowcopyBeforeUpdate( $targetDate ) {

    $shadowCopies = $null
    $shadowcopies = Get-WmiObject Win32_shadowcopy | Where-Object { [System.Management.ManagementDateTimeConverter]::ToDateTime($_.InstallDate) -lt $targetDate } | Sort-Object InstallDate -Descending 

    $driveDict = @{}
    foreach ($shadow in $shadowcopies ) {
        LogAndConsole "$($shadow.VolumeName) $($shadow.DeviceObject) $($shadow.InstallDate)  $($shadow.CreationTime)"
        # this is intentional, to replace \ with \\
        $escapedDrive = $shadow.VolumeName -replace '\\', '\\'
        $volume = Get-WmiObject -Class Win32_Volume -Namespace "root\cimv2" -Filter "DeviceID='$escapedDrive'"

        if ($null -eq $driveDict[$volume.DriveLetter]) {
            $driveDict[$volume.DriveLetter] = @()
        } 
        $driveDict[$volume.DriveLetter] += $shadow
    }
    
    return $driveDict
}

function getAllValidExtsForDrive($path, $drive, $prefix, $extension) {
    $prefixLen = $($path).length

    LogAndConsole "[+] Listing $($extension) for $($path)\$($prefix)*"
    $extFiles = Get-ChildItem -ErrorAction SilentlyContinue -Path "$path\$($prefix)*" -Include "*$($extension)" -Recurse -Force
    if ($Verbose -gt 2) {
        LogAndConsole "`tNow analyzing ($extension) files..."
    }
      
    if ($extFiles) {
        $validFiles = @()
        foreach ($extFile in $extFiles) {
            if ($Verbose -gt 2) {
                LogAndConsole "`tFound $($extension): $($extFile.FullName)"
            }
            $drivePath = $drive + $extFile.FullName.Substring($prefixLen)
            try {
                if ($Verbose -gt 2) {
                    LogAndConsole "`tChecking original: $($drivePath)"
                }
                $originalLink = Get-Item -Path $drivePath -ErrorAction Stop
            }
            catch {
                Copy-Item -Path $extFile.FullName -Destination $drivePath
                if ($Verbose -gt 2) {
                    LogAndConsole "`tOriginal path doesn't exist anymore: $($drivePath)"
                }
                $validFiles += $extFile
            }
        }
        return $validFiles
    }
}

function getAllValidLNKsForDrive($path, $drive, $prefix) {
    $prefixLen = $($path).length
   
    LogAndConsole "[+] Listing .lnk for $path\$($prefix)*"
    $lnkFiles = Get-ChildItem -ErrorAction SilentlyContinue -Path "$path\$($prefix)*" -Include "*.lnk" -Recurse -Force
    if ($Verbose -gt 2) {
        LogAndConsole "`tNow analyzing .lnk files..."
    }
      
    if ($lnkFiles) {
        $validLinks = @()
        foreach ($lnkFile in $lnkFiles) {
            try {
                $target = (New-Object -ComObject WScript.Shell).CreateShortcut($lnkFile.FullName).TargetPath
                $targetFile = Get-Item -Path $target -ErrorAction Stop
            }
            catch {
                if ($Verbose -gt 2) {
                    LogAndConsole "`tThe target of $($lnkFile.FullName) does not exist. Skipped!"
                }
            }
            if ($Verbose -gt 2) {
                LogAndConsole "`tFound LNK: $($lnkFile.FullName)"
            }
            $drivePath = $drive + $lnkFile.FullName.Substring($prefixLen)
            try {
                if ($Verbose -gt 2) {
                    LogAndConsole "`tChecking original: $($drivePath)"
                }
                $originalLink = Get-Item -Path $drivePath -ErrorAction Stop
            }
            catch {
                if ($Verbose -gt 2) {
                    LogAndConsole "`tOriginal path doesn't exist anymore: $($drivePath)"
                }
                Copy-Item -Path $lnkFile.FullName -Destination $drivePath
                $validLinks += $lnkFile
            }
        }
        return $validLinks
    }
}

Function VssFileRecovery($events_time) {
    LogAndConsole "[+] Starting vss file recovery"
    $lnks = @()
    if ($events_time) {
        if ($Verbose -gt 2) {
            LogAndConsole ("`tStart time of update: $($events_time[0])")
            LogAndConsole ("`tEnd time of update: $($events_time[1])")
        }

        $missed_drives = @{}
        $guid = New-Guid
        $target = "$env:SystemDrive\vssrecovery-$guid\"
        try {
            $shadowcopies = GetShadowcopyBeforeUpdate( $events_time[0])
            if ($shadowcopies) {
                # create a directory for vss mount
                New-Item -Path $target -ItemType Directory -force | Out-Null
                # get list of profiles that have been modified within range
                $localUsersPath = Get-ItemPropertyValue -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList" -Name ProfilesDirectory
    
                $profiles = Get-ChildItem -Path $localUsersPath -Force
                LogAndConsole "[+] Start recovering profiles"
                foreach ($profilename in $profiles) {
                    $profiledir = (Split-Path $profilename.FullName -NoQualifier).Trim("\").ToString()
                    $drive = Split-Path $profilename.FullName -Qualifier
    
                    if ($null -ne $shadowCopies[$drive]) {
                        $shadowCopy = $shadowCopies[$drive][0]
                        if ($Verbose -gt 2) {
                            LogAndConsole "`tRestoring items for drive $drive and profile $profilename"
                        }
                        LogAndConsole $($shadowCopy.DeviceObject)
                        $res = Mount-VolumeShadowCopy $shadowCopy.DeviceObject -Destination $target -Verbose
    
                        if ($Verbose -gt 2) {
                            LogAndConsole "`tNow enumerating for $($profiledir)"
                        }
                        $lnks += getAllValidLNKsForDrive -path $res -drive $drive -prefix "$($profiledir)\AppData\Roaming\Microsoft\Windows\"
                        $lnks += getAllValidLNKsForDrive -path $res -drive $drive -prefix "$($profiledir)\AppData\Roaming\Microsoft\Internet Explorer\"
                        $lnks += getAllValidLNKsForDrive -path $res -drive $drive -prefix "$($profiledir)\AppData\Roaming\Microsoft\Office\"
                        $lnks += getAllValidExtsForDrive -path $res -drive $drive -prefix "$($profiledir)\Favorites\" -extension ".url"
                        $lnks += getAllValidExtsForDrive -path $res -drive $drive -prefix "$($profiledir)\Desktop\" -extension ".url"
                        Get-ChildItem -Path $target | Dismount-VolumeShadowCopy -Verbose
                    }
                    else {
                        if ($null -eq $missed_drives[$drive]) {
                            $missed_drives[$drive] = 1
                            if ($Verbose -gt 2) {
                                LogErrorAndConsole ("[!] No shadow copy could be found before update for $drive, unable to do VSS recovery!")
                            }
                        }
                    }
                }
                if ($Verbose -gt 2) {
                    if ($lnks) {
                        LogAndConsole "`tRecovered Links from VSS: $($lnks)"
                    }
                    else {
                        LogAndConsole "[!] No .lnk and .url files were found in the shadow copy"
                    }
                }
                #remove vss directory
                Remove-Item -Path $target -Recurse -force | Out-Null
            }
            else {
                LogErrorAndConsole ("[!] No shadow copy could be found before update, unable to do VSS recovery!")
            }
        }
        catch {
            LogErrorAndConsole "[!] VSSRecovery failed!"
            #remove vss directory
            if (Test-Path -Path $target) {
                Remove-Item -Path $target -Recurse -force | Out-Null
            }
        }
    }
    return $lnks.Length
}

Function CopyAclFromOwningDir($path, $SetAdminsOwner) {
    $base_path = Split-Path -Path $path
    $acl = Get-Acl $base_path
    if ($SetAdminsOwner) {
        $group = New-Object System.Security.Principal.SecurityIdentifier("S-1-5-32-544")
        $acl.SetOwner($group)
    }
    Set-Acl $path $acl
}

Function LookupHKLMAppsFixLnks($programslist) {
    $success = 0
    $failures = 0
    $programslist.GetEnumerator() | ForEach-Object {
        $reg_path = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\App Paths\$($_.Value)"
        try {
            $apppath = $null
            $target = $null
            try { $apppath = Get-ItemPropertyValue $reg_path -Name "Path" -ErrorAction SilentlyContinue } catch {}
            if ($null -ne $apppath) {
                if ($apppath.EndsWith(";") -eq $true) {
                    $apppath = $apppath.Trim(";")
                }
                if ($apppath.EndsWith("\") -eq $false) {
                    $apppath = $apppath + "\"
                }
                $target = $apppath + $_.Value
            }
            else {
                try { $target = Get-ItemPropertyValue $reg_path -Name "(default)" -ErrorAction SilentlyContinue } catch {}
            }

            if ($null -ne $target) {
                $targetName = $_.Key
                $target = $target.Trim("`"")

                if ($targetName.StartsWith("[") -and $targetName.EndsWith("]")) {
                    try {
                        $targetNameInVersion = (Get-Item -Path $target).VersionInfo.FileDescription.Trim()
                        if ($targetNameInVersion) {
                            $targetName = $targetNameInVersion
                        }
                    }
                    catch {
                        $targetName = $_.Key.Trim("][")
                    }
                }

                $shortcut_path = "$env:PROGRAMDATA\Microsoft\Windows\Start Menu\Programs\$($targetName).lnk"

                if (-not (Test-Path -Path $shortcut_path)) {
                    LogAndConsole ("`tShortcut for {0} not found in \Start Menu\, creating it now." -f $targetName)
                    $description = $targetName
                    $workingdirectory = (Get-ChildItem $target).DirectoryName
                    $WshShell = New-Object -ComObject WScript.Shell
                    $Shortcut = $WshShell.CreateShortcut($shortcut_path)
                    $Shortcut.TargetPath = $target
                    $Shortcut.Description = $description
                    $shortcut.WorkingDirectory = $workingdirectory
                    $Shortcut.Save()
                    Start-Sleep -Seconds 1          # Let the LNK file be backed to disk
                    if ($Verbose -gt 2) {
                        LogAndConsole "`tCopying ACL from owning folder"
                    }
                    CopyAclFromOwningDir $shortcut_path $True
                    $success += 1
                }
            }
        }
        catch {
            $failures += 1
            LogErrorAndConsole "Exception: $_"
        }
    }

    return $success, $failures
}

Function LookupHKUAppsFixLnks($programslist) {
    $success = 0
    $failures = 0
    $guid = New-Guid
    New-PSDrive -PSProvider Registry -Name $guid -Root HKEY_USERS -Scope Global | Out-Null
    $users = Get-ChildItem -Path "${guid}:\"
    foreach ($user in $users) {
        # Skip builtin    
        if ($user.Name.Contains(".DEFAULT") -or $user.Name.EndsWith("_Classes")) {        
            continue;   
        }  
        $sid_string = $user.Name.Split("\")[-1] 
    
        ## Get the user profile path   
        $profile_path = (Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList\$sid_string" -Name "ProfileImagePath").ProfileImagePath
        $programslist.GetEnumerator() | ForEach-Object {
            $reg_path = "${user}\SOFTWARE\Microsoft\Windows\CurrentVersion\App Paths\$($_.Value)"
            try {
                $apppath = $null
                $target = $null
                try { $apppath = Get-ItemPropertyValue Registry::$reg_path -Name "Path" -ErrorAction SilentlyContinue } catch {}
            
                if ($null -ne $apppath) {
                    if ($apppath.EndsWith(";") -eq $true) {
                        $apppath = $apppath.Trim(";")
                    }
                    if ($apppath.EndsWith("\") -eq $false) {
                        $apppath = $apppath + "\"
                    }
                    $target = $apppath + $_.Value
                }
                else {
                    try { $target = Get-ItemPropertyValue Registry::$reg_path -Name "(default)" -ErrorAction SilentlyContinue } catch {}
                }
            
                if ($null -ne $target) {

                    $targetName = $_.Key
                    $target = $target.Trim("`"")

                    if ($targetName.StartsWith("[") -and $targetName.EndsWith("]")) {
                        try {
                            $targetNameInVersion = (Get-Item -Path $target).VersionInfo.FileDescription.Trim()
                            if ($targetNameInVersion) {
                                $targetName = $targetNameInVersion
                            }
                        }
                        catch {
                            $targetName = $_.Key.Trim("][")
                        }
                    }

                    $shortcut_path = "$profile_path\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\$($targetName).lnk"

                    if (-not (Test-Path -Path $shortcut_path)) {
                        LogAndConsole ("`tShortcut for {0} not found in \Start Menu\, creating it now." -f $targetName)
                        $description = $targetName
                        $workingdirectory = (Get-ChildItem $target).DirectoryName
                        $WshShell = New-Object -ComObject WScript.Shell
                        $Shortcut = $WshShell.CreateShortcut($shortcut_path)
                        $Shortcut.TargetPath = $target
                        $Shortcut.Description = $description
                        $shortcut.WorkingDirectory = $workingdirectory
                        $Shortcut.Save()
                        Start-Sleep -Seconds 1          # Let the LNK file be backed to disk
                        if ($Verbose -gt 2) {
                            LogAndConsole "`tCopying ACL from owning folder"
                        }
                        CopyAclFromOwningDir $shortcut_path $False
                        $success += 1
                    }
                }
            }
            catch {
                $failures += 1
                LogErrorAndConsole "Exception: $_"
            }
        }
    }
    Remove-PSDrive -Name $guid | Out-Null
    return $success, $failures  
}

# Validate elevated privileges
LogAndConsole "[+] Starting LNK rescue - Script version: $ScriptVersionStr"
$selfhash = (Get-FileHash -Algorithm:Sha1 $MyInvocation.MyCommand.Path).Hash
LogAndConsole "`tScript hash: $selfhash"
LogAndConsole "`tPowerShell Version: $(Get-PSVersion)"

$id = [System.Security.Principal.WindowsIdentity]::GetCurrent()
$p = New-Object System.Security.Principal.WindowsPrincipal($id)
if (!($p.IsInRole([System.Security.Principal.WindowsBuiltInRole]::Administrator) -Or ($id.Name -like "NT AUTHORITY\SYSTEM"))) {
    LogErrorAndConsole "[!] Not running from an elevated context"
    throw "[!] Please run this script from an elevated PowerShell as Admin or as System"
    exit
}

$isserver = IsServerSKU
if ($isserver -and (-not $ForceRepair)) {
    LogAndConsole "[+] Server SKU didnt get affected, if repair is still needed, please run script again with parameter -ForceRepair"
    exit
}

# Is Machine Affected Check, continue if $ForceRepair is true
$events_time = GetTimeRangeOfVersion
if (-Not ($ForceRepair -or ($null -ne $events_time))) {
    LogAndConsole "[+] Machine didnt get affected, if repair is still needed, please run script again with parameter -ForceRepair"
    exit
}
else {
    if ($ForceRepair) {
        LogAndConsole "[+] Continue repair honoring ForceRepair"
    }
}

$doesCFANeedsReset = (Get-MpPreference).EnableControlledFolderAccess
if ($doesCFANeedsReset) {
    LogAndConsole "[+] Turn off CFA temporarily for lnk repair"
    Set-MpPreference -EnableControlledFolderAccess 0
}

# attempt vss recovery for restoring lnk files
$VssRecoveredLnks = 0
if ($VssRecovery) {
    try {
        $VssRecoveredLnks = VssFileRecovery($events_time)
        LogAndConsole "[+] VSSRecovery found $VssRecoveredLnks lnks"
    }
    catch {
        LogErrorAndConsole "[!] VSSRecovery failed!"
    }
}

# Check for shortcuts in Start Menu, if program is available and the shortcut isn't... Then recreate the shortcut
LogAndConsole "[+] Enumerating installed software under HKLM"
$hklm_apps_success, $hklm_apps_failures = LookupHKLMAppsFixLnks($programs)
LogAndConsole "`tFinished with $hklm_apps_failures failures and $hklm_apps_success successes in fixing Machine level app links"

LogAndConsole "[+] Enumerating installed software under HKU"
$hku_apps_success, $hku_apps_failures = LookupHKUAppsFixLnks($programs)
LogAndConsole "`tFinished with $hku_apps_failures failures and $hku_apps_success successes in fixing User level app links"

if ($doesCFANeedsReset) {
    # turn it back on
    LogAndConsole "[+] Turn CFA back ON to its original state"
    Set-MpPreference -EnableControlledFolderAccess 1
    $doesCFANeedsReset = $false
}

#Saving the result
SaveResult -Succeeded -NumLinksFound $VssRecoveredLnks -HKLMAppsSuccess $hklm_apps_success -HKLMAppsFailure $hklm_apps_failures -HKUAppsSuccess $hku_apps_success -HKUAppsFailure $hku_apps_failure

# SIG # Begin signature block
# MIIlpQYJKoZIhvcNAQcCoIIlljCCJZICAQExDzANBglghkgBZQMEAgEFADB5Bgor
# BgEEAYI3AgEEoGswaTA0BgorBgEEAYI3AgEeMCYCAwEAAAQQH8w7YFlLCE63JNLG
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCBlSiqjSMz3lp4L
# D0PkUdKGeUlZjoO7VMyh4i9/phMyW6CCC14wggTrMIID06ADAgECAhMzAAAJaWnl
# VutOg/ZMAAAAAAlpMA0GCSqGSIb3DQEBCwUAMHkxCzAJBgNVBAYTAlVTMRMwEQYD
# VQQIEwpXYXNoaW5ndG9uMRAwDgYDVQQHEwdSZWRtb25kMR4wHAYDVQQKExVNaWNy
# b3NvZnQgQ29ycG9yYXRpb24xIzAhBgNVBAMTGk1pY3Jvc29mdCBXaW5kb3dzIFBD
# QSAyMDEwMB4XDTIyMDUwNTIyMDAyN1oXDTIzMDUwNDIyMDAyN1owcDELMAkGA1UE
# BhMCVVMxEzARBgNVBAgTCldhc2hpbmd0b24xEDAOBgNVBAcTB1JlZG1vbmQxHjAc
# BgNVBAoTFU1pY3Jvc29mdCBDb3Jwb3JhdGlvbjEaMBgGA1UEAxMRTWljcm9zb2Z0
# IFdpbmRvd3MwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQDpucHUMbAq
# 9TX7bb9eT5HgeUEAkCQqx8db9IGteLWtjh7NXNnUoxW79fDID+6GZihupXDFRFP7
# pD+iewhd91gfBNLczlB1hMeaggJ988VzxWpMNgQ3fYpeJDEwMdhmExRJyZEIKYFH
# Dy/Bh5eykRIQmbiUi/r9+kj0W9hCMnuKRn2aXLee2YONt75g9vHH83+K+spbd04Y
# ECV7o416V9cN/T5Sff4V8Bfx3q5B4wS8eWrTYV2CYwUFJaK4RSyuPIbBwxRuZ4Fk
# uhonXnXHkaqQeMnd8PiFLppsga9wBhCDgmfamObmxwzl7gnl6jy0sNc7/3qMeWa2
# F/UKhk8suiwNAgMBAAGjggFzMIIBbzAfBgNVHSUEGDAWBgorBgEEAYI3CgMGBggr
# BgEFBQcDAzAdBgNVHQ4EFgQUP5G9CxyPFlyBsy62z8QNx41WZv0wUAYDVR0RBEkw
# R6RFMEMxKTAnBgNVBAsTIE1pY3Jvc29mdCBPcGVyYXRpb25zIFB1ZXJ0byBSaWNv
# MRYwFAYDVQQFEw0yMzAwMjgrNDcwMDM5MB8GA1UdIwQYMBaAFNFPqYoHCM70JBiY
# 5QD/89Z5HTe8MFMGA1UdHwRMMEowSKBGoESGQmh0dHA6Ly9jcmwubWljcm9zb2Z0
# LmNvbS9wa2kvY3JsL3Byb2R1Y3RzL01pY1dpblBDQV8yMDEwLTA3LTA2LmNybDBX
# BggrBgEFBQcBAQRLMEkwRwYIKwYBBQUHMAKGO2h0dHA6Ly93d3cubWljcm9zb2Z0
# LmNvbS9wa2kvY2VydHMvTWljV2luUENBXzIwMTAtMDctMDYuY3J0MAwGA1UdEwEB
# /wQCMAAwDQYJKoZIhvcNAQELBQADggEBAB4ai/kHW6cL86Rj+whuX/0UERNcW/Ls
# KHite2ZfF46eYv73CyuLFzuCpc9Kuo41WjQx1Sl/pTeSPx57lJHQRmeVK+yYvm24
# 8LsVmLUiTZC1yRQ+PLvNfmwf26A3Bjv2eqi0xSKlRqYNcX1UWEJYBrxfyK+MWEtd
# 84bwd8dnflZcPd4xfGPCtR9FUuFVjf+yXrSPUnD3rxT9AcebzU2fdqMGYHODndNz
# ZmoroyIYPE7bIchKPa0WeQwT7pGf5FZdWCo/M8ym2qzIKhFGyG67cI5ZTErj4nvv
# s5NSLMP0Og+6TQ5mRgVCwZyRknQ/1qLuuZNDd0USoHmOVTtp8tqqOiAwggZrMIIE
# U6ADAgECAgphDGoZAAAAAAAEMA0GCSqGSIb3DQEBCwUAMIGIMQswCQYDVQQGEwJV
# UzETMBEGA1UECBMKV2FzaGluZ3RvbjEQMA4GA1UEBxMHUmVkbW9uZDEeMBwGA1UE
# ChMVTWljcm9zb2Z0IENvcnBvcmF0aW9uMTIwMAYDVQQDEylNaWNyb3NvZnQgUm9v
# dCBDZXJ0aWZpY2F0ZSBBdXRob3JpdHkgMjAxMDAeFw0xMDA3MDYyMDQwMjNaFw0y
# NTA3MDYyMDUwMjNaMHkxCzAJBgNVBAYTAlVTMRMwEQYDVQQIEwpXYXNoaW5ndG9u
# MRAwDgYDVQQHEwdSZWRtb25kMR4wHAYDVQQKExVNaWNyb3NvZnQgQ29ycG9yYXRp
# b24xIzAhBgNVBAMTGk1pY3Jvc29mdCBXaW5kb3dzIFBDQSAyMDEwMIIBIjANBgkq
# hkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAwHm7OrHwD4S4rWQqdRZz0LsH9j4NnRTk
# sZ/ByJSwOHwf0DNV9bojZvUuKEhTxxaDuvVRrH6s4CZ/D3T8WZXcycai91JwWiwd
# lKsZv6+Vfa9moW+bYm5tS7wvNWzepGpjWl/78w1NYcwKfjHrbArQTZcP/X84RuaK
# x3NpdlVplkzk2PA067qxH84pfsRPnRMVqxMbclhiVmyKgaNkd5hGZSmdgxSlTAig
# g9cjH/Nf328sz9oW2A5yBCjYaz74E7F8ohd5T37cOuSdcCdrv9v8HscH2MC+C5Me
# KOBzbdJU6ShMv2tdn/9dMxI3lSVhNGpCy3ydOruIWeGjQm06UFtI0QIDAQABo4IB
# 4zCCAd8wEAYJKwYBBAGCNxUBBAMCAQAwHQYDVR0OBBYEFNFPqYoHCM70JBiY5QD/
# 89Z5HTe8MBkGCSsGAQQBgjcUAgQMHgoAUwB1AGIAQwBBMAsGA1UdDwQEAwIBhjAP
# BgNVHRMBAf8EBTADAQH/MB8GA1UdIwQYMBaAFNX2VsuP6KJcYmjRPZSQW9fOmhjE
# MFYGA1UdHwRPME0wS6BJoEeGRWh0dHA6Ly9jcmwubWljcm9zb2Z0LmNvbS9wa2kv
# Y3JsL3Byb2R1Y3RzL01pY1Jvb0NlckF1dF8yMDEwLTA2LTIzLmNybDBaBggrBgEF
# BQcBAQROMEwwSgYIKwYBBQUHMAKGPmh0dHA6Ly93d3cubWljcm9zb2Z0LmNvbS9w
# a2kvY2VydHMvTWljUm9vQ2VyQXV0XzIwMTAtMDYtMjMuY3J0MIGdBgNVHSAEgZUw
# gZIwgY8GCSsGAQQBgjcuAzCBgTA9BggrBgEFBQcCARYxaHR0cDovL3d3dy5taWNy
# b3NvZnQuY29tL1BLSS9kb2NzL0NQUy9kZWZhdWx0Lmh0bTBABggrBgEFBQcCAjA0
# HjIgHQBMAGUAZwBhAGwAXwBQAG8AbABpAGMAeQBfAFMAdABhAHQAZQBtAGUAbgB0
# AC4gHTANBgkqhkiG9w0BAQsFAAOCAgEALkGmhrUGb/CAhfo7yhfpyfrkOcKUcMNk
# lMPYVqaQjv7kmvRt9W+OU41aqPOu20Zsvn8dVFYbPB1xxFEVVH6/7qWVQjP9DZAk
# JOP53JbK/Lisv/TCOVa4u+1zsxfdfoZQI4tWJMq7ph2ahy8nheehtgqcDRuM8wBi
# QbpIdIeC/VDJ9IcpwwOqK98aKXnoEiSahu3QLtNAgfUHXzMGVF1AtfexYv1NSPdu
# QUdSHLsbwlc6qJlWk9TG3iaoYHWGu+xipvAdBEXfPqeE0VtEI2MlNndvrlvcItUU
# I2pBf9BCptvvJXsE49KWN2IGr/gbD46zOZq7ifU1BuWkW8OMnjdfU9GjN/2kT+gb
# Dmt25LiPsMLq/XX3LEG3nKPhHgX+l5LLf1kDbahOjU6AF9TVcvZW5EifoyO6BqDA
# jtGIT5Mg8nBf2GtyoyBJ/HcMXcXH4QIPOEIQDtsCrpo3HVCAKR6kp9nGmiVV/UDK
# rWQQ6DH5ElR5GvIO2NarHjP+AucmbWFJj/Elwot0md/5kxqQHO7dlDMOQlDbf1D4
# n2KC7KaCFnxmvOyZsMFYXaiwmmEUkdGZL0nkPoGZ1ubvyuP9Pu7sCYYDBw0bDXzr
# 9FrJlc+HEgpd7MUCks0FmXLKffEqEBg45DGjKLTmTMVSo5xqx33AcQkEDXDeAj+H
# 7lah7Ou1TIUxghmdMIIZmQIBATCBkDB5MQswCQYDVQQGEwJVUzETMBEGA1UECBMK
# V2FzaGluZ3RvbjEQMA4GA1UEBxMHUmVkbW9uZDEeMBwGA1UEChMVTWljcm9zb2Z0
# IENvcnBvcmF0aW9uMSMwIQYDVQQDExpNaWNyb3NvZnQgV2luZG93cyBQQ0EgMjAx
# MAITMwAACWlp5VbrToP2TAAAAAAJaTANBglghkgBZQMEAgEFAKCBrjAZBgkqhkiG
# 9w0BCQMxDAYKKwYBBAGCNwIBBDAcBgorBgEEAYI3AgELMQ4wDAYKKwYBBAGCNwIB
# FTAvBgkqhkiG9w0BCQQxIgQg//G1F3ZufeyYsEGHStE0ahQYX5qJ7n5h/r5cTh1b
# S+MwQgYKKwYBBAGCNwIBDDE0MDKgFIASAE0AaQBjAHIAbwBzAG8AZgB0oRqAGGh0
# dHA6Ly93d3cubWljcm9zb2Z0LmNvbTANBgkqhkiG9w0BAQEFAASCAQCaiJw2JatO
# wZpGziHBggM9A4ZQ1cywgt+2KhCtK9jGD5uXnHtCb88vcNEiF/ut6MVHtfA6yGAm
# cDF6RPJfHCmQrJSLoLowXxf8NpEBIcHHOH6gY04db/Yb5bbkycjMBhPloQtzSxXm
# yuv3oDInqc/eCOMZHlvQLPVYYHDesKDzUVsR+OqVj87fiKHly93C+aJb+yjgAVpv
# C1O7fQXEe4suaIjTQ0Fplo/5m17Nx6UHJ+/5/xNPGBM3il60w1MarwsRKrb/+lud
# ZScv4ddk0gz1Sta3S6OUulX1hNINMMOCsKY8ivHMmSWPpSZNJ1NnJydEi21a38+O
# d/qh5Y3cFl6SoYIXLDCCFygGCisGAQQBgjcDAwExghcYMIIXFAYJKoZIhvcNAQcC
# oIIXBTCCFwECAQMxDzANBglghkgBZQMEAgEFADCCAVkGCyqGSIb3DQEJEAEEoIIB
# SASCAUQwggFAAgEBBgorBgEEAYRZCgMBMDEwDQYJYIZIAWUDBAIBBQAEIF8bQmxW
# tAYMr+kVzPj7bX9TD+7rAoE+7R7mmH32pX1NAgZjovNUUs8YEzIwMjMwMTE3MDQ0
# OTUyLjM1MlowBIACAfSggdikgdUwgdIxCzAJBgNVBAYTAlVTMRMwEQYDVQQIEwpX
# YXNoaW5ndG9uMRAwDgYDVQQHEwdSZWRtb25kMR4wHAYDVQQKExVNaWNyb3NvZnQg
# Q29ycG9yYXRpb24xLTArBgNVBAsTJE1pY3Jvc29mdCBJcmVsYW5kIE9wZXJhdGlv
# bnMgTGltaXRlZDEmMCQGA1UECxMdVGhhbGVzIFRTUyBFU046OEQ0MS00QkY3LUIz
# QjcxJTAjBgNVBAMTHE1pY3Jvc29mdCBUaW1lLVN0YW1wIFNlcnZpY2WgghF7MIIH
# JzCCBQ+gAwIBAgITMwAAAbP+Jc4pGxuKHAABAAABszANBgkqhkiG9w0BAQsFADB8
# MQswCQYDVQQGEwJVUzETMBEGA1UECBMKV2FzaGluZ3RvbjEQMA4GA1UEBxMHUmVk
# bW9uZDEeMBwGA1UEChMVTWljcm9zb2Z0IENvcnBvcmF0aW9uMSYwJAYDVQQDEx1N
# aWNyb3NvZnQgVGltZS1TdGFtcCBQQ0EgMjAxMDAeFw0yMjA5MjAyMDIyMDNaFw0y
# MzEyMTQyMDIyMDNaMIHSMQswCQYDVQQGEwJVUzETMBEGA1UECBMKV2FzaGluZ3Rv
# bjEQMA4GA1UEBxMHUmVkbW9uZDEeMBwGA1UEChMVTWljcm9zb2Z0IENvcnBvcmF0
# aW9uMS0wKwYDVQQLEyRNaWNyb3NvZnQgSXJlbGFuZCBPcGVyYXRpb25zIExpbWl0
# ZWQxJjAkBgNVBAsTHVRoYWxlcyBUU1MgRVNOOjhENDEtNEJGNy1CM0I3MSUwIwYD
# VQQDExxNaWNyb3NvZnQgVGltZS1TdGFtcCBTZXJ2aWNlMIICIjANBgkqhkiG9w0B
# AQEFAAOCAg8AMIICCgKCAgEAtHwPuuYYgK4ssGCCsr2N7eElKlz0JPButr/gpvZ6
# 7kNlHqgKAW0JuKAy4xxjfVCUev/eS5aEcnTmfj63fvs8eid0MNvP91T6r819dIqv
# WnBTY4vKVjSzDnfVVnWxYB3IPYRAITNN0sPgolsLrCYAKieIkECq+EPJfEnQ26+W
# Tvit1US+uJuwNnHMKVYRri/rYQ2P8fKIJRfcxkadj8CEPJrN+lyENag/pwmA0JJe
# YdX1ewmBcniX4BgCBqoC83w34Sk37RMSsKAU5/BlXbVyDu+B6c5XjyCYb8Qx/Qu9
# EB6KvE9S76M0HclIVtbVZTxnnGwsSg2V7fmJx0RP4bfAM2ZxJeVBizi33ghZHnjX
# 4+xROSrSSZ0/j/U7gYPnhmwnl5SctprBc7HFPV+BtZv1VGDVnhqylam4vmAXAdrx
# Q0xHGwp9+ivqqtdVVDU50k5LUmV6+GlmWyxIJUOh0xzfQjd9Z7OfLq006h+l9o+u
# 3AnS6RdwsPXJP7z27i5AH+upQronsemQ27R9HkznEa05yH2fKdw71qWivEN+IR1v
# rN6q0J9xujjq77+t+yyVwZK4kXOXAQ2dT69D4knqMlFSsH6avnXNZQyJZMsNWaEt
# 3rr/8Nr9gGMDQGLSFxi479Zy19aT/fHzsAtu2ocBuTqLVwnxrZyiJ66P70EBJKO5
# eQECAwEAAaOCAUkwggFFMB0GA1UdDgQWBBTQGl3CUWdSDBiLOEgh/14F3J/DjTAf
# BgNVHSMEGDAWgBSfpxVdAF5iXYP05dJlpxtTNRnpcjBfBgNVHR8EWDBWMFSgUqBQ
# hk5odHRwOi8vd3d3Lm1pY3Jvc29mdC5jb20vcGtpb3BzL2NybC9NaWNyb3NvZnQl
# MjBUaW1lLVN0YW1wJTIwUENBJTIwMjAxMCgxKS5jcmwwbAYIKwYBBQUHAQEEYDBe
# MFwGCCsGAQUFBzAChlBodHRwOi8vd3d3Lm1pY3Jvc29mdC5jb20vcGtpb3BzL2Nl
# cnRzL01pY3Jvc29mdCUyMFRpbWUtU3RhbXAlMjBQQ0ElMjAyMDEwKDEpLmNydDAM
# BgNVHRMBAf8EAjAAMBYGA1UdJQEB/wQMMAoGCCsGAQUFBwMIMA4GA1UdDwEB/wQE
# AwIHgDANBgkqhkiG9w0BAQsFAAOCAgEAWoa7N86wCbjAAl8RGYmBZbS00ss+TpVi
# Pnf6EGZQgKyoaCP2hc01q2AKr6Me3TcSJPNWHG14pY4uhMzHf1wJxQmAM5Agf4aO
# 7KNhVV04Jr0XHqUjr3T84FkWXPYMO4ulQG6j/+/d7gqezjXaY7cDqYNCSd3F4lKx
# 0FJuQqpxwHtML+a4U6HODf2Z+KMYgJzWRnOIkT/od0oIXyn36+zXIZRHm7OQij7r
# yr+fmQ23feF1pDbfhUSHTA9IT50KCkpGp/GBiwFP/m1drd7xNfImVWgb2PBcGsqd
# JBvj6TX2MdUHfBVR+We4A0lEj1rNbCpgUoNtlaR9Dy2k2gV8ooVEdtaiZyh0/VtW
# fuQpZQJMDxgbZGVMG2+uzcKpjeYANMlSKDhyQ38wboAivxD4AKYoESbg4Wk5xkxf
# RzFqyil2DEz1pJ0G6xol9nci2Xe8LkLdET3u5RGxUHam8L4KeMW238+RjvWX1RMf
# NQI774ziFIZLOR+77IGFcwZ4FmoteX1x9+Bg9ydEWNBP3sZv9uDiywsgW40k00Am
# 5v4i/GGiZGu1a4HhI33fmgx+8blwR5nt7JikFngNuS83jhm8RHQQdFqQvbFvWuuy
# Ptzwj5q4SpjO1SkOe6roHGkEhQCUXdQMnRIwbnGpb/2EsxadokK8h6sRZMWbriO2
# ECLQEMzCcLAwggdxMIIFWaADAgECAhMzAAAAFcXna54Cm0mZAAAAAAAVMA0GCSqG
# SIb3DQEBCwUAMIGIMQswCQYDVQQGEwJVUzETMBEGA1UECBMKV2FzaGluZ3RvbjEQ
# MA4GA1UEBxMHUmVkbW9uZDEeMBwGA1UEChMVTWljcm9zb2Z0IENvcnBvcmF0aW9u
# MTIwMAYDVQQDEylNaWNyb3NvZnQgUm9vdCBDZXJ0aWZpY2F0ZSBBdXRob3JpdHkg
# MjAxMDAeFw0yMTA5MzAxODIyMjVaFw0zMDA5MzAxODMyMjVaMHwxCzAJBgNVBAYT
# AlVTMRMwEQYDVQQIEwpXYXNoaW5ndG9uMRAwDgYDVQQHEwdSZWRtb25kMR4wHAYD
# VQQKExVNaWNyb3NvZnQgQ29ycG9yYXRpb24xJjAkBgNVBAMTHU1pY3Jvc29mdCBU
# aW1lLVN0YW1wIFBDQSAyMDEwMIICIjANBgkqhkiG9w0BAQEFAAOCAg8AMIICCgKC
# AgEA5OGmTOe0ciELeaLL1yR5vQ7VgtP97pwHB9KpbE51yMo1V/YBf2xK4OK9uT4X
# YDP/XE/HZveVU3Fa4n5KWv64NmeFRiMMtY0Tz3cywBAY6GB9alKDRLemjkZrBxTz
# xXb1hlDcwUTIcVxRMTegCjhuje3XD9gmU3w5YQJ6xKr9cmmvHaus9ja+NSZk2pg7
# uhp7M62AW36MEBydUv626GIl3GoPz130/o5Tz9bshVZN7928jaTjkY+yOSxRnOlw
# aQ3KNi1wjjHINSi947SHJMPgyY9+tVSP3PoFVZhtaDuaRr3tpK56KTesy+uDRedG
# bsoy1cCGMFxPLOJiss254o2I5JasAUq7vnGpF1tnYN74kpEeHT39IM9zfUGaRnXN
# xF803RKJ1v2lIH1+/NmeRd+2ci/bfV+AutuqfjbsNkz2K26oElHovwUDo9Fzpk03
# dJQcNIIP8BDyt0cY7afomXw/TNuvXsLz1dhzPUNOwTM5TI4CvEJoLhDqhFFG4tG9
# ahhaYQFzymeiXtcodgLiMxhy16cg8ML6EgrXY28MyTZki1ugpoMhXV8wdJGUlNi5
# UPkLiWHzNgY1GIRH29wb0f2y1BzFa/ZcUlFdEtsluq9QBXpsxREdcu+N+VLEhReT
# wDwV2xo3xwgVGD94q0W29R6HXtqPnhZyacaue7e3PmriLq0CAwEAAaOCAd0wggHZ
# MBIGCSsGAQQBgjcVAQQFAgMBAAEwIwYJKwYBBAGCNxUCBBYEFCqnUv5kxJq+gpE8
# RjUpzxD/LwTuMB0GA1UdDgQWBBSfpxVdAF5iXYP05dJlpxtTNRnpcjBcBgNVHSAE
# VTBTMFEGDCsGAQQBgjdMg30BATBBMD8GCCsGAQUFBwIBFjNodHRwOi8vd3d3Lm1p
# Y3Jvc29mdC5jb20vcGtpb3BzL0RvY3MvUmVwb3NpdG9yeS5odG0wEwYDVR0lBAww
# CgYIKwYBBQUHAwgwGQYJKwYBBAGCNxQCBAweCgBTAHUAYgBDAEEwCwYDVR0PBAQD
# AgGGMA8GA1UdEwEB/wQFMAMBAf8wHwYDVR0jBBgwFoAU1fZWy4/oolxiaNE9lJBb
# 186aGMQwVgYDVR0fBE8wTTBLoEmgR4ZFaHR0cDovL2NybC5taWNyb3NvZnQuY29t
# L3BraS9jcmwvcHJvZHVjdHMvTWljUm9vQ2VyQXV0XzIwMTAtMDYtMjMuY3JsMFoG
# CCsGAQUFBwEBBE4wTDBKBggrBgEFBQcwAoY+aHR0cDovL3d3dy5taWNyb3NvZnQu
# Y29tL3BraS9jZXJ0cy9NaWNSb29DZXJBdXRfMjAxMC0wNi0yMy5jcnQwDQYJKoZI
# hvcNAQELBQADggIBAJ1VffwqreEsH2cBMSRb4Z5yS/ypb+pcFLY+TkdkeLEGk5c9
# MTO1OdfCcTY/2mRsfNB1OW27DzHkwo/7bNGhlBgi7ulmZzpTTd2YurYeeNg2Lpyp
# glYAA7AFvonoaeC6Ce5732pvvinLbtg/SHUB2RjebYIM9W0jVOR4U3UkV7ndn/OO
# PcbzaN9l9qRWqveVtihVJ9AkvUCgvxm2EhIRXT0n4ECWOKz3+SmJw7wXsFSFQrP8
# DJ6LGYnn8AtqgcKBGUIZUnWKNsIdw2FzLixre24/LAl4FOmRsqlb30mjdAy87JGA
# 0j3mSj5mO0+7hvoyGtmW9I/2kQH2zsZ0/fZMcm8Qq3UwxTSwethQ/gpY3UA8x1Rt
# nWN0SCyxTkctwRQEcb9k+SS+c23Kjgm9swFXSVRk2XPXfx5bRAGOWhmRaw2fpCjc
# ZxkoJLo4S5pu+yFUa2pFEUep8beuyOiJXk+d0tBMdrVXVAmxaQFEfnyhYWxz/gq7
# 7EFmPWn9y8FBSX5+k77L+DvktxW/tM4+pTFRhLy/AsGConsXHRWJjXD+57XQKBqJ
# C4822rpM+Zv/Cuk0+CQ1ZyvgDbjmjJnW4SLq8CdCPSWU5nR0W2rRnj7tfqAxM328
# y+l7vzhwRNGQ8cirOoo6CGJ/2XBjU02N7oJtpQUQwXEGahC0HVUzWLOhcGbyoYIC
# 1zCCAkACAQEwggEAoYHYpIHVMIHSMQswCQYDVQQGEwJVUzETMBEGA1UECBMKV2Fz
# aGluZ3RvbjEQMA4GA1UEBxMHUmVkbW9uZDEeMBwGA1UEChMVTWljcm9zb2Z0IENv
# cnBvcmF0aW9uMS0wKwYDVQQLEyRNaWNyb3NvZnQgSXJlbGFuZCBPcGVyYXRpb25z
# IExpbWl0ZWQxJjAkBgNVBAsTHVRoYWxlcyBUU1MgRVNOOjhENDEtNEJGNy1CM0I3
# MSUwIwYDVQQDExxNaWNyb3NvZnQgVGltZS1TdGFtcCBTZXJ2aWNloiMKAQEwBwYF
# Kw4DAhoDFQBxi0Tolt0eEqXCQl4qgJXUkiQOYaCBgzCBgKR+MHwxCzAJBgNVBAYT
# AlVTMRMwEQYDVQQIEwpXYXNoaW5ndG9uMRAwDgYDVQQHEwdSZWRtb25kMR4wHAYD
# VQQKExVNaWNyb3NvZnQgQ29ycG9yYXRpb24xJjAkBgNVBAMTHU1pY3Jvc29mdCBU
# aW1lLVN0YW1wIFBDQSAyMDEwMA0GCSqGSIb3DQEBBQUAAgUA53BhAzAiGA8yMDIz
# MDExNzA3NDkyM1oYDzIwMjMwMTE4MDc0OTIzWjB3MD0GCisGAQQBhFkKBAExLzAt
# MAoCBQDncGEDAgEAMAoCAQACAgyQAgH/MAcCAQACAhKoMAoCBQDncbKDAgEAMDYG
# CisGAQQBhFkKBAIxKDAmMAwGCisGAQQBhFkKAwKgCjAIAgEAAgMHoSChCjAIAgEA
# AgMBhqAwDQYJKoZIhvcNAQEFBQADgYEAgRF7Pk5aoPz9GX+ii3fY5z7kyUP1ch4n
# WRATA5XmfovQoxpKnP78v0lHj/0+YMNyxcZodeEgE8xUEvXlw6vZH4lMMTO2UXVR
# 5R44Lxa2m7+q+UO+GNlBCqP81GGEb2m8mQuxcIq5fF8kMugkRVJhcw9fZpGb4f6Z
# QJ1d+XcUKiYxggQNMIIECQIBATCBkzB8MQswCQYDVQQGEwJVUzETMBEGA1UECBMK
# V2FzaGluZ3RvbjEQMA4GA1UEBxMHUmVkbW9uZDEeMBwGA1UEChMVTWljcm9zb2Z0
# IENvcnBvcmF0aW9uMSYwJAYDVQQDEx1NaWNyb3NvZnQgVGltZS1TdGFtcCBQQ0Eg
# MjAxMAITMwAAAbP+Jc4pGxuKHAABAAABszANBglghkgBZQMEAgEFAKCCAUowGgYJ
# KoZIhvcNAQkDMQ0GCyqGSIb3DQEJEAEEMC8GCSqGSIb3DQEJBDEiBCAXLRCa0jei
# 15VC8ueLIColviRdg/ikl3SecHPMkCekBzCB+gYLKoZIhvcNAQkQAi8xgeowgecw
# geQwgb0EIIahM9UqENIHtkbTMlBlQzaOT+WXXMkaHoo6GfvqT79CMIGYMIGApH4w
# fDELMAkGA1UEBhMCVVMxEzARBgNVBAgTCldhc2hpbmd0b24xEDAOBgNVBAcTB1Jl
# ZG1vbmQxHjAcBgNVBAoTFU1pY3Jvc29mdCBDb3Jwb3JhdGlvbjEmMCQGA1UEAxMd
# TWljcm9zb2Z0IFRpbWUtU3RhbXAgUENBIDIwMTACEzMAAAGz/iXOKRsbihwAAQAA
# AbMwIgQg+qnSCH9MMcrr85dc+Mp1yiB4mIwWwDjgtSHyLtQSN9kwDQYJKoZIhvcN
# AQELBQAEggIAcQe9+BcJUtpdnXsx0HzdZm1BibJqy9RRr7qwx79Or0y0GXM6Hyso
# MZRTLQt3tp3JP29Iye1Az8EzxY/P15CsNnuQ4TQOAbLsm5AXTZzwp0Q5NqPMaQEH
# 2Yl8imB1O1SrEoRG7NBz6XozTeXNUxIxiIKP7k0cf1cOawBRmpmQOOPeAk89Cq2O
# GeLbx23z21BOJhPn7AP+UQ9+9I1HEeIRDWpzm4bwhPvqOO7Ge0lo7gliy+vbGvVn
# uedXx9LH8taeqAn3Cc+lxJwdg2T3Rlt99UP4vPAKWLVKOyVTIjOEBgIOlUePi75x
# byzcIQ8mp5k+FIKpB6pXt+OHKJhxuoLFL1SAKEeOb4XcRr9P16woG9tPVJ28ssZi
# eSVamuQNqBWBCfS4Sp0Z92NYJtdDfefRLjSpXIwnz0DmAe4kzcznMsE6y4PZ/N8l
# pUiiwaKsftX91loYORi70pw7d/H83r5qDRWY1fRqq5RRyUOe7oZF8ypGwJeVQjGr
# bLEGEgRNxD6eSryTENBy1fEjjKqq9X/WB7dpCrCTMczJxVNyl5xyx/U5Q6g5rtXj
# DOqiBf3XFxMnkZtI9rsiK0s0WSUwrJYmyiXA4x100EHLDlt2YfnTjZS3tfPJJU3a
# gNDTbZe5daHn+y4z4lX8UgPZ6AdsXpkb2kul8l+jy4ixGCFmBgU0ddQ=
# SIG # End signature block
