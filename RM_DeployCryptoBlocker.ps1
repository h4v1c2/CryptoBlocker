# DeployCryptoBlocker.ps1 - Based off works from Nexxai
#
# Updated Dec 2017 RM
# Implement working skip list & exclusions list Oct 2017
# Implement E-Mail & Event Log notifications Nov 2017
# Dec 2017 - Add folder screen exception to ignore Windows Updates to reduce spam levels - C:\Windows\WinSxS\Temp\PendingDeletes
# April 2019 - Include Proxy authentication method - $webClient.Proxy.Credentials =[System.Net.CredentialCache]::DefaultNetworkCredentials
# April 2019 - Added IF check to see if a local copy of the API data exists, else use online version

$StartTime = Get-Date
# Active screening: Do not allow users to save unathorized files
$fileTemplateType = "Active"
# Passive screening: Allow users to save unathorized files (use for monitoring)
# $fileTemplateType = "Passive"

# Write the email options to the temporary file - comment out the entire block if no email notification should be set
$EmailNotification = $env:TEMP+"\tmpMail001.tmp"
"Notification=m" >> $EmailNotification
"To=[Admin Email]" >> $EmailNotification
"ReplyTo=[Admin Email]" >> $EmailNotification
"Subject=Unauthorized file from the [Violated File Group] file group detected!" >> $EmailNotification
"Message=User [Source Io Owner] attempted to save [Source File Path] to [File Screen Path] on the [Server] server. This file is in the [Violated File Group] file group, which is not permitted on the server." >> $EmailNotification

# Write the event log options to the temporary file - comment out the entire block if no event notification should be set
#$EventNotification = $env:TEMP+"\tmpEvent001.tmp"
#"Notification=e" >> $EventNotification
#"EventType=Error" >> $EventNotification
#"Message=The system detected that user [Source Io Owner] saved [Source File Path] on [File Screen Path] on server [Server]. This file matches the [Violated File Group] file group. These files can be harmful as they may contain malicious code or viruses." >> $EventNotification

################################ Functions ################################

function ConvertFrom-Json20([Object] $obj)
{
    Add-Type -AssemblyName System.Web.Extensions
    $serializer = New-Object System.Web.Script.Serialization.JavaScriptSerializer
    return ,$serializer.DeserializeObject($obj)
}

Function New-CBArraySplit {

    param(
        $extArr,
        $depth = 1
    )

    $extArr = $extArr | Sort-Object -Unique

    # Concatenate the input array
    $conStr = $extArr -join ','
    $outArr = @()

    # If the input string breaks the 4Kb limit
    If ($conStr.Length -gt 4000) {
        # Pull the first 4000 characters and split on comma
        $conArr = $conStr.SubString(0,4000).Split(',')
        # Find index of the last guaranteed complete item of the split array in the input array
        $endIndex = [array]::IndexOf($extArr,$conArr[-2])
        # Build shorter array up to that indexNumber and add to output array
        $shortArr = $extArr[0..$endIndex]
        $outArr += [psobject] @{
            index = $depth
            array = $shortArr
        }

        # Then call this function again to split further
        $newArr = $extArr[($endindex + 1)..($extArr.Count -1)]
        $outArr += New-CBArraySplit $newArr -depth ($depth + 1)
        
        return $outArr
    }
    # If the concat string is less than 4000 characters already, just return the input array
    Else {
        return [psobject] @{
            index = $depth
            array = $extArr
        }  
    }
}

################################ Functions ################################

# Add to all drives
$drivesContainingShares = Get-WmiObject Win32_Share | Select Name,Path,Type | Where-Object { $_.Type -eq 0 } | Select -ExpandProperty Path | % { "$((Get-Item -ErrorAction SilentlyContinue $_).Root)" } | Select -Unique
if ($drivesContainingShares -eq $null -or $drivesContainingShares.Length -eq 0)
{
    Write-Host "No drives containing shares were found. Exiting.  .  ." -f "Red"
    exit
}

Write-Host "The following shares need to be protected: $($drivesContainingShares -Join ",")"

$majorVer = [System.Environment]::OSVersion.Version.Major
$minorVer = [System.Environment]::OSVersion.Version.Minor

Write-Host "Checking File Server Resource Manager .  .  ."

#Import-Module ServerManager

# Code added here to support Server 2016
if ($majorVer -ge 10)
    {Import-Module ServerManager
	$checkFSRM = Get-WindowsFeature -Name FS-Resource-Manager, RSAT-FSRM-Mgmt
    if ($minorVer -ge 0 -and $checkFSRM.Installed -ne "True")
    {
    # Server 2016
        Write-Host "FSRM not found. Installing for Server 2016 . .  ." -f "Yellow"
        Install-WindowsFeature -Name FS-Resource-Manager, RSAT-FSRM-Mgmt
     }
# End new code for Server 2016

elseif ($majorVer -ge 6){
If ($minorVer -ge 1){
	{Import-Module ServerManager
    $checkFSRM = Get-WindowsFeature -Name FS-Resource-Manager, RSAT-FSRM-Mgmt

# Add check for Server 2012 R2
    if ($minorVer -ge 3 -and $checkFSRM.Installed -ne "True")
    {
        # Server 2012 R2
        Write-Host "FSRM not found. Installing for Server 2012 R2 . .  ." -f "Yellow"
        Install-WindowsFeature -Name FS-Resource-Manager, RSAT-FSRM-Mgmt
    }
# End check for Server 2012 R2
    elseif ($minorVer -ge 2 -and $checkFSRM.Installed -ne "True")
    {
        # Server 2012
        Write-Host "FSRM not found. Installing for Server 2012 . .  ." -f "Yellow"
        Install-WindowsFeature -Name FS-Resource-Manager, RSAT-FSRM-Mgmt
    }
    elseif ($minorVer -ge 1 -and $checkFSRM.Installed -ne "True")
    {
        # Server 2008 R2
        Write-Host "FSRM not found. Installing for Server 2008 R2 . .  ." -f "Yellow"
        Add-WindowsFeature FS-FileServer, FS-Resource-Manager, RSAT-FSRM-Mgmt
    }}
}
    # Break this portion from above loop - Import-Module ServerManager not supported on Server 2008
elseif ($checkFSRM.Installed -ne "True")
    {
        # Server 2008
        Write-Host "FSRM not found. Installing for Server 2008 .  .  ." -f "Yellow"
        &servermanagercmd -Install FS-FileServer, FS-Resource-Manager -IncludeManagementTools
    }
}
else
{
    # Assume Server 2003
    Write-Host "Unsupported Windows detected! Quitting .  .  ." -f "Red"
    return
}} # Add Server 2008 (-R2 & 2003) into minor loop check

$fileGroupName = "CryptoBlockerGroup"
$fileTemplateName = "CryptoBlockerTemplate"
$fileScreenName = "CryptoBlockerScreen"

$webClient = New-Object System.Net.WebClient
$webClient.Proxy.Credentials =[System.Net.CredentialCache]::DefaultNetworkCredentials
If (Test-Path .\FSRM.json) {Write-Host "Using local data"; $jsonStr = $webClient.DownloadString(".\FSRM.josn")}
Else {Write-Host "Using online data"; $jsonStr = $webClient.DownloadString("https://fsrm.experiant.ca/api/v1/get")}
$monitoredExtensions = @(ConvertFrom-Json20($jsonStr) | % { $_.filters })

# Process SkipList.txt
Write-Host "Checking for Skip List.  .  ." -f "Green"
If (Test-Path .\SkipList.txt)
{
    Write-Host "Processing Skip List.  .  ." -f "Green"
    $Skiplist = @(Get-Content .\SkipList.txt | ForEach-Object { $_.Trim() })
    $monitoredExtensions = $monitoredExtensions | Where-Object { $SkipList -notcontains $_ }

}
Else 
{
    Write-Host "SkipList.txt not found. Nothing to skip. Continuing.  .  ." -f "Green"
}

# Split the $monitoredExtensions array into fileGroups of less than 4kb to allow processing by filescrn.exe
$fileGroups = New-CBArraySplit $monitoredExtensions
ForEach ($group in $fileGroups) {
    $group | Add-Member -MemberType NoteProperty -Name fileGroupName -Value "$FileGroupName$($group.index)"
}

# Check for any exclusions to process
Write-Host "Checking for Exclusion List.  .  ." -f "Green"
If (Test-Path .\ExcludeList.txt)
{
Write-Host "Processing Exclude List.  .  ." -f "Green"
$ExcludeList = Get-Content -path .\ExcludeList.txt
ForEach ($Exclude in $ExcludeList) {
    $Exclude | Add-Member -MemberType NoteProperty -Name fileGroupName -Value "$FileGroupName$($exclude.index)"
}
}
Else
{
Write-Host "ExcludeList.txt not found. Nothing to exclude. Continuing.  .  ." -f "Green"
}

# Perform these steps for each of the 4KB limit split fileGroups
ForEach ($group in $fileGroups) {
    Write-Host "Building File Group [$($group.fileGroupName)] with monitored file [$($group.array -Join ",")].  .  ."
    &filescrn.exe filegroup Delete "/Filegroup:$($group.fileGroupName)" /Quiet
    &filescrn.exe Filegroup Add "/Filegroup:$($group.fileGroupName)" "/Members:$($group.array -Join '|')" "/NonMembers:$($Excludelist -Join '|')"
    $cry += @($($group.fileGroupName))
}

Write-Host "Building File Screen Template [$fileTemplateName] with Event Notification [$eventConfFilename] and Command Notification [$cmdConfFilename].  .  ."
&filescrn.exe Template Delete /Template:$fileTemplateName /Quiet
# Build the argument list with all required fileGroups
$screenArgs = 'Template','Add',"/Template:$fileTemplateName", "/Type:$fileTemplateType"
ForEach ($group in $fileGroups) {
    $screenArgs += "/Add-Filegroup:$($group.fileGroupName)"
}
If ($EmailNotification -ne $null) {
    $screenArgs += "/Add-Notification:m,$EmailNotification"
}
If ($EventNotification -ne $null) {
    $screenArgs += "/Add-Notification:e,$EventNotification"
}

&filescrn.exe $screenArgs

Write-Host "Adding File Screens.  .  ."
$drivesContainingShares | % {
    Write-Host "Adding File Screen for [$_] with Source Template [$fileTemplateName].  .  ."
    &filescrn.exe Screen Delete "/Path:$_" /Quiet
    &filescrn.exe Exception Delete "/path:C:\Windows\WinSxS\Temp\PendingDeletes" /quiet
    &filescrn.exe Screen Add "/Path:$_" "/SourceTemplate:$fileTemplateName"
    # Add path exception for Windows Update spam
    &filescrn.exe exception add "/path:C:\Windows\WinSxS\Temp\PendingDeletes" "/Add-Filegroup:$($cry[0])"
}

$counter = $cry.count -1
ForEach ($Exceptions in $Cry[1..$counter]) {
	&filescrn exception modify "/p:c:\windows\winsxs\temp\pendingdeletes" "/a:$exceptions"
}

Write-Host "Cleaning up temporary files.  .  ." -f "Yellow"
If ($EmailNotification -ne $null) {
	Remove-Item $EmailNotification -Force
}
 If ($EventNotification -ne $null) {
	Remove-Item $EventNotification -Force
}
If ($ExcludeList -ne $Null){
    ForEach ($ExcludeOut in $ExcludeList){
        Write-Host "Excluded $ExcludeOut from FSRM monitoring." -f Yellow
    }
}
If ($SkipList -ne $Null){
    ForEach ($SkipOut in $SkipList){
        Write-Host "Removed $SkipOut file type from FSRM monitoring." -f Yellow
    }
}

$EndTime = Get-Date
Write-Host "Process Complete" -f "Green"
