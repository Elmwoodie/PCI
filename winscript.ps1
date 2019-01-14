
param([string[]]$ComputerName,[string]$path='.\',[string[]]$TCPTestEndpoints=@('google.com','facebook.com','RDP01.PS.PHX1.winsys.tmcs'),[int[]]$TCPTestPorts=@(80,443,3389))

function HTMLTableSection {
    param([string]$title, [object[]]$Object, [string[]]$Properties = '*')
    $Object | ConvertTo-Html -As Table -Property $Properties -PreContent "<h2>$title</h2>" | Out-String
}

function HTMLListSection {
    param([string]$title, [object]$Object, [string[]]$Properties = '*')
    $Object | ConvertTo-Html -As List -Property $Properties -PreContent "<h2>$title</h2>" | Out-String
}

function TextSection {
    param([string]$title, [String[]]$String)
    "<h2>$title</h2>`r`n<pre>`r`n$($string | Out-String)`r`n</pre>`r`n" | Out-String
}



$scripBlock = {
    param(
        [string[]]$TCPTestEndpoints = 'google.com',
        [int[]]$TCPTestPorts = 80
    )
    function TestTCPPort {
        Param(
            [string[]]$ComputerName,
            [int[]]$port
        )

        foreach($Computer in $ComputerName){
            foreach ($PortNumber in $port){
                $returnObject = New-Object -TypeName psobject -Property @{
                    Target = $Computer
                    Port = $PortNumber
                    Open = $true
                    Notes = [string]::Empty
                }
                $tcpObj = New-Object System.Net.Sockets.TcpClient
                $Connect = $tcpObj.BeginConnect($Computer,$PortNumber,$null,$null)
                $wait = $Connect.AsyncWaitHandle.WaitOne(1000,$false)
                if(! $wait){
                    $returnObject.Open = $false
                    $returnObject.Notes = "Connection timed out"
                } else {
                    $error.Clear()
                    #$tcpObj.EndConnect($Connect) | Out-Null
                    if($error.Count -ne 0){
                        [string]$string = ($error[0].exception).message
                        $message = (($string.split(":")[1]).replace('"',"")).TrimStart()
                        $failed = $true
                    }
                    $tcpObj.Close()
                    if($failed){
                        $returnObject.Open = $false
                        $returnObject.Notes = $message
                    }
                }
                $returnObject
            }
        }
    }
if (Test-Path \\$env:COMPUTERNAME\SYSVOL)
    {
        $hash = @{
            ComputerName          = $env:COMPUTERNAME
            Processes             = Get-Process -ErrorAction SilentlyContinue
            Services              = Get-Service -ErrorAction SilentlyContinue
            LocalAccounts         = $null
            LocalGroupMembership  = $null
            GPResult              = gpresult.exe /SCOPE COMPUTER /Z
            WindowsFeatures       = $(if($null -ne (Get-Command -Name 'Get-WindowsFeature' -ErrorAction SilentlyContinue)){Get-WindowsFeature  -ErrorAction SilentlyContinue})
            RDPEncryptionLevel    = Get-WmiObject -Class 'Win32_TSGeneralSetting' -Namespace 'root/CIMV2/TerminalServices' -ErrorAction SilentlyContinue
            LogForwarding         = Get-ItemProperty -Path 'HKLM:\Software\Policies\Microsoft\Windows\EventLog\EventForwarding\SubscriptionManager'  -ErrorAction SilentlyContinue
            networkConnections    = netstat -a
            InstalledApplications = Get-WmiObject -Class Win32_Product -ErrorAction SilentlyContinue
            installedUpdates      = Get-HotFix -ErrorAction SilentlyContinue
            WindowsInfoLegacy     = systeminfo
            IPCOnfigLegacy        = ipconfig /all
            SNMPSettings          = @{
                Managers          = Get-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\services\SNMP\Parameters\PermittedManagers' -ErrorAction SilentlyContinue
                TrapConfiguration = Get-ChildItem -Path 'HKLM:\SYSTEM\CurrentControlSet\services\SNMP\Parameters\TrapConfiguration' -ErrorAction SilentlyContinue | ForEach-Object {
                    New-Object -TypeName psobject -Property @{
                        "Trap"     = $_.Name
                        "Managers" = Get-ItemProperty -Path $_.PSPath  -ErrorAction SilentlyContinue
                    }
                }
            }
            TrendMicroData        = Get-ItemProperty -Path 'HKLM:\SOFTWARE\Wow6432Node\TrendMicro\PC-cillinNTCorp\CurrentVersion\Misc.'  -ErrorAction SilentlyContinue

            TCPConnectivity = TestTCPPort -ComputerName $TCPTestEndpoints -port $TCPTestPorts

        }
    }
    else
    {
        $hash = @{
            ComputerName          = $env:COMPUTERNAME
            Processes             = Get-Process -ErrorAction SilentlyContinue
            Services              = Get-Service -ErrorAction SilentlyContinue
            LocalAccounts         = Get-WmiObject -Class Win32_UserAccount -Filter  "LocalAccount='True'"  -ErrorAction SilentlyContinue
            LocalGroupMembership  = Foreach ($Group in (Get-WmiObject -Class win32_group -Filter "LocalAccount='True'"  -ErrorAction SilentlyContinue)) {
                foreach ($GU in (Get-WmiObject -Class  win32_GroupUser -Filter "GroupComponent='$($Group.__RELPATH)'"  -ErrorAction SilentlyContinue)) {
                    New-Object -TypeName psobject -Property @{
                        GroupName    = ([wmi]$GU.GroupComponent).Name
                        GroupCaption = ([wmi]$GU.GroupComponent).Caption
                        #UserName     = ([wmi]$GU.PartComponent).Name
                        UserName      = (($GU | select -ExpandProperty PartComponent).split('=')[2]).replace('"','')
                        #UserCaption  = ([wmi]$GU.PartComponent).Caption
                    }
                }
            }
            GPResult              = gpresult.exe /SCOPE COMPUTER /Z
            WindowsFeatures       = $(if($null -ne (Get-Command -Name 'Get-WindowsFeature' -ErrorAction SilentlyContinue)){Get-WindowsFeature  -ErrorAction SilentlyContinue})
            RDPEncryptionLevel    = Get-WmiObject -Class 'Win32_TSGeneralSetting' -Namespace 'root/CIMV2/TerminalServices' -ErrorAction SilentlyContinue
            LogForwarding         = Get-ItemProperty -Path 'HKLM:\Software\Policies\Microsoft\Windows\EventLog\EventForwarding\SubscriptionManager'  -ErrorAction SilentlyContinue
            networkConnections    = netstat -a
            InstalledApplications = Get-WmiObject -Class Win32_Product -ErrorAction SilentlyContinue
            installedUpdates      = Get-HotFix -ErrorAction SilentlyContinue
            WindowsInfoLegacy     = systeminfo
            IPCOnfigLegacy        = ipconfig /all
            SNMPSettings          = @{
                Managers          = Get-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\services\SNMP\Parameters\PermittedManagers' -ErrorAction SilentlyContinue
                TrapConfiguration = Get-ChildItem -Path 'HKLM:\SYSTEM\CurrentControlSet\services\SNMP\Parameters\TrapConfiguration' -ErrorAction SilentlyContinue | ForEach-Object {
                    New-Object -TypeName psobject -Property @{
                        "Trap"     = $_.Name
                        "Managers" = Get-ItemProperty -Path $_.PSPath  -ErrorAction SilentlyContinue
                    }
                }
            }
            TrendMicroData        = Get-ItemProperty -Path 'HKLM:\SOFTWARE\Wow6432Node\TrendMicro\PC-cillinNTCorp\CurrentVersion\Misc.'  -ErrorAction SilentlyContinue

            TCPConnectivity = TestTCPPort -ComputerName $TCPTestEndpoints -port $TCPTestPorts

        }
    }
  $hash
}

Function BuildReport {
    param([hashtable]$InfoHash,[String]$footer='')
    $Template = @'
<!DOCTYPE html PUBLIC "-//W3C//DTD XHTML 1.0 Strict//EN"  "http://www.w3.org/TR/xhtml1/DTD/xhtml1-strict.dtd">
<html xmlns="http://www.w3.org/1999/xhtml">
<head>
<title>{0}</title>
<style>
table {{border-collapse: collapse;border: 2px solid #000000;color: #000000}}
table td {{border: 1px solid #000000;vertical-align: top;background-color: #FFFFFF}}
table th {{border: 1px solid;padding: 8pt 2pt 5pt 2pt;font-weight: bold;vertical-align: middle;background-color: #FFFFFF;}}
table td:first-of-type {{font-weight: bold;border-right: 2px solid #000000;}}
table tr:nth-child(even) td:nth-child(odd) {{background-color: #FFFFFF;}}
table tr:nth-child(even) td:nth-child(even) {{background-color: #FFFFFF;}}
table tr:nth-child(odd) td:nth-child(odd) {{background-color: #FFFFFF;}}
table tr:nth-child(odd) td:nth-child(even) {{background-color: #FFFFFF;}}
table th:nth-child(even) {{background-color: #FFFFFF;}}
</style>

</head><body>
<h1>{1}</h1>
{2}
{3}
</body></html>
'@
    $title = $InfoHash['ComputerName']
    $sections = @()
    $sections += HTMLTableSection -title "Processes" -Object $InfoHash["Processes"] -Properties name, Path, MainModule
    $sections += HTMLTableSection -title "Services" -Object $InfoHash["Services"] -Properties name, DisplayName, Status
    $sections += HTMLTableSection -title "Local Accounts" -Object $InfoHash["LocalAccounts"] -Properties Caption, Domain, Name
    $sections += HTMLTableSection -title "Local Group Membership" -Object $InfoHash["LocalGroupMembership"] -Properties UserName, GroupName, GroupCaption, UserCaption
    $sections += TextSection -title "Group Policy Results (GPResult)" -String $InfoHash["GPResult"]
    $sections += HTMLTableSection -title "Windows Features" -Object $InfoHash["WindowsFeatures"] -Properties Name, DisplayName, Installed
    $sections += (HTMLListSection -title "RDPEcryption Level" -Object $InfoHash["RDPEncryptionLevel"] -Properties MinEncryptionLevel) + "`r`n`r`n<strong>Legend</strong><table><tr><td rowspan=`"3`"><strong>MinEncryptionLevel</strong></td><td>1:</td><td>Low</td></tr><tr><td>2:</td><td>Medium</td></tr><tr><td>3:</td><td>High</td></tr><tr><td rowspan=`"3`"><strong>PolicySourceMinEncryptionLevel</strong></td><td>1:</td><td>Server</td></tr><tr><td>2:</td><td>Group policy</td></tr><tr><td>3:</td><td>Default</td></tr></table><hr />"
    $sections += HTMLListSection -title "Log Forwarding" -Object $InfoHash["LogForwarding"] -Properties ($InfoHash["LogForwarding"].psobject.Properties | ForEach-Object {$_.name} | Where-Object {$_ -match "^\d+$"})
    $sections += TextSection -title "Network Connections (netstat -a)" -String $InfoHash["networkConnections"]
    $sections += HTMLTableSection -title "Installed Applications" -Object $InfoHash["InstalledApplications"] -Properties Name, Vendor, Version, Caption, IdentifyingNumber
    $sections += HTMLTableSection -title "Installed Updates" -Object $InfoHash["installedUpdates"] -Properties Source, Description, HotFixID, InstalledBy, InstalledOn
    $sections += TextSection -title "Windows Information (systeminfo)" -String $InfoHash["WindowsInfoLegacy"]
    $sections += TextSection -title "IP Configuration (ipconfig /all)" -String $InfoHash["IPCOnfigLegacy"]
    $sections += HTMLListSection -title "SNMP Managers" -Object $InfoHash["SNMPSettings"]['Managers'] -Properties ($InfoHash["installedUpdates"]['Managers'].psobject.Properties | ForEach-Object {$_.name} | Where-Object {$_ -match "^\d+$"})
    foreach ($trap in $InfoHash["SNMPSettings"]['TrapConfiguration']) {
        $sections += HTMLListSection -title "SNMP Trap: $($trap.Trap)" -Object $trap.Managers -Properties ($trap.Managers.psobject.Properties | ForEach-Object {$_.name} | Where-Object {$_ -match "^\d+$"})
    }
    $sections += HTMLListSection -title "TrendMicro Data" -Object $InfoHash["TrendMicroData"] -Properties ($InfoHash["TrendMicroData"].psobject.Properties | ForEach-Object {$_.name} | Where-Object {$_ -match "^\d+$"})
    $sections += HTMLTableSection -title "TCP Connectivity" -Object $InfoHash['TCPConnectivity'] -Properties 'Port','Target','Open','Notes'
    $report = $Template -f $title, $title, $($Sections -join "`r`n<hr />`r`n"),$footer
    $report
}

$computers = If($null -eq $ComputerName){@{}}else{@{ComputerName=$ComputerName}}

$results = Invoke-Command @computers -ScriptBlock $scripBlock -ArgumentList $TCPTestEndpoints,$TCPTestPorts

If(! (Test-Path -Path $path -PathType Container)){
    New-Item -Path $path -ItemType Directory | Out-Null
}

foreach($result in $results){
    $reportContent = BuildReport -InfoHash $result | Out-String
    New-Item -Force -ItemType File -Path $path -Name "$($result['ComputerName']).html" -Value $reportContent
}
