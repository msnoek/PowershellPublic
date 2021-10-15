#Script to check if various security agents are installed and up-to-date, and if not, install current version.


function Check-Install { #Function to check and make sure that the software is not installed already

    $installed = (Get-ItemProperty HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\* | Where { $_.DisplayName -eq $Software }) -ne $null

    If(-Not $installed) {
     return $false 
    } else {
    return $true 
    }
}

function Install-Agent01 { #Function to install Agent01 using Powershell 2.0 compatible commands
    #Gets the TEMP folder path from environment variables, downloads the installer to that path, then runs the installer
    $TempFolder = $env:TEMP
    $Agent01Installer = "$TempFolder\Agent01Installer.exe"
    $uri = "http://avfix.ra.rockwell.com/Agent01/WindowsSensor 6.21.exe" #http, not http, because powershell v2.0 and older .NET can't handle TLS1.2
    $CID = "CID=xxxxxxx" #customer ID for Agent01 install
    Write-Host "Attempting to Download Agent01 installer file to $Agent01Installer" -ForegroundColor Yellow
    try{
        (new-object System.Net.WebClient).DownloadFile($uri, $Agent01Installer)
    }catch{
        Write-Host "Failed to download installer file from $uri, please check and see if this site is accessible." -ForegroundColor Red
        Return #Exits function since download of installer file failed
    }
    Write-Host "Attempting to install Agent01."  -ForegroundColor Yellow
    Invoke-Expression "$Agent01Installer /install /quiet /norestart $CID VDI=1"
    Start-Sleep -Seconds 60
}

function Install-Agent02 {#function to install Agent02 with Powershell v2.0 compatible commands
    #Gets the TEMP folder path from environment variables, downloads the installer to that path, then runs the installer
    $TempFolder = $env:TEMP
    $Agent02Installer = "$TempFolder\agent02Installer.msi"
    $uri = "http://example.downloadpath.com/Agent02/agent02Installer.msi" #http, not http, because powershell v2.0 and older .NET can't handle TLS1.2
    Write-Host "Downloading Agent02 installer file to $Agent02Installer." -ForegroundColor Yellow
    try{
        (new-object System.Net.WebClient).DownloadFile($uri, $Agent02Installer)
    }catch{
        Write-Host "Failed to download installer file from $uri, please check and see if this site is accessible." -ForegroundColor Red
        Return #Exits function since download of installer file failed
    }
    Write-Host "Attempting to install Agent02." -ForegroundColor Yellow
    msiexec /i $Agent02Installer /l*v $TempFolder\Agent02Installer.log CUSTOMTOKEN=us:xxxxx /quiet
    Start-Sleep -Seconds 60
}

function Install-Agent02v2 {#function to install Rpaid7 over existing older versions
    $AgentService = "agent_service"
    $SnapshotPath = "C:\path\to\snapshots"
    $TempFolder = $env:TEMP
    $Agent02Installer = "$TempFolder\Agent02Installer.msi"
    $uri = "http://example.downloadpath.com/Agent02/agent02Installer.msi" #http, not http, because powershell v2.0 and older .NET can't handle TLS1.2
    Write-Host "Downloading Agent02 installer file to $Agent02Installer." -ForegroundColor Yellow
    try{
        (new-object System.Net.WebClient).DownloadFile($uri, $Agent02Installer)
    }catch{
        Write-Host "Failed to download installer file from $uri, please check and see if this site is accessible." -ForegroundColor Red
        Return #Exits function since download of installer file failed
    }
    Write-Host "Stopping $AgentService" -ForegroundColor Yellow
    Stop-Service $AgentService
    Write-Host "Deleting registry entries" -ForegroundColor Yellow
    try {
        New-PSDrive -PSProvider registry -Root HKEY_CLASSES_ROOT -Name HKCR
        Remove-Item -path HKLM:\SOFTWARE\Agent02 -Force -Recurse
        Remove-Item -path HKCR:\Installer\Products\xxxxxxx -Force -Recurse
        Remove-Item -path HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Installer\UserData\S-1-5-18\Components\xxxxxxx -Force -Recurse
    }catch{
        Write-Host "Failed to delete old $Software registry entries. This is likely to be because they either do not exist, or are not in the expected location." -ForegroundColor Red
    }
    Write-Host "Taking ownership of $Snapshotpath and deleting" -ForegroundColor Yellow
    Try {
        TakeOwn.exe /a /r /d Y /f "$SnapshotPath"
        Remove-Item -path "$SnapshotPath" -Force -Recurse
        Remove-Item -path "C:\Program Files\Agent02" -Force -Recurse
    }catch{
        Write-Host "Failed to take ownership of $Snapshot and delete C:\Program Files\Agent02. The most likely reason for this is that the path does not exist." -ForegroundColor Red
    }
    Write-Host "Removing service $AgentService" -ForegroundColor Yellow
    sc.exe delete "$AgentService"

    Write-Host "Installing Agent02" -ForegroundColor Yellow
    msiexec /i $Agent02Installer /l*v $tempfolder\agent02installer.log CUSTOMTOKEN=us:xxxxx /quiet
    Start-Sleep -Seconds 60

}

function Install-Agent03 {#function to install Agent02 with Powershell v2.0 compatible commands
    #Gets the TEMP folder path from environment variables, downloads the installer to that path, then runs the installer
    $TempFolder = $env:TEMP
    $Agent03Installer = "$TempFolder\Agent03Installer.msi"
    $Transform = "$TempFolder\Agent03Installer.mst"
    $uri_1 = "http://example.downloadpath.com/Agent03/agent03Installer.msi" #http, not http, because powershell v2.0 and older .NET can't handle TLS1.2
    $uri_2 = "http://example.downloadpath.com/Agent02/agent03Installer.msi.mst.txt" #http, not http, because powershell v2.0 and older .NET can't handle TLS1.2
    Write-Host "Downloading Agent03 installer file to $Agent03Installer." -ForegroundColor Yellow
    try{
        (new-object System.Net.WebClient).DownloadFile($uri_1, $Agent03Installer)
    }catch{
        Write-Host "Failed to download installer file from $uri_1, please check and see if this site is accessible." -ForegroundColor Red
        Return #Exits function since download of installer file failed
    }
    Write-Host "Downloading Agent03 msi file to $Transform." -ForegroundColor Yellow
    try{
        (new-object System.Net.WebClient).DownloadFile($uri_2, $Transform)
    }catch{
        Write-Host "Failed to download installer file from $uri_2, please check and see if this site is accessible." -ForegroundColor Red
        Return #Exits function since download of installer file failed
    }

    Write-Host "Attempting to install Agent03." -ForegroundColor Yellow
    msiexec /i "$TempFolder\Agent03Installer.msi" TRANSFORMS="$Transform" /l*v "$TempFolder\Agent03InstallerUnInstall.log" /qn
    Write-Host "Sleeping for 60 seconds" -ForegroundColor Yellow
    Start-Sleep -Seconds 60

    Write-Host "Checking for existing Agent03 configuration file." -ForegroundColor Yellow
    if (test-path -Path "c:\Program Files\Agent03\sample.conf" -PathType Leaf)
    { Continue }
    else {
    if (-Not (test-path -Path "c:\Program Files\Agent03\seed.conf" -PathType Leaf)) {
        try {
            New-Item -ItemType "file" -Path "c:\Program Files\Agent03\seed.conf"
            ADD-Content -Path "c:\Program Files\Agent03\seed.conf" -Value "[user_info]"
            ADD-Content -Path "c:\Program Files\Agent03\seed.conf" -Value "USERNAME = admin"
            ADD-Content -Path "c:\Program Files\Agent03\seed.conf" -Value "PASSWORD = xxxxxx"
        }catch{
            Write-Host "Failed to create the Agent03 seed.conf file" -ForegroundColor Red
        }
    }

    Write-Host "Restarting Agent03 service (this may throw an error due to the service being slow to stop)" -ForegroundColor Yellow
    Stop-Service -Name Agent03Service -Force -ErrorAction SilentlyContinue

    Start-Sleep -s 60

    Start-Service -Name Agent03Service

    Write-Host "Setting the poller" -ForegroundColor Yellow
    invoke-expression "cmd.exe /c 'c:\Program Files\Agent03\Agent03.exe' set deploy-poll fqdn.controlserver.address:xxxx -auth admin:xxxxxx"

    }
}

function Install-Agent03v2 {#function to install Agent03 over an older version
    #Gets the TEMP folder path from environment variables, downloads the installer to that path, then runs the installer
    $TempFolder = $env:TEMP
    $Agent03Installer = "$TempFolder\Agent03Installer.msi"
    $Transform = "$TempFolder\Agent03Installer.mst"
    $uri_1 = "http://example.downloadpath.com/Agent03/agent03Installer.msi" #http, not http, because powershell v2.0 and older .NET can't handle TLS1.2
    $uri_2 = "http://example.downloadpath.com/Agent02/agent03Installer.msi.mst.txt" #http, not http, because powershell v2.0 and older .NET can't handle TLS1.2
    Write-Host "Downloading Agent03 installer file to $Agent03Installer." -ForegroundColor Yellow
    try{
        (new-object System.Net.WebClient).DownloadFile($uri_1, $Agent03Installer)
    }catch{
        Write-Host "Failed to download installer file from $uri_1, please check and see if this site is accessible." -ForegroundColor Red
        Return #Exits function since download of installer file failed
    }
    Write-Host "Downloading Agent03 msi file to $Transform." -ForegroundColor Yellow
    try{
        (new-object System.Net.WebClient).DownloadFile($uri_2, $Transform)
    }catch{
        Write-Host "Failed to download installer file from $uri_2, please check and see if this site is accessible." -ForegroundColor Red
        Return #Exits function since download of installer file failed
    }
    Write-Host "Deleting old registry entries" -ForegroundColor Yellow
    try {
        New-PSDrive -PSProvider registry -Root HKEY_CLASSES_ROOT -Name HKCR
        Remove-Item -Path HKCR:\Installer\Products\xxxxxx -Force -Recurse
    }catch
    {
        Write-Host "Failed to delete old $Software registry entries. This is likely to be because they either do not exist, or are not in the expected location." -ForegroundColor Red
    }
    Write-Host "Attempting to install Agent03." -ForegroundColor Yellow
    msiexec /i "$TempFolder\Agent03Installer.msi" TRANSFORMS="$Transform" /l*v "$TempFolder\Agent03InstallerUnInstall.log" /qn
    Write-Host "Sleeping for 60 seconds" -ForegroundColor Yellow
    Start-Sleep -Seconds 60

    if (test-path -Path "c:\Program Files\Agent03\sample.conf" -PathType Leaf)
    { Continue }
    else {
    if (-Not (test-path -Path "c:\Program Files\Agent03\seed.conf" -PathType Leaf)) {
        try {
            New-Item -ItemType "file" -Path "c:\Program Files\Agent03\seed.conf"
            ADD-Content -Path "c:\Program Files\Agent03\seed.conf" -Value "[user_info]"
            ADD-Content -Path "c:\Program Files\Agent03\seed.conf" -Value "USERNAME = admin"
            ADD-Content -Path "c:\Program Files\Agent03\seed.conf" -Value "PASSWORD = xxxxxx"
        }catch{
            Write-Host "Failed to create the Agent03 seed.conf file" -ForegroundColor Red
        }
    }

    Write-Host "Restarting Agent03 service (this may throw an error due to the service being slow to stop)" -ForegroundColor Yellow
    Stop-Service -Name Agent03Forwarder -Force -ErrorAction SilentlyContinue

    Start-Sleep -s 60

    Start-Service -Name Agent03Forwarder

    Write-Host "Setting the poller" -ForegroundColor Yellow
    invoke-expression "cmd.exe /c 'c:\Program Files\Agent03\Agent03.exe' set deploy-poll fqdn.controlserver.address:xxxx -auth admin:xxxxxx"

    }
}

$AgentList = "Agent01", "Agent02", "Agent03"

$ServerName = Hostname

ForEach ($Agent in $AgentList){

    If ($Agent -eq "Agent01"){
        $Software = "Agent01"
        $Installed = Check-Install -Software $Software
		if($Installed -eq $true) {
            write-host "$($Software) already installed.  Exiting." -ForegroundColor Green
        } else {
            write-host "$($Software) missing.  Installing." -ForegroundColor Yellow
            Write-Host "Installing Agent01 using Powershell 2.0 configuration" -ForegroundColor Yellow
            Install-Agent01
            $Installed = Check-Install -Software $Software
            if($Installed -eq $true) {
                write-host "$Software install on $ServerName SUCCESS." -ForegroundColor Green
            }
            else {
                write-host "$Software install on $ServerName FAILED." -ForegroundColor Red
            }
        }
    }#end Agent01 install

    If ($Agent -eq "Agent02"){
        $VersionCheck = Get-ItemProperty HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\* | Where-Object { $_.DisplayName -like "Agent02*" } | Select-Object -ExpandProperty DisplayName #Gets the registry entry of any existing Agent02 install, including older versions
        $Software = "Agent02"
        $Installed = Check-Install -Software $Software
        if($Installed -eq $true) {
            write-host "$($Software) already installed.  Exiting." -ForegroundColor Green
        }
        else {
            write-host "$($Software) is not installed or is an old version, installing." -ForegroundColor Yellow
            Write-Host "Installing Agent02 using Powershell 2.0 configuration" -ForegroundColor Yellow
            if ($VersionCheck -eq "Agent02_old_string"){Install-Agent02v2}else{Install-Agent02} #uses overwrite install function if an old version of Agent02 is installed, otherwise uses the normal install function
            Start-Sleep 60
            $Installed = Check-Install -Software $Software
            if($Installed -eq $true) {
                write-host "$Software install on $ServerName SUCCESS." -ForegroundColor Green
                }
	    	else {
                write-host "$Software install on $ServerName FAILED." -ForegroundColor Red
		}
        }
    }#end Agent02 install

    If ($Agent -eq "Agent03"){
        $ServerName = Hostname
        $ConfigFile = "c:\Program Files\Agent03\sample.conf"
        $HostnameFile = "c:\Program Files\Agent03\hostnames.conf"
        $ServiceRestart = "0"
        $VersionCheck = Get-ItemProperty HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\* | Where-Object { $_.DisplayName -like "*Agent03*" } | Select-Object -ExpandProperty DisplayName #Gets the registry entry of any existing Agent03 install, including older versions
        $Software = "Agent03"
        $Installed = Check-Install -Software $Software
        if($Installed -eq $true) {
            $ServiceCheck = Get-Service -Name Agent03

            if ($ServiceCheck.Status -eq "Stopped"){
                Write-Host "$Software installed, but service not started. Attempting to start service." -ForegroundColor Yellow
                Start-Service -Name Agent03
            }

            $Config = Get-Content "$ConfigFile"
            $ConfLine = $Config | Select-Object -First 1
            If($ConfLine -eq "???"){#checks to see if the config file is misconfigured with 3 ?'s, if so, removes them and resaves the file
                Write-Host "$Software already installed, but the deployment config file is misconfigured. Correcting and restarting services." -ForegroundColor Yellow
                (Get-Content $ConfigFile | Select-Object -Skip 1) | Set-Content $ConfigFile
                $ServiceRestart = "1"
            }

            $HostCheck = Get-Content $HostnameFile
            If(($HostCheck -match $Servername) -eq $false){#Checks to see if the input.conf file contains the correct servername and corrects it if not
                Write-Host "$Software already installed, but the inputs.conf file has an incorrect server name. Correcting and restarting services." -ForegroundColor Yellow
                Write-Host "Current hostnames.conf file contents:" -ForegroundColor Yellow
                $HostCheck
                $HostUpdate = "[default]`r`nhost = $ServerName"
                $HostUpdate | Set-Content $HostnameFile
                $ServiceRestart = "1"
            }

            if($ServiceRestart -eq "1"){#restarts service if necessary
                Write-Host "Stopping Agent03 service." -ForegroundColor Yellow
                Stop-Service -Name Agent03 -Force -ErrorAction SilentlyContinue
                Start-Sleep -s 30
                Write-Host "Starting Agent03 service." -ForegroundColor Yellow
                Start-Service -Name Agent03
            }
            write-host "$($Software) already installed.  Exiting." -ForegroundColor Green

        }
        else {
            write-host "$($Software) is not installed, installing." -ForegroundColor Yellow
            Write-Host "Installing Agent03 using Powershell 2.0 configuration" -ForegroundColor Yellow
            if ($VersionCheck -like "Agent03*"){Install-Agent03v2}else{Install-Agent03}#uses overwrite install function if an old version of Agent03 is installed, otherwise uses the normal install function
            Start-Sleep 60
            $Installed = Check-Install -Software $Software
            if($Installed -eq $true) {
                write-host "$Software install on $ServerName SUCCESS." -ForegroundColor Green
                }
	    	else {
                write-host "$Software install on $ServerName FAILED." -ForegroundColor Red
		}
        }
    }#end Agent03 install

}#end agent foreach