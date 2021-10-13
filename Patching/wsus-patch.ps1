param(
    [Parameter(Mandatory=$true)]
    [string]$PatchTarget
)

$FunctionsPath = "path\to\functions"
. $FunctionsPath\Update-Install.ps1 #Load functions
. $FunctionsPath\Update-Check.ps1
$Creds = Get-Credential -Message "Enter domain creds" 

if (Get-Module -ListAvailable -Name PSWindowsUpdate) { #Checks if the PSWindowsUpdate module is already present
    Write-Host "Module PSWindowsUpdate already installed" -ForegroundColor Yellow
}
else {#If not, installs it
    Write-Host "Module PSWindowsUpdate not installed, installing now." -ForegroundColor Yellow
    [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12 #Some servers might require this to be able to download the NuGet package provider
    Install-PackageProvider -Name NuGet -MinimumVersion 2.8.5.201 -Force #Installing the PSWindowsUpdate module requires NuGet
    Install-Module -Name PSWindowsUpdate -Force
}

Import-Module PSWindowsUpdate

#Maybe adjust credential section to use credentials from Azure and not have to manually enter them

$ServerList = Get-Content $PatchTarget

Update-Check $ServerList $Creds

Update-Install $ServerList $Creds