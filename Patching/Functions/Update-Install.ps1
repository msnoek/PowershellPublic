#This function installs updates from WSUS to the listed servers, then reboots
function Update-Install {
    param(
        [Parameter(Mandatory=$true)]
        $ServerList,
        [Parameter(Mandatory=$true)]
        [System.Management.Automation.PSCredential]$Creds
    )
    ForEach ($Server in $ServerList){

        Write-Host "`nAdding $Server to WSMan Trusted Hosts" -ForegroundColor Yellow

        Set-Item WSMan:\localhost\Client\TrustedHosts -value "$Server" -Force #Adds the name of the target server to the WSMan trusted hosts list to allow for invoke-command

        Write-Host "`nStarting remote job to update $Server" -ForegroundColor Yellow

        Invoke-Command -Credential $Creds -ComputerName $Server -ScriptBlock {

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
            $UpdateJob = "Install-WindowsUpdate -AcceptAll -AutoReboot" 
            Invoke-WUJob -Script $UpdateJob -RunNow -Confirm:$false #Invoke-WUJob works by creating a scheduled task and running it immediately. Have to do this because Windows won't let you perform an invoke-command that remotely downloads updates, even with proper auth, otherwise we could just run that $script directly
        } #End ScriptBlock

        Write-Host "`nRemoving $Server from WSMan Trusted Hosts" -ForegroundColor Yellow

        Clear-Item WSMan:\localhost\Client\TrustedHosts -Force #Removes the name of the target server to the WSMan trusted hosts list to allow for invoke-command

    }#End ForEach
}#End Function