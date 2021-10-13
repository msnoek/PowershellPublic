param(
    [Parameter(Mandatory=$true)]
    [string]$PatchTarget
)

function Update-Check {
    param(
        [Parameter(Mandatory=$true)]
        $ServerList,
        [Parameter(Mandatory=$true)]
        [System.Management.Automation.PSCredential]$Creds
    )

$ServerCSV = $ServerList -Join ", " #Converts the serverlist to a comma separated list, for setting the WSMan trusted hosts

Set-Item WSMan:\localhost\Client\TrustedHosts -value "$ServerCSV" -Force #Adds the name of the target server to the WSMan trusted hosts list to allow for invoke-command

$Jobs = Invoke-Command -ComputerName $ServerList -Credential $Creds -ScriptBlock { #Starts a background job on each server in the list to force checkin with WSUS
    $updateSession = new-object -com "Microsoft.Update.Session"; $updates=$updateSession.CreateupdateSearcher().Search($criteria).Updates
    wuauclt /reportnow
    } -asjob #End Scriptblock

$Jobs | Wait-Job #Waits until all the jobs in the above invoke-command are complete

Get-Job | Remove-Job #Clears out all the jobs

Clear-Item WSMan:\localhost\Client\TrustedHosts -Force #Removes the name of the target server to the WSMan trusted hosts list to allow for invoke-command

}#End Function

function Update-Install {
    param(
        [Parameter(Mandatory=$true)]
        $ServerList,
        [Parameter(Mandatory=$true)]
        [System.Management.Automation.PSCredential]$Creds
    )
    ForEach ($Server in $ServerList){

        Set-Item WSMan:\localhost\Client\TrustedHosts -value "$Server" -Force #Adds the name of the target server to the WSMan trusted hosts list to allow for invoke-command

        Invoke-Command -Credential $Creds -ComputerName $Server -ScriptBlock {

            if !((Get-Module -ListAvailable -Name PSWindowsUpdate)) { #Checks if the PSWindowsUpdate module is already present, installs if not
                [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12 #Some servers might require this to be able to download the NuGet package provider
                Install-PackageProvider -Name NuGet -MinimumVersion 2.8.5.201 -Force #Installing the PSWindowsUpdate module requires NuGet
                Install-Module -Name PSWindowsUpdate -Force
            }
            Import-Module PSWindowsUpdate
            $UpdateJob = "Install-WindowsUpdate -AcceptAll -AutoReboot" 
            Invoke-WUJob -Script $UpdateJob -RunNow -Confirm:$false #Invoke-WUJob works by creating a scheduled task and running it immediately. Have to do this because Windows won't let you perform an invoke-command that remotely downloads updates, even with proper auth, otherwise we could just run that $script directly
        } #End ScriptBlock

        Clear-Item WSMan:\localhost\Client\TrustedHosts -Force #Removes the name of the target server to the WSMan trusted hosts list to allow for invoke-command

    }#End ForEach
}#End Function

#Gets various domain creds from shared cred repository
$Domain01Creds = Get-AutomationPSCredential -Name Domain01-Domain-Automation
$Domain02Creds = Get-AutomationPSCredential -Name Domain02-Domain-Automation
$Domain03Creds = Get-AutomationPSCredential -Name Domain03-Domain-Automation

$ServerList = (Get-AZAutomationVariable -Name $PatchTarget -ResourceGroupName "ResourceGroup" -AutomationAccountName "AutomationAccount").Value

#Sets $creds to use the appropriate credential
if ($ServerList[0] -like "*.domain01.com"){$Creds = $Domain01Creds}
if ($ServerList[0] -like "*.domain02.com"){$Creds = $Domain02Creds}
if ($ServerList[0] -like "*.domain03.com"){$Creds = $Domain03Creds}

Install-Module PSWindowsUpdate -Force

#Update-Check $ServerList $Creds

#Update-Install $ServerList $Creds