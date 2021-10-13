param(
    [Parameter(Mandatory=$true)]
    $ServerList
)

$ServerWSMan = $ServerList -Join ", " #Converts the serverlist to a comma separated list (with space), for setting the WSMan trusted hosts

Set-Item WSMan:\localhost\Client\TrustedHosts -value "$ServerWSMan" -Force #Adds the name of the target server to the WSMan trusted hosts list to allow for invoke-command

$Jobs = Invoke-Command -ComputerName $ServerList -Credential $Creds -ScriptBlock { #Starts a background job on each server in the list to force checkin with WSUS
    $updateSession = new-object -com "Microsoft.Update.Session"; $updates=$updateSession.CreateupdateSearcher().Search($criteria).Updates
    wuauclt /reportnow
    } -asjob #End Scriptblock

$Jobs | Wait-Job #Waits until all the jobs in the above invoke-command are complete
Write-Output $Jobs
Get-Job | Remove-Job #Clears out all the jobs

Clear-Item WSMan:\localhost\Client\TrustedHosts -Force #Removes the name of the target server to the WSMan trusted hosts list to allow for invoke-command
