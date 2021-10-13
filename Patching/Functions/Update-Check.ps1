#This function forces the server to check in with WSUS, more information at http://pleasework.robbievance.net/howto-force-really-wsus-clients-to-check-in-on-demand/
function Update-Check {
    param(
        [Parameter(Mandatory=$true)]
        $ServerList,
        [Parameter(Mandatory=$true)]
        [System.Management.Automation.PSCredential]$Creds
    )

$ServerCSV = $ServerList -Join ", " #Converts the serverlist to a comma separated list, for setting the WSMan trusted hosts

Write-Host "`nAdding target servers to the WSMan trusted hosts list" -ForegroundColor Yellow

Set-Item WSMan:\localhost\Client\TrustedHosts -value "$ServerCSV" -Force #Adds the name of the target server to the WSMan trusted hosts list to allow for invoke-command

Write-Host "`nForcing servers to check in to WSUS server" -ForegroundColor Yellow

$Jobs = Invoke-Command -ComputerName $ServerList -Credential $Creds -ScriptBlock { #Starts a background job on each server in the list to force checkin with WSUS
    $updateSession = new-object -com "Microsoft.Update.Session"; $updates=$updateSession.CreateupdateSearcher().Search($criteria).Updates
    wuauclt /reportnow
    } -asjob #End Scriptblock

Write-Host "`nWaiting for checkin jobs to complete" -ForegroundColor Yellow

$Jobs | Wait-Job #Waits until all the jobs in the above invoke-command are complete

Write-Host "`nClearing finished check in jobs" -ForegroundColor Yellow

Get-Job | Remove-Job #Clears out all the jobs

Write-Host "`nRemoving target servers from the WSMan trusted hosts list" -ForegroundColor Yellow

Clear-Item WSMan:\localhost\Client\TrustedHosts -Force #Removes the name of the target server to the WSMan trusted hosts list to allow for invoke-command

}#End Function