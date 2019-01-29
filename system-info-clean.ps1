#
#System Info script
#Created by Matthew Snoek (matthew.snoek at gmail.com)
#Script parses AD for Server objects and runs various WMIObject commands against them to pull system info
#TO-DO: Need to clean up the script blocks, get error checking working
#

$ErrorActionPreference = "silentlycontinue" #Allows Try Catch block to work. Note: Try Catch block not actually working yet, needs further testing
$OutputLoc = Read-Host "Enter the output location, no trailing \"
Write-Host "Enter domain creds" 
$Creds = Get-Credential #Enter credentials in Domain\Username format, account will need admin rights on servers that are being hit
$DomainSuffix = Read-Host "Enter the domain suffix" #domain suffix of domain you are testing against. Used in the event that you have multiple domains
$ErrorLog = ""
Import-Module ActiveDirectory
Write-Host "Getting server list from AD" -ForegroundColor Green
$ADServerList = Get-ADComputer -Filter {OperatingSystem -Like "Windows Server*"} -Property * | Select-Object -ExpandProperty Name #gets list of server objects from AD
$ADServerList > "$OutputLoc\ADServerList.txt" #Outputs servers list to a text file for reference. Script is not using this file, but could be useful for something else.
ForEach ($Server in $ADServerList) #Loops through each server in list gathered above
{
    Write-Host "Gathering info for server $Server.$DomainSuffix" -ForegroundColor Green
    try { #Try/Catch block needs some work yet
        $ServerInfo = Invoke-Command -ComputerName "$Server.$DomainSuffix" -Credential $Creds -ScriptBlock { #This script block can probably be cleaned up
            Get-WMIObject -Class Win32_ComputerSystem | Select-Object Name,Domain,Manufacturer,Model | Format-List
            Get-WMIObject -Class Win32_OperatingSystem -Property Caption | Select-Object Caption | Format-List
            Get-WMIObject -Class Win32_NetworkAdapterConfiguration | Where-Object -FilterScript {$_.IPAddress -notcontains $null} | Select-Object IPAddress,DefaultIPGateway,MACAddress | Format-List
            }
        }
        catch {
            $ErrorLog = $Error[0] | Format-List -Force #gets the last error, formats it to view the full error, then outputs to error log
            $ErrorLog >> "$OutputLoc\Errors.log"
        }
    
    $ServerInfo > "$OutputLoc\$Server.txt"
    $HostInfo = Invoke-Command -ComputerName "$Server.$DomainSuffix" -Credential $Creds -scriptblock {(Get-Item "HKLM:\SOFTWARE\Microsoft\Virtual Machine\Guest\Parameters").GetValue("HostName")} #Pulls the name of the Hyper-V host that a VM is running on
    #Below If statement is used to determine the cluster and physical location of VMs by parsing the name of the host gathered from above. Add more If statements and adjust to match environment as necessary.	
	#This will probably only really work well for smaller numbers of clusters
	if (($HostInfo -eq "samplehostname1.asFQDN") -or ($HostInfo -eq "samplehostname2.asFQDN") -or ($HostInfo -eq "samplehostname3.asFQDN") -or ($HostInfo -eq "samplehostname4.asFQDN") -or ($HostInfo -eq "samplehostname5.asFQDN"))
    {
        Write-Output "Cluster   : SampleClusterName.FQDN" >> "$OutputLoc\$Server.txt"
        Write-Output "Location  : Physical-Location-of-Cluster-Above" >> "$OutputLoc\$Server.txt"
    }
    
    (Get-Content "$OutputLoc\$Server.txt") | ForEach-Object {$_ -Replace "Caption", "Operating System"} | Where-Object { $_ } | Set-Content "$OutputLoc\$Server.txt" #removes the blank lines from the previously created text file and replaces 'Caption' with 'Operating System'
}