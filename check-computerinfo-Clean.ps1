#It's ugly, Invoke-Command wouldn't return properly formatted strings when running all info checks as a large chunk and it needed to be done quick, so had to split them out

$OutputLoc = Read-Host "Enter the output location, WITHOUT trailing \"
$CSVName = Read-Host "Enter the CSV file name"
Write-Host "Enter domain creds in Domain\Username format" 
$DomainSuffix = Read-Host "Enter the domain suffix" #domain suffix of domain you are testing against. Used in the event that you have multiple domains
$Creds = Get-Credential
$FullOutput = "$OutputLoc\$CSVName"

Import-Module ActiveDirectory
Write-Host "Getting server list from AD" -ForegroundColor Green
$ADServerList = Get-ADComputer -Filter {OperatingSystem -Like "Windows Server*"} -Server "$DomainSuffix" -Property * | Select-Object -ExpandProperty Name #gets list of server objects from AD
#Comment out below to remove specific servers from being checked
#$ADServerList -replace "servertoremove01|servertoremove02|servertoremove03","" | Where-Object { $_ }  #removes problematic servers from the list, as script is hanging on that server, likely due to corrupt WMI. Also removes Hyper-V clusters
$ADServerList > "$OutputLoc\ADServerList.txt" #Outputs servers list to a text file for reference. Script is not using this file, but could be useful for something else.

Add-Content -Path "$FullOutput" -Value '"Name","Model","RAM","PhysicalCPU","CPUCores","Disk1","Disk2","Disk3","Disk4","Disk5","Disk6"'

ForEach ($Server in $ADServerList) #Loops through each server in list gathered above
{
    #Checks to see if server is live, if so, runs block of code
    if ((Test-Connection -ComputerName "$Server" -BufferSize 16 -Count 1 -Quiet) -eq "True")
    {
        Write-Host "Gathering info for server $Server.$DomainSuffix" -ForegroundColor Green
        try
        {
				
				$Name = "$Server.$DomainSuffix"
				$Model = Invoke-Command -ComputerName "$Server.$DomainSuffix" -Credential $Creds -scriptblock {(Get-WMIObject -Class Win32_ComputerSystem).Model}
				$RAM = Invoke-Command -ComputerName "$Server.$DomainSuffix" -Credential $Creds -scriptblock {(Get-WMIObject -Class Win32_ComputerSystem).TotalPhysicalMemory}
				$CPU = Invoke-Command -ComputerName "$Server.$DomainSuffix" -Credential $Creds -scriptblock {(Get-WMIObject -Class Win32_ComputerSystem).NumberOfProcessors}
				$Cores = Invoke-Command -ComputerName "$Server.$DomainSuffix" -Credential $Creds -scriptblock {(Get-WMIObject -Class Win32_ComputerSystem).NumberOfLogicalProcessors}
				[Array]$Disk = Invoke-Command -ComputerName "$Server.$DomainSuffix" -Credential $Creds -scriptblock {((Get-Disk | Where-Object {$_.OperationalStatus -eq "Online"}).Size)}
				$RAM = $RAM/1GB #Divides the RAM bytes by a gigabyte. Not doing this at the end of the script block because some machine don't have high enough powershell version to do it
				$RAM = [int]$RAM #Rounds up to the nearest whole integer
								
        } 
        catch [System.Management.Automation.Remoting.PSRemotingTransportException] {Write-Output "$Server.$DomainSuffix failed Invoke-Command" >> "$OutputLoc\ErrorLog.txt"}
		$i=0
		$DiskOut = $null
		For ($i=0; $i -lt $Disk.Count; $i++){#if there is more than 1 disk parses them out and adds to diskout string. Note that there will be a comma no matter what at the beginning, this is accounted for in the $Info Write-Output
			$Disk[$i] = $Disk[$i]/1GB
			$DiskIn = $Disk[$i]
			$DiskOut = "$DiskOut,$DiskIn"
		}
		
		$Info = Write-Output "$Name,$Model,$RAM,$CPU,$Cores$DiskOut"
		$Info | Out-File -Append -FilePath "$FullOutput"
        
    } Else #end Alive check If
    {
       
        Write-Output "$Server" >> "$OutputLoc\OfflineServers.txt"
      
    }#End Alive Check Else
}#End ForEach loop
