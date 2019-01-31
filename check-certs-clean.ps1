#Checks for the existence of a specified cert in all servers in the domain
#By Matt Snoek matthew.snoek at gmail.com

$OutputLoc = Read-Host "Enter the output location, WITHOUT trailing \"
Write-Host "Enter domain creds in Domain\Username format" 
$Creds = Get-Credential
$DomainSuffix = Read-Host "Enter the domain suffix" #domain suffix of domain you are testing against. Used in the event that you have multiple domains
$Thumbprint = Read-Host "Enter the certificate thumbprint"
Import-Module ActiveDirectory
Write-Host "Getting server list from AD" -ForegroundColor Green
$ADServerList = Get-ADComputer -Filter {OperatingSystem -Like "Windows Server*"} -Server "$DomainSuffix" -Property * | Select-Object -ExpandProperty Name #gets list of server objects from AD
#Uncomment the below line to remove specified servers from the check
#$ADServerList = $ADServerList -replace "excludeserver1|excludeserver2|excludeserver3","" | Where-Object { $_ }  #removes problematic servers from the list, as script is hanging on that server, likely due to corrupt WMI. Also removes Hyper-V clusters
$ADServerList > "$OutputLoc\ADServerList.txt" #Outputs servers list to a text file for reference. Script is not using this file, but could be useful for something else.


ForEach ($Server in $ADServerList) #Loops through each server in list gathered above
{
    #Checks to see if server is live, if so, runs block of code
    if ((Test-Connection -ComputerName "$Server" -BufferSize 16 -Count 1 -Quiet) -eq "True")
    {
        Write-Host "Gathering info for server $Server.$DomainSuffix" -ForegroundColor Green
        $Cert = Invoke-Command -ComputerName "$Server.$DomainSuffix" -Credential $Creds -scriptblock {Get-ChildItem -Path "Cert:\LocalMachine\My\$Thumbprint"} -ErrorAction Continue
        #Below If statement checks to see the error message from the Invoke-Command and if it matches a failure of Powershell to remotely connect, writes to the error log
        #Not using Try-Catch because if the file doesn't exit (which is shouldn't if the cert isn't installed) that will generate an error also
        if ($Error[0].Exception.GetType().FullName -eq "System.Management.Automation.Remoting.PSRemotingTransportException") {Write-Output "$Server failed Invoke-Command" >> "$OutputLoc\ErrorLog.txt"}
        if ($Cert) {Write-Output $Server >> "$OutputLoc\Servers_With_Cert.txt"} Else {Write-Output "$Server ran Invoke-Command successfully, but did not return a result" >> "$OutputLoc\Servers_Without_Cert.txt"}
           
    } Else #end Alive check If
    {
       
        Write-Output "$Server" >> "$OutputLoc\OfflineServers.txt"
      
    }#End Alive Check Else
}#End ForEach loop
