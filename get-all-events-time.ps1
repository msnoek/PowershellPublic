
#Gets all the events on a computer in a specified time frame, excluding security and sysmon operational
#Written by Matt Snoek matthew.snoek at gmail.com

#ToDo: Make this a little prettier and allow usage on multiple computers?
$StartTime = Read-Host "Enter the beginning of the time range in format 'mm-dd-yyyy hh:mm:ss'"
$StartTime = [datetime]$StartTime
$EndTime = Read-Host "Enter the end of the time range in format 'mm-dd-yyyy hh:mm:ss'"
$EndTime = [datetime]$EndTime
$TimeFilter = {($_.TimeCreated -ge $StartTime) -and ($_.TimeCreated -le $EndTime)} #Creates filter from start and end times
$Remote = Read-Host "Will this be checking a remote computer? Enter 'yes' or 'no'"

if ($Remote -eq "yes")
{
        Write-Host "Enter the appropriate domain credentials."
        $Creds = Get-Credential
        $Target = Read-Host "Enter the target computer FQDN"
        $Session = New-PSSession -ComputerName "$Target" -Credential $Creds
}

$OutPath = Read-Host "Enter the full output path, including .txt extension"

New-Item $OutPath -ItemType "file" #Creates text file

if ($Target)
{
                    
        $RemoteEvents = Invoke-Command -Session $Session -ArgumentList $Creds,$Target,$TimeFilter -ScriptBlock {
                param ($Creds, $Target, $TimeFilter)
                $EventList = New-Object System.Collections.ArrayList #Creates array list
                $AllLogs = Get-WinEvent -ListLog * -Credential $Creds -ComputerName "$Target" | Where-Object {$_.RecordCount-and $_.LogName -ne "Microsoft-Windows-Sysmon/Operational" -and $_.LogName -ne "Security"} #Gets a list of all event logs on the remote server that have events in them
                                
                ForEach ($Log in $AllLogs) #Pulls out events from the listed logs
                {
                        $ListAdd = Get-WinEvent $Log.LogName -Credential $Creds -ComputerName "$Target" | Where-Object $TimeFilter
                        #Select-Object @{n='Time';e={$_.TimeCreated}},
                        #@{n='Source';e={$_.ProviderName}},
                        #@{n='EventId';e={$_.Id}},
                        #@{n='Message';e={$_.Message}},
                        #@{n='EventLog';e={$_.LogName}}
                        
                        $EventList.Add($ListAdd) #Adds the event to the EventList array
                }

                $EventList
        }

        $RemoteEvents | Out-File -FilePath $OutPath -Append -Force
}
else 
{
        $AllLogs = Get-WinEvent -ListLog * | Where-Object {$_.RecordCount-and $_.LogName -ne "Microsoft-Windows-Sysmon/Operational" -and $_.LogName -ne "Security"}
       
        ForEach ($Log in $AllLogs)
        {
	        Get-WinEvent $Log.LogName | Where-Object $TimeFilter | Out-File -FilePath $OutPath -Append -Force
		#Select-Object @{n='Time';e={$_.TimeCreated}},
                #@{n='Source';e={$_.ProviderName}},
                #@{n='EventId';e={$_.Id}},
                #@{n='Message';e={$_.Message}},
                #@{n='EventLog';e={$_.LogName}} | 
	        
        }      
}

Get-Content $OutPath | Out-GridView

workflow LogTest
{
        Param ($TimeFilter, $OutPath)
        $AllLogs = Get-WinEvent -ListLog * | Where-Object {$_.RecordCount-and $_.LogName -ne "Microsoft-Windows-Sysmon/Operational" -and $_.LogName -ne "Security"}
       
        ForEach -Parallel ($Log in $AllLogs)
        {
               
                Get-WinEvent $Log.LogName | Where-Object $TimeFilter | Out-File -FilePath $OutPath -Append -Force
               	        
        }   
}
