#Checks disconnected sessions domain wide
#written by Matt Snoek matthew.snoek at gmail.com

Write-Host "Input domain credentials for the domain you wish to check"
$Creds = Get-Credential
$DomainSuffix = Read-Host "Enter the domain suffix"
$OutputLoc = Read-Host "Enter the output path, do NOT include trailing backslash"


Write-Host "Getting list of servers from AD"
$ADServerList = Get-ADComputer -Filter {OperatingSystem -Like "Windows Server*"} -Server "$DomainSuffix" -Property * | Select-Object -ExpandProperty Name #gets list of server objects from AD

Add-Content -Path "$OutputLoc\SessionsReport.csv" -Value '"Server","Username"' #Creates CSV

ForEach ($Server in $ADServerList)#Gets disconnected session user names
{
    if ((Test-Connection -ComputerName "$Server" -BufferSize 16 -Count 1 -Quiet) -eq "True")
    {
        Write-Host "Checking server $Server"
        $DiscSessions = Invoke-Command -ComputerName "$Server" -Credential $Creds -ScriptBlock {(qwinsta | 
            ForEach-Object { (($_.trim() -replace "\s+",","))} | 
            ConvertFrom-Csv) | 
            Where-Object {$_.ID -eq "disc" -and $_.SessionName -ne ">services"}
        }

        ForEach ($Session in $DiscSessions) #parses the data and appends to CSV
        {
            $User = $Session.SessionName
            $CSVAdd = "$Server,$User"
            $CSVAdd | Out-File "$OutputLoc\SessionsReport.csv" -Append
        }

    }
}


