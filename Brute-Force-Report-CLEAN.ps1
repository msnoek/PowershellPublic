#Created by Matt Snoek matthew.snoek at gmail.com
#Script to report on number of failed logon attempts

Import-Module ActiveDirectory

$DomainControllers = Get-ADDomainController -Filter * -Server "fqdn.domain.name" | Select-Object hostname -ExpandProperty hostname

$Date = Get-Date -Format FileDate
$EventTime = (Get-Date).AddDays(-1)
$smtpSender = "sender@domain.com"
$smtpServer = "smtp.server.com"
$OutputPath = "C:\scripts\Logs\Failed-Logons"
$DOMAINUser = "DOMAIN\serviceaccount"
$EncryptedPass = Get-Content "C:\scripts\Failed-Logons\DOMAIN-Encrypted-Pass.txt" | ConvertTo-SecureString #Pulls encrypted password from text file. See README-Password-Notes.txt in C:\Scripts\Failed-Logons and https://interworks.com/blog/trhymer/2013/07/08/powershell-how-encrypt-and-store-credentials-securely-use-automation-scripts/
$DOMAINCreds = New-Object System.Management.Automation.PsCredential($DOMAINUser, $EncryptedPass) #Creates credentials from encrypted password


$Pattern4771 = "Account Name","Client Address","Domain Controller","Failure Code:","Pre-Authentication Type:"

#Creates blank CSV for report
Add-Content -Path "$OutputPath\$Date-Brute-Force-Report-Full-DOMAIN.csv" -Value '"Time Stamp","Account Name","Client Address","Domain Controller","Failure Code","Pre-Authentication Type"'
Add-Content -Path "$OutputPath\$Date-Brute-Force-Report-Check-DOMAIN.csv" -Value '"Time Stamp","Account Name","Client Address","Domain Controller","Failure Code","Pre-Authentication Type"'

$Event4771Object = New-Object PSObject -Property @{
    TimeStamp           = ""
    AccountName         = ""
    ClientAddress       = ""
    DomainController    = ""
    FailureCode         = ""
    PreAuthType         = ""
}#end 4771 object creation

ForEach ($DC in $DomainControllers)
{
    $Events4771DC = Get-WinEvent -ComputerName "$DC" -Credential $DOMAINCreds -FilterhashTable @{Logname='Security';ID=4771;StartTime=$EventTime}
    
  
    ForEach ($Event in $Events4771DC)#Copies the above for event 4771
    {
        $EventTime = $Event.TimeCreated -Replace "`n","" #Gets timestamp from event, removing extra lines
        $EventMessage = $Event.Message #Gets only the Message property of the Event object
        $EventString = $EventMessage | Out-String #Turns the object into a string for pulling out the needed information
        $EventString = $EventString.Split("`r`n") #Splits the one giant string that we created into an array of strings split on each line so that we can manipulate it further
        $Event4771Array = $EventString | Select-String -Pattern $Pattern4771 #creates an array from the pattern selected text
        
        #Cleans up the input
        $AccountName = $Event4771Array[0] -Replace "`t|Account Name:",""
        $ClientAddress = $Event4771Array[1] -Replace "`t|Client Address:|::ffff:",""
        $FailureCode = $Event4771Array[2] -Replace "`t|Failure Code:",""
        $PreAuthType = $Event4771Array[3] -Replace "`t|PreAuthentication Type:",""
        
        #Adds the input back, including timestamp
        $Event4771Object.TimeStamp = $EventTime
        $Event4771Object.AccountName = $AccountName
        $Event4771Object.ClientAddress = $ClientAddress
        $Event4771Object.DomainController = $DC
        $Event4771Object.FailureCode = $FailureCode #Failure code info located https://www.ultimatewindowssecurity.com/securitylog/encyclopedia/event.aspx?eventID=4771
        $Event4771Object.PreAuthType = $PreAuthType
        
        $Event4771Object = $Event4771Object | Select-Object TimeStamp,AccountName,ClientAddress,DomainController,FailureCode,PreAuthType #Rearranges the property order
        $Event4771Object | Convertto-CSV -NoTypeInformation | Select-Object -Skip 1 | Out-File -Encoding ASCII "$OutputPath\$Date-Brute-Force-Report-Full-DOMAIN.csv" -Append #Appends the event to the output CSV
    }#End 4771 Event foreach
}#End DC If
$Full4771Event = Import-CSV "$OutputPath\$Date-Brute-Force-Report-Full-DOMAIN.csv"
    
$NameCountList = @()
$BruteCheck = @()

$GroupCount = $Full4771Event."Account Name" | Group-Object #Gets number of times names show up

foreach ($Item in $GroupCount) {if ($Item.Count -gt 15){$NameCountList += ($Item | Select-Object Count,Name)}} #Checks the number of times a username appears in the list of failed logons, and if greater than 15, adds to a list
foreach ($Item in $GroupCount) {if ($Item.Count -gt 15){$BruteCheck += $Item.Name}} #Same thing as above, only this list is only name, not name and count

$4771OutputArray = @()

ForEach ($Name in $BruteCheck)#Goes through the $BruteCheck array created above and pulls out the full events matching the usernames
    {
        
       $OutputArrayAdd = $Full4771Event | Where-Object "Account Name" -eq $Name #Select only events from the full event list that match a username that has appeared more than 5 times
       $4771OutputArray += $OutputArrayAdd #Adds the selected events to the output array
       
    }#End BruteCheck ForEach
$4771OutputArray | Convertto-CSV -NoTypeInformation | Select-Object -Skip 1 | Out-File -Encoding ASCII "$OutputPath\$Date-Brute-Force-Report-Check-DOMAIN.csv" -Append


$NameCountList | Convertto-Html > "$OutputPath\$Date-Brute-Force-Name-List.htm"

$MailBody = "Below is a list of users with failed logon audit events greater than 15. Please see attached CSV for full report. Failure code and authentication type info can be found at https://www.ultimatewindowssecurity.com/securitylog/encyclopedia/event.aspx?eventID=4771" + (Get-Content "$OutputPath\$Date-Brute-Force-Name-List.htm" -Raw)

if ($NameCountList) #Checks if there is anything in the list of names to check, and if so, emails the IT department.
{
    Send-MailMessage -To "Destination@company.com" -From $smtpSender -Subject "DOMAIN Brute Force Attempt Report" -SMTPServer $smtpServer -Body "$MailBody" -BodyAsHtml -Attachments "$OutputPath\$Date-Brute-Force-Report-Full-DOMAIN.csv","$OutputPath\$Date-Brute-Force-Report-Check-DOMAIN.csv"
}