#New user creation script
#Written by Matt Snoek matthew.snoek at gmail.com

#Gathers variables
$NewFirstName = Read-Host "Enter the FIRST name of the new user"
$NewLastname = Read-Host "Enter the LAST name of the new user"
$Password = Read-Host "Enter the temporary password for the new user"
$Description = Read-Host "Enter a description of the new user's role ('Description' field in AD)"
$Office = Read-Host "Enter the office location of the new user, Office01 or Office02"
$NotifyEmail = Read-Host "Enter the email address that will receive the account creation notification email (for Exchange Unified Messaging)"
$FirstInitial = $NewFirstName.Substring(0,1) #pulls the first initial from the first name
$FirstInitialLower = $FirstInitial.ToLower() #Makes the first initial lowercase
$NewLastNameLower = $NewLastName.ToLower() #Makes last name lowercase
#AD country code info required for proper 365 creation
$Country = "US"
$CountryCode = "840"
$CountryName = "United States"
$smtpSender = "sendingaddress@sample.com"
$smtpServer = "smtp.relay.address.com"

#Error Checking
if ($Office -ne "Office01" -And $Office -ne "Office02")
{
    Write-Output "The office location was not entered correctly. It must be either 'Office02' or 'Office01'. Exiting now."
    Exit 
} 

#Prompts for 365 credentials
$DomainCredentials = Get-Credential -Message "Enter Domain Admin credentials in DOMAIN\Username format"
$365Credentials = Get-Credential -Message "Enter 365 admin credentials in USERNAME@company.com format"

$ShouldCopy = Read-Host "Should security and distribution groups be copied from another user? Enter 'Yes' or 'No'"
if ($ShouldCopy -eq "Yes") 
    {
        $CopiedUser = Read-Host "Enter the username in first initial last name format that you wish to copy"
    }

$DisplayName = "$NewFirstName $NewLastName"
$UserLogonName = "$FirstInitialLower" + "$NewLastNameLower"
$NewUserEmail = "$UserLogonName@company.com"
$AltEmail01 = "$UserLogonName@company.onmicrosoft.com"
$AltEmail02 = "$UserLogonName@company.mail.onmicrosoft.com"

#Starts doing work here
#connects to 365 using previously input credentials
Write-Output "Connecting to Office 365"
$Session = New-PSSession -ConfigurationName Microsoft.Exchange -ConnectionUri https://outlook.office365.com/powershell-liveid/ -Credential $365Credentials -Authentication Basic -AllowRedirection
Import-PSSession $Session
Connect-MsolService -Credential $365Credentials #This requires the MSOnline powershell module

Import-Module ActiveDirectory #Imports AD module
Import-Module MSOnline #imports MSOL module
Import-Module SkypeOnlineConnector #Imports skype online module


#Checks available licenses in 365 and exits script if none available
Write-Output "Checking available Office 365 licenses"
$Licensing = Get-MsolAccountSku | Where-Object {$_.AccountSkuId -eq 'edgeaq:ENTERPRISEPREMIUM'}
$AvailableLicenses = $Licensing.ActiveUnits - $Licensing.ConsumedUnits
If ($AvailableLicenses -le 0) 
    {
        Write-Output "There are no available 365 licenses. The script will now exit"
        Exit
    }
    Else
    {
        Write-Output "There are $AvailableLicenses 365 licenses available. Continuing with user creation."
    }


#Checks if a user is supposed to be copied and uses that user as the default instance, and a default user if not
if ($CopiedUser)
{
    $DefaultUserInstance = Get-ADUser -Identity "$CopiedUser"
    $OUPath = (Get-ADUser -Identity $CopiedUser).distinguishedName.Split(',',2)[1]
}
else
{
    $DefaultUserInstance = Get-ADUser -Identity "duser" #uses the default user account created in AD under (insert OU location here)
    $OUPath = (Get-ADUser -Identity "duser").distinguishedName.Split(',',2)[1]
}

#Creates new user
Write-Output "Creating $UserLogonName in AD"
New-AdUser -Name "$DisplayName" -GivenName "$NewFirstName" -Surname "$NewLastName" -DisplayName "$DisplayName" -SamAccountName "$UserLogonName" -UserPrincipalName "$NewUserEmail" -EmailAddress "$NewUserEmail" -Description "$Description" -Instance "$DefaultUserInstance" -Office "$Office" -Path "$OUPath" -AccountPassword (ConvertTo-SecureString "$Password" -AsPlainText -Force) -ChangePasswordAtLogon $false -Enabled $true
Set-ADUser -Identity "$UserLogonName" -Replace @{c="$Country";co="$CountryName";countrycode="$CountryCode"}
Set-ADUser -Identity "$UserLogonName" -Add @{proxyAddresses="SMTP:$NewUserEmail"}
Set-ADUser -Identity "$UserLogonName" -Add @{proxyAddresses="smtp:$AltEmail01"}
Set-ADUser -Identity "$UserLogonName" -Add @{proxyAddresses="smtp:$AltEmail02"}
Set-ADUser -Identity "$UserLogonName" -Add @{msNPAllowDialIn=$TRUE} #Sets dial-in remote access setting

#Need to put syncing between domain controllers
$HostName = $env:computername
repadmin /syncall $HostName /e
Write-Output "Sleeping for 1 minute to allow for domain replication"
Start-Sleep -s 60

#Runs a manual dirsync to 365
Write-Output "Running a manual dirsync to 365, then sleeping for 5 minutes to allow for catchup"
$Dirsyncsession  = New-PSSession -Computername "dirsync.computer.FQDN"
Invoke-Command -Session $Dirsyncsession -ScriptBlock {Import-Module -Name 'ADSync'}
Invoke-Command -Session $Dirsyncsession -ScriptBlock {Start-ADSyncSyncCycle -PolicyType Delta}
Remove-PSSession $Dirsyncsession
Start-Sleep -s 300

Write-Output "Checking to see if new user has synced to 365 yet"
$UserCheck = Get-MsolUser -UserPrincipalName "$NewUserEmail"
$UserCheckCounter = 0
while ($UserCheck -eq $null -and $UserCheckCounter -lt 11)
{
    Write-Output "New user has not synced to 365 yet, resyncing and waiting another 4 minutes"
    $Dirsyncsession  = New-PSSession -Computername "dirsync.computer.FQDN"
    Invoke-Command -Session $Dirsyncsession -ScriptBlock {Import-Module -Name 'ADSync'}
    Invoke-Command -Session $Dirsyncsession -ScriptBlock {Start-ADSyncSyncCycle -PolicyType Delta}
    Remove-PSSession $Dirsyncsession
    Start-Sleep -s 240
    $UserCheckCounter = $UserCheckCounter + 1
    if ($UserCheckCounter -eq 10)
    {
        Write-Output "User has not synced with 365 for 30 minutes, exiting script"
		Send-MailMessage -To $NotifyEmail -From $smtpSender -Subject "New User $NewFirstName $NewLastName" -SMTPServer $smtpServer -Body "The user has been failed to sync to 365 after 20 minutes and the script has exited."
        Exit
    }
    $UserCheck = Get-MsolUser -UserPrincipalName "$NewUserEmail" 
}
if ($UserCheck)
{
Send-MailMessage -To $NotifyEmail -From $smtpSender -Subject "New User $NewFirstName $NewLastName" -SMTPServer $smtpServer -Body "The user has been synced successfully to 365"
}


#Add licensing here
Set-MsolUser -UserPrincipalName "$NewUserEmail" -UsageLocation "US"
Set-MsolUserLicense -UserPrincipalName "$NewUserEmail" -AddLicenses "edgeaq:ENTERPRISEPREMIUM"
Set-MsolUserLicense -UserPrincipalName "$NewUserEmail" -AddLicenses "edgeaq:MCOPSTN1" #Teams/Skype VOIP licensing

#Pulls Exchange Online GUID
Write-Output "Getting Exchange Online GUID and adding to on-premise Exchange server"
$ExchangeOnlineGUID = Get-Mailbox "$UserLogonName" | Select-Object -ExpandProperty ExchangeGUID | Select-Object -ExpandProperty Guid
$ExchangeGUIDCounter = 0
while ($ExchangeOnlineGUID -eq $null -and $ExchangeGUIDCounter -lt 11)
{
    Write-Output "Unable to get Exchange Online GUID, waiting 30 seconds and trying again"
    Start-Sleep -s 30
    $ExchangeOnlineGUID = Get-Mailbox "$UserLogonName" | Select-Object -ExpandProperty ExchangeGUID | Select-Object -ExpandProperty Guid
    $ExchangeGUIDCounter = $ExchangeGUIDCounter + 1
    
    if ($ExchangeGUIDCounter -eq 10)
    {
        Write-Output "Exchange GUID was unable to be found after 5 minutes. Exiting script."
        Send-MailMessage -To $NotifyEmail -From $smtpSender -Subject "New User $NewFirstName $NewLastName" -SMTPServer $smtpServer -Body "Unable to get Exchange GUID after 10 minutes and the script has exited."
        Exit
    }
    
}

#Need to connect to on-prem exchange server and then enable remote mailbox https://docs.microsoft.com/en-us/powershell/module/exchange/federation-and-hybrid/enable-remotemailbox?view=exchange-ps
$LocalExchangeSession = New-PSSession -ConfigurationName microsoft.exchange -ConnectionURI "http://internal.exchange.server.FQDN/powershell" -Credential $DomainCredentials
Import-PSSession $LocalExchangeSession
Enable-RemoteMailbox -Identity "$UserLogonName" -RemoteRoutingAddress "$UserLogonName@company.mail.onmicrosoft.com"
Set-RemoteMailbox "$UserLogonName" -ExchangeGUID "$ExchangeOnlineGUID"
Remove-PSSession $LocalExchangeSession

#Set up email alerting for when a step completes

#need to add skype for business connector https://docs.microsoft.com/en-us/skypeforbusiness/set-up-your-computer-for-windows-powershell/download-and-install-the-skype-for-business-online-connector

Start-Service WinRM
$cssession = New-CsOnlineSession -Credential $365Credentials -OverrideAdminDomain "company.onmicrosoft.com" 
Import-PSSession $CSSession -AllowClobber
Write-Output "Starting WinRM service in case it is stopped"
Write-Output "Connecting to Skype For Business Online"
Write-Output "Checking to see if $UserLogonName has been synced to Skype for Business Online"
$CSOnlineUserCheck = Get-CSOnlineVoiceUser -Identity "$UserLogonName"
$CSOnlineCounter = 0

#Starts a loop to check for user syncing to Skype
while ($CSOnlineUserCheck -eq $null -and $CSOnlineCounter -lt 21)
{
	$CSOnlineUserCheck = Get-CSOnlineVoiceUser -Identity "$UserLogonName"
	Write-Output "$UserLogonName has not synced to Skype for Business Online yet, sleeping for 2 minutes and trying again"
	Start-Sleep -s 120

	if ($CSOnlineUserCheck -eq $null -and $CSOnlineCounter -eq 20)
	{
		Write-Output "$UserLogonName has not synced to Skype for Business Online after 40 minutes, exiting script now"
		Send-MailMessage -To $NotifyEmail -From $smtpSender -Subject "New User $NewFirstName $NewLastName" -SMTPServer $smtpServer -Body "The user has failed to sync to Skype for Business Online after 40 minutes and the script will now exit."
		Exit
	}
    $CSOnlineCounter = $CSOnlineCounter + 1
}

#Assigns telephone city code and picks the first available phone number
Write-Output "Checking user location and assigning phone number and emergency info based on that"
if ($Office -eq "Office01")
{
    $SfBRegion = "SKYPE-FOR-BUSINESS-REGION-CODE-HERE"
    $NewPhoneNumber = Get-CSOnlineTelephoneNumber -isnotassigned | Where-Object {$_.CityCode -eq "SKYPE-FOR-BUSINESS-REGION-CODE-HERE"} | Select-Object -first 1 | Select-Object -ExpandProperty Id
    $EmergencyLocationID = "EMERGENCY-LOCATION-ID-HERE"
}
if ($Office -eq "Office02")
{
    $SfBRegion = "SKYPE-FOR-BUSINESS-REGION-CODE-HERE"
    $NewPhoneNumber = Get-CSOnlineTelephoneNumber -isnotassigned | Where-Object {$_.CityCode -eq "SKYPE-FOR-BUSINESS-REGION-CODE-HERE"} | Select-Object -first 1 | Select-Object -ExpandProperty Id
    $EmergencyLocationID = "EMERGENCY-LOCATION-ID-HERE"
}

#Makes extension variable from the last three of the phone number
Write-Output "Getting extension from new phone number"
$Extension = $NewPhoneNumber.substring(8,3)
#Sets phone number
Write-Output "Setting phone number"
#this one doesn't work, need to split out Set-CSOnlineVoiceUser -Identity $UserLogonName -TelephoneNumber $NewPhoneNumber -EnterpriseVoiceEnabled $true -HostedVoiceMail $true -LocationID $EmergencyLocationID
Set-CSOnlineVoiceUser -Identity $UserLogonName -TelephoneNumber $NewPhoneNumber -HostedVoiceMail $true -LocationID $EmergencyLocationID #needs testing, fails with ssh connection error
Set-CSUser -Identity $UserLogonName -EnterpriseVoiceEnabled $true

#Enables Unified Messaging
Write-Output "Enabling Unified Messaging"
Enable-UMMailbox -Identity "$NewUserEmail" -UMMailboxPolicy "DEFAULT POLICY HERE" -NotifyEmail "$NotifyEmail" -PINExpired $true -Extensions "$Extension"

#Adds the user phone number to AD
Write-Output "Adding phone number to user's AD account"
Set-ADUser -Identity "$UserLogonName" -OfficePhone "$NewPhoneNumber"

#Need to have new user account created and email synced to 365 before the below will work
if ($CopiedUser)
{
    $CopiedUserEmail = "$CopiedUser@edgenet.com"
    $CopiedMailbox = Get-Mailbox $CopiedUserEmail
    $DN = $CopiedMailbox.distinguishedName
    $CopiedAlias = $CopiedMailbox.$CopiedAlias
    $Filter = "Members -like ""$DN"""
    
    Write-Output "Gathering the AD security groups that $CopiedUser is a member of"
    Get-ADPrincipalGroupMembership -Identity $CopiedUser | Where-Object {$_.GroupCategory -eq "Security"} | Select-Object Name | Export-CSV "C:\Logs\UserLogs\$UserLogonName\ADSecurityToCopy.csv"

    Write-Output "Gathering the on-premise AD distribution groups that $CopiedUser is a member of"
    Get-ADPrincipalGroupMembership -Identity $CopiedUser | Where-Object {$_.GroupCategory -eq "Distribution"} | Select-Object Name | Export-CSV "C:\Logs\UserLogs\$UserLogonName\ADDistroToCopy.csv"

    Write-Output "Gathering the 365 distribution groups that $CopiedUser is a member of"
    Get-DistributionGroup -ResultSize Unlimited -Filter $Filter | Select-Object Name | Export-CSV "C:\Logs\UserLogs\$UserLogonName\365DistroToCopy.csv"

    Write-Output "Gathering the 365 Unified groups that $CopiedUser ia a member of"
    Get-UnifiedGroup -ResultSize Unlimited -Filter $Filter | Select-Object Name | Export-CSV "C:\Logs\UserLogs\$UserLogonName\365UnifiedToCopy.csv"

    Write-Output "Adding $UserLogonName to AD security groups"
    Import-CSV "C:\Logs\UserLogs\$UserLogonName\ADSecurityToCopy.csv" | ForEach-Object {Add-ADGroupMember -Identity $_.Name -Members $UserLogonName}

    Write-Output "Adding $UserLogonName to AD distribution groups"
    Import-CSV "C:\Logs\UserLogs\$UserLogonName\ADDistroToCopy.csv" | ForEach-Object {Add-ADGroupMember -Identity $_.Name -Members $UserLogonName}

    Write-Output "Adding $UserLogonName to 365 distribution groups"
    Import-CSV "C:\Logs\UserLogs\$UserLogonName\365DistroToCopy.csv" | ForEach-Object {Add-DistributionGroupMember -Identity $_.Name -Member $NewUserEmail}

    Write-Output "Adding $UserLogonName to 365 Unified groups"
    Import-CSV "C:\Logs\UserLogs\$UserLogonName\365UnifiedToCopy.csv" | ForEach-Object {Add-UnifiedGroupLinks -Identity $_.Name -Links $NewUserEmail -LinkType Member}
}