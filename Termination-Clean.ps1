#user termination script
#written by Matt Snoek matthew.snoek at gmail.com

#Gathers variables
$TermUserName = Read-Host "Enter the username of the terminated user in first initial lastname format. Example: Test User = tuser"
$TermEmailAddress = Read-Host "Enter the primary email address of the terminated user."
$ForwardingEmail = Read-Host "Enter the email address that the terminated user's mail should be forwarded to. Hit Enter to leave blank for no forwarding."
$NewPassword = Read-Host "Enter the new password for the terminated user."

Write-Host "Please review the below information and verify that it is correct." -ForegroundColor Green
Write-Host ""
Write-Host "Terminated Username = $TermUserName" -ForegroundColor Yellow
Write-Host ""
Write-Host "Terminated user email address = $TermEmailAddress" -ForegroundColor Yellow
Write-Host ""
Write-Host "Forwarding email = $ForwardingEmail" -ForegroundColor Yellow
Write-Host ""
Write-Host "New user password = $NewPassword" -ForegroundColor Yellow

$VarReview = Read-Host "If this information is correct, type 'yes'. Otherwise, enter 'no'."

if ($VarReview -ne "yes") #Exits if the variable information has been indicated as not correct
{
    Write-Host "You have indicated that the user information entered was incorrect. Exiting script now." -ForegroundColor DarkRed
    Exit
}

$365Credentials = Get-Credential -Message "Enter 365 admin credentials in username@company.com format."
$DOMAIN1Credentials = Get-Credential -Message "Enter DOMAIN1 domain admin credentials in DOMAIN1\username format."
$DOMAIN2Credentials = Get-Credential -Message "Enter DOMAIN2 domain admin credentials in DOMAIN2\username format."
$DOMAIN3Credentials = Get-Credential -Message "Enter DOMAIN3 domain admin credentials in DOMAIN3\username format."

Write-Host ""
Write-Host "Importing modules." -ForegroundColor Green
Import-Module ActiveDirectory
Import-Module MSOnline
Import-Module SkypeOnlineConnector

Write-Host ""
Write-Host "Creating folder for logs and exports"
New-Item -Path "C:\Logs\UserLogs\$TermUserName" -ItemType Directory

Write-Host ""
Write-Host "Connecting to 365." -ForegroundColor Green
$Session = New-PSSession -ConfigurationName Microsoft.Exchange -ConnectionUri https://outlook.office365.com/powershell-liveid/ -Credential $365Credentials -Authentication Basic -AllowRedirection
Import-PSSession $Session
Connect-MsolService -Credential $365Credentials

Write-Host "" 
Write-Host "Syncing DOMAIN1 Domain Controllers." -ForegroundColor Green
RepAdmin /syncall DomainController.DOMAIN1.FQDN /e

Write-Host ""
Write-Host "Verifying user existence in DOMAIN1 AD." -ForegroundColor Green
$DOMAIN1TermVerify = Get-ADUser -Identity "$TermUserName"

if ($DOMAIN1TermVerify -eq $null) #checks to see if user exists in DOMAIN1 domain, exits if not
{
    Write-Host ""
    Write-Host "User $TermUserName does not exist in DOMAIN1 AD, exiting script." -ForegroundColor DarkRed
    Exit
}

if ($DOMAIN1TermVerify) #if user exists in DOMAIN1 domain and runs various termination steps if so
{
    Write-host ""
    Write-Host "Disabling user account $TermUserName." -ForegroundColor Green
    Disable-ADAccount -Identity "$TermUserName"
    
    Write-Host ""
    Write-Host "Resetting user password." -ForegroundColor Green
    Set-ADAccountPassword -Identity "$TermUserName" -Reset -NewPassword (ConvertTo-SecureString "$NewPassword" -AsPlainText -Force)

    Write-Host ""
    Write-Host "Removing user from AD groups." -ForegroundColor Green
    Get-ADPrincipalGroupMembership -Identity "$TermUserName" | ForEach-Object {Remove-ADPrincipalGroupMembership -Identity $TermUserName -MemberOf $_ -Confirm:$False}

    Write-Host ""
    Write-Host "Removing dial-in permissions." -ForegroundColor Green
    Set-ADUser -Identity $TermUserName -Replace @{msNPAllowDialIn=$False}

    Write-Host ""
    Write-Host "Removing user ability to log in via Remote Desktop." -ForegroundColor Green
    $UserDN = Get-ADUser -Identity $TermUserName | Select-Object DistinguishedName -ExpandProperty DistinguishedName
    $UserRDPDisable = [ADSI]"LDAP://$UserDN"
    $UserRDPDisable.psbase.invokeSet("allowLogon",0)
    $UserRDPDisable.setinfo()

    Write-Host ""
    Write-Host "Running a manual dirsync to 365, then sleeping for 5 minutes to allow for catchup" -ForegroundColor Green
    $Dirsyncsession  = New-PSSession -Computername "DIRSYNC.SERVER.FQDN"
    Invoke-Command -Session $Dirsyncsession -ScriptBlock {Import-Module -Name 'ADSync'}
    Invoke-Command -Session $Dirsyncsession -ScriptBlock {Start-ADSyncSyncCycle -PolicyType Delta}
    Remove-PSSession $Dirsyncsession
    Start-Sleep -s 300

    Write-Host ""
    Write-Host "Removing user from 365 security and distribution groups."
    $Mailbox=get-Mailbox $TermEmailAddress
    $DN=$mailbox.DistinguishedName
    $Filter = "Members -like ""$DN"""
    Get-DistributionGroup -ResultSize Unlimited -Filter $Filter | Remove-DistributionGroupMember -Member $TermEmailAddress -Confirm:$False
    Get-UnifiedGroup -ResultSize Unlimited -Filter $Filter | Remove-UnifiedGroupLinks -LinkType Members -Links $TermEmailAddress -Confirm:$False

    Write-Host ""
    Write-Host "Exporting a list of shared mailboxes that the user has Send-As permissions to." -ForegroundColor Green
    Get-Mailbox -RecipientTypeDetails 'SharedMailbox' | Get-MailboxPermission -User $TermEmailAddress | Select-Object Identity | Export-Csv C:\Logs\UserLogs\$TermUserName\$TermUserName.csv

    Write-Host ""
    Write-Host "Removing user from Send-As permissions on shared mailboxes." -ForegroundColor Green
    Import-CSV C:\Logs\UserLogs\$TermUserName\$TermUserName.csv | Foreach-Object {remove-recipientpermission $_.Identity -AccessRights SendAs -Trustee $TermEmailAddress -confirm:$false}

    Write-Host ""
    Write-Host "Removing Full Access permissions on shared mailboxes." -ForegroundColor Green
    Import-Csv C:\Logs\UserLogs\$TermUserName\$TermUserName.csv | Foreach-Object {Remove-MailboxPermission $_.Identity -User $TermEmailAddress -AccessRights FullAccess -Confirm:$False}

    Write-Host ""
    Write-Host "Breaking current ActiveSync mobile connections." -ForegroundColor Green
    Get-MobileDevice -Mailbox $TermEmailAddress | ForEach-object {Remove-ActiveSyncDevice ([string]$_.Guid) -confirm:$false}
    Set-CASMailbox -Identity $TermEmailAddress -ActiveSyncEnabled $False

    Write-Host ""
    Write-Host "Disabling POP, IMAP and OWA access." -ForegroundColor Green
    Set-CASMailbox -Identity $TermEmailAddress -PopEnabled $False
    Set-CASMailbox -Identity $TermEmailAddress -ImapEnabled $False
    Set-CASMailbox -Identity $TermEmailAddress -OWAEnabled $False
    
    Write-Host ""
    Write-Host "Removing 365 and Skype licenses." -ForegroundColor Green
    Set-MsolUserLicense -UserPrincipalName "$TermEmailAddress" -RemoveLicenses "edgeaq:ENTERPRISEPREMIUM"
    Set-MsolUserLicense -UserPrincipalName "$TermEmailAddress" -RemoveLicenses "edgeaq:MCOPSTN1"

    Write-Host ""
    Write-Host "Converting user mailbox to a shared mailbox." -ForegroundColor Green
    Set-Mailbox $TermEmailAddress -Type Shared

    if ($ForwardingEmail)
    {
        Write-Host ""
        Write-Host "Setting forwarding email address to $ForwardingEmail." -ForegroundColor Green
        Set-Mailbox -Identity $TermEmailAddress -DeliverToMailboxAndForward $true -ForwardingAddress $ForwardingEmail

        Write-Host ""
        Write-Host "Granting Full Access permissions to $ForwardingEmail." -ForegroundColor Green
        Add-MailboxPermission -AccessRights FullAccess -Identity $TermEmailAddress -User $ForwardingEmail
    }

    #Write-Host "" 
    #Write-Host "Setting mailbox auto-reply." -ForegroundColor Green
    #Set-mailboxautoreplyconfiguration -identity $TermEmailAddress -AutoReplyState Enabled -ExternalMessage  "Insert external message here" -InternalMessage "Insert internal message here."

    Write-Host ""
    Write-Host "Moving user to Disabled Users OU." -ForegroundColor Green
    Get-ADUser $TermUserName | Move-ADObject -TargetPath 'OU=Disabled Users,DC=domain,DC=name,DC=com'

    Write-Host ""
    Write-Host "Syncing DOMAIN1 domain controllers." -ForegroundColor Green
    RepAdmin /syncall DomainController.DOMAIN1.FQDN /e

	#Checks servers for RDP sessions and removes them
    $ADServerList = Get-ADComputer -Filter {OperatingSystem -Like "Windows Server*"} -Server "$Domain" -Property * | Select-Object -ExpandProperty Name #gets list of server objects from AD

    ForEach ($Server in $ADServerList)
    {
        if ((Test-Connection -ComputerName "$Server" -BufferSize 16 -Count 1 -Quiet) -eq "True") #Checks if server is alive, runs code if it is
        {
            Write-Host "Checking $Domain logged on sessions for server $Server" -ForeGroundColor Green
            Invoke-Command -ComputerName "$Server" -Credential $Creds -ScriptBlock {$SessionID = (qwinsta | 
            ForEach-Object { (($_.trim() -replace "\s+",","))} | 
            ConvertFrom-Csv) | 
            Where-Object {$_.UserName -eq "$TermUserName"} |
            Select-Object -ExpandProperty ID
        
            if ($SessionID)
            {
                Write-Host "Terminating session on server $Server" -ForeGroundColor Yellow
                Logoff "$SessionID"
            }#End $SessionID Exists If
            
        }#End Invoke-Command
        }#End alive check If    
    }#End ForEach
}

Write-Host ""
Write-Host "Connecting to DOMAIN2 AD and checking if user exists." -ForegroundColor Green


$DOMAIN2User = Get-ADUser -Identity $TermUserName -Server "DC.DOMAIN2.FQDN"

if ($DOMAIN2User)
{
    Write-host ""
    Write-Host "Disabling DOMAIN2 user account $TermUserName." -ForegroundColor Green
    Disable-ADAccount -Identity "$TermUserName" -Server "DC.DOMAIN.FQDN" -Credential $DOMAIN2Credentials
    
    Write-Host ""
    Write-Host "Resetting DOMAINT2 user password." -ForegroundColor Green
    Set-ADAccountPassword -Identity "$TermUserName" -Server "DC.DOMAIN2.FQDN" -Credential $DOMAIN2Credentials -Reset -NewPassword (ConvertTo-SecureString "$NewPassword" -AsPlainText -Force)

    Write-Host ""
    Write-Host "Removing user from DOMAIN2 AD groups." -ForegroundColor Green
    Get-ADPrincipalGroupMembership -Identity "$TermUserName" -Server "DC.DOMAIN2.FQDN" -Credential $DOMAIN2Credentials | ForEach-Object {Remove-ADPrincipalGroupMembership -Identity $TermUserName -MemberOf $_ -Confirm:$False}

    Write-Host ""
    Write-Host "Removing DOMAIN2 dial-in permissions." -ForegroundColor Green
    Set-ADUser -Identity $TermUserName -Server "DC.DOMAIN2.FQDN" -Credential $DOMAIN2Credentials -Replace @{msNPAllowDialIn=$False}

    Write-Host ""
    Write-Host "Removing user ability to log in via Remote Desktop." -ForegroundColor Green
    $UserDN = Get-ADUser -Identity $TermUserName -Server "DC.DOMAIN2.FQDN" -Credential $DOMAIN2Credentials | Select-Object DistinguishedName -ExpandProperty DistinguishedName
    $UserRDPDisable = [ADSI]"LDAP://$UserDN"
    $UserRDPDisable.psbase.invokeSet("allowLogon",0)
    $UserRDPDisable.setinfo()

    Write-Host ""
    Write-Host "Moving DOMAIN2 user to Disabled Users OU." -ForegroundColor Green
    Get-ADUser $TermUserName -Server "DC.DOMAIN2.FQDN" -Credential $DOMAIN2Credentials | Move-ADObject -TargetPath 'OU=Disabled Accounts,DC=domain,DC=ou,DC=path'
    
	ForEach ($Server in $ADServerList)
    {
        if ((Test-Connection -ComputerName "$Server" -BufferSize 16 -Count 1 -Quiet) -eq "True") #Checks if server is alive, runs code if it is
        {
            Write-Host "Checking $Domain logged on sessions for server $Server" -ForeGroundColor Green
            Invoke-Command -ComputerName "$Server" -Credential $Creds -ScriptBlock {$SessionID = (qwinsta | 
            ForEach-Object { (($_.trim() -replace "\s+",","))} | 
            ConvertFrom-Csv) | 
            Where-Object {$_.UserName -eq "$TermUserName"} |
            Select-Object -ExpandProperty ID
        
            if ($SessionID)
            {
                Write-Host "Terminating session on server $Server" -ForeGroundColor Yellow
                Logoff "$SessionID"
            }#End $SessionID Exists If
            
        }#End Invoke-Command
        }#End alive check If    
    }#End ForEach
} else {
    Write-Host ""
    Write-Host "DOMAIN2 user not found, continuing with script." -ForegroundColor Yellow
}


Write-Host ""
Write-Host "Connecting to DOMAIN3 AD and checking if user exists." -ForegroundColor Green

$DOMAIN3User = Get-ADUser -Identity $TermUserName -Server "DC.DOMAIN3.FQDN"

if ($DOMAIN3User)
{
    Write-host ""
    Write-Host "Disabling DOMAIN3 user account $TermUserName." -ForegroundColor Green
    Disable-ADAccount -Identity "$TermUserName" -Server "DDC.DOMAIN3.FQDN" -Credential $DOMAIN3Credentials
    
    Write-Host ""
    Write-Host "Resetting DOMAIN3 user password." -ForegroundColor Green
    Set-ADAccountPassword -Identity "$TermUserName" -Server "DC.DOMAIN3.FQDN" -Credential $DOMAIN3Credentials -Reset -NewPassword (ConvertTo-SecureString "$NewPassword" -AsPlainText -Force)

    Write-Host ""
    Write-Host "Removing user from DOMAIN3 AD groups." -ForegroundColor Green
    Get-ADPrincipalGroupMembership -Identity "$TermUserName" -Server "DC.DOMAIN3.FQDN" -Credential $DOMAIN3Credentials | ForEach-Object {Remove-ADPrincipalGroupMembership -Identity $TermUserName -MemberOf $_ -Confirm:$False}

    Write-Host ""
    Write-Host "Removing DOMAIN3 dial-in permissions." -ForegroundColor Green
    Set-ADUser -Identity $TermUserName -Server "DC.DOMAIN3.FQDN" -Credential $DOMAIN3Credentials -Replace @{msNPAllowDialIn=$False}

    Write-Host ""
    Write-Host "Removing user ability to log in via Remote Desktop." -ForegroundColor Green
    $UserDN = Get-ADUser -Identity $TermUserName -Server "DC.DOMAIN3.FQDN" -Credential $DOMAIN3Credentials | Select-Object DistinguishedName -ExpandProperty DistinguishedName
    $UserRDPDisable = [ADSI]"LDAP://$UserDN"
    $UserRDPDisable.psbase.invokeSet("allowLogon",0)
    $UserRDPDisable.setinfo()

    Write-Host ""
    Write-Host "Moving DOMAIN3 user to Disabled Users OU." -ForegroundColor Green
    Get-ADUser $TermUserName -Server "DC.DOMAIN3.FQDN" -Credential $DOMAIN3Credentials | Move-ADObject -TargetPath 'OU=Disabled Users,DC=domain,DC=ou,DC=path'
    
	ForEach ($Server in $ADServerList)
    {
        if ((Test-Connection -ComputerName "$Server" -BufferSize 16 -Count 1 -Quiet) -eq "True") #Checks if server is alive, runs code if it is
        {
            Write-Host "Checking $Domain logged on sessions for server $Server" -ForeGroundColor Green
            Invoke-Command -ComputerName "$Server" -Credential $Creds -ScriptBlock {$SessionID = (qwinsta | 
            ForEach-Object { (($_.trim() -replace "\s+",","))} | 
            ConvertFrom-Csv) | 
            Where-Object {$_.UserName -eq "$TermUserName"} |
            Select-Object -ExpandProperty ID
        
            if ($SessionID)
            {
                Write-Host "Terminating session on server $Server" -ForeGroundColor Yellow
                Logoff "$SessionID"
            }#End $SessionID Exists If
            
        }#End Invoke-Command
        }#End alive check If    
    }#End ForEach
} else {
    Write-Host ""
    Write-Host "DOMAIN3 user not found, continuing with script." -ForegroundColor Yellow
}

Write-Host ""
Write-Host "Removing 365 powershell session." -ForegroundColor Green
Remove-PSsession $Session

Write-Host ""
Write-Host "User termination complete." -ForegroundColor Green
Write-Host "REMOVE USER ACCESS FROM ALL THIRD PARTY SITES!" -ForegroundColor Red