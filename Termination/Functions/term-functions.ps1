function Get-AzureKey {
param ($VaultName, $DomainVars)
$Pass = (Get-AzKeyVaultSecret -VaultName $VaultName -Name $DomainVars.TERM_KEY).SecretValue
New-Object System.Management.Automation.PSCredential ($DomainVars.SERVICE_ACCOUNT, $Pass)
}

function Read-HostColor ($Text) {
    Write-Host $Text -ForegroundColor Yellow -NoNewline
    Write-Output (Read-Host ' ')
}

function Show-Menu {
    Clear-Host
    Write-Host "============================= Environment Selection ============================" -ForegroundColor Yellow
    Write-Host "Enter the key for each environment the user should be removed from. Enter 'Q' to finish" -ForegroundColor Yellow
    Write-Host "Press '1' for domain01 domain." -ForegroundColor Yellow
    Write-Host "Press '2' for domain02 domain." -ForegroundColor Yellow
    Write-Host "Press '3' for domain03 domain." -ForegroundColor Yellow
    Write-Host "Press '4' for domain04 domain." -ForegroundColor Yellow
    Write-Host "Press '5' for domain05 domain." -ForegroundColor Yellow
    Write-Host "Press '6' for Office 365 email" -ForegroundColor Yellow
    Write-Host ""
    Write-Host "Enter 'done' when done." -ForegroundColor Yellow
}

function Office365-Term {
param ($TermEmailAddress, $TermUserName, $ForwardingEmail, $Creds, $LogPath)

    Write-Output "Email Termination Log:" | Out-File "$LogPath\$TermUserName\$TermUserName-EmailLog.txt"

    Write-Host ""
    Write-Host "Connecting to 365 and Azure." -ForegroundColor Green
    
    Connect-ExchangeOnline -Credential $Creds 2>&1 | Tee-Object -FilePath "$LogPath\$TermUserName\$TermUserName-EmailLog.txt" -Append
    Connect-AzureAD -Credential $Creds 2>&1 | Tee-Object -FilePath "$LogPath\$TermUserName\$TermUserName-EmailLog.txt" -Append
    Connect-MsolService -Credential $Creds 2>&1 | Tee-Object -FilePath "$LogPath\$TermUserName\$TermUserName-EmailLog.txt" -Append
    Connect-SpoService -Credential $Creds -url "https://company.sharepoint.com" 2>&1 | Tee-Object -FilePath "$LogPath\$TermUserName\$TermUserName-EmailLog.txt" -Append
    
    $GroupExclude = "All Company" #unified groups to exclude from removal. Will need some adjusting if more than one is required

    #Gathers info on gorup membership
    $Mailbox=get-Mailbox $TermEmailAddress 2>&1 | Tee-Object -FilePath "$LogPath\$TermUserName\$TermUserName-EmailLog.txt" -Append
    $DN=$Mailbox.DistinguishedName 2>&1 | Tee-Object -FilePath "$LogPath\$TermUserName\$TermUserName-EmailLog.txt" -Append
    $Filter = "Members -like ""$DN""" 2>&1 | Tee-Object -FilePath "$LogPath\$TermUserName\$TermUserName-EmailLog.txt" -Append
    $DistributionGroups = Get-Recipient -Filter $Filter | Where-Object {$_.RecipientType -eq "MailUniversalDistributionGroup"} | Select-Object -ExpandProperty Name 2>&1 | Tee-Object -FilePath "$LogPath\$TermUserName\$TermUserName-EmailLog.txt" -Append
    $SecurityGroups = Get-Recipient -Filter $Filter | Where-Object {$_.RecipientType -eq "MailUniversalSecurityGroup"} | Select-Object -ExpandProperty Name 2>&1 | Tee-Object -FilePath "$LogPath\$TermUserName\$TermUserName-EmailLog.txt" -Append
    $UnifiedGroups = Get-UnifiedGroup -ResultSize Unlimited -Filter $Filter | Select-Object -ExpandProperty DisplayName 2>&1 | Tee-Object -FilePath "$LogPath\$TermUserName\$TermUserName-EmailLog.txt" -Append
    $UnifiedGroupsExclude = Get-UnifiedGroup -ResultSize Unlimited -Filter $Filter | Where-Object {$_.DisplayName -notlike "$GroupExclude"} | Select-Object -ExpandProperty DisplayName 2>&1 | Tee-Object -FilePath "$LogPath\$TermUserName\$TermUserName-EmailLog.txt" -Append
    $AzureADGroups = Get-AzureAdUserMembership -ObjectId $TermEmailAddress | Where-Object {$_.DisplayName -notlike "$GroupExclude"} | Select-Object DisplayName, ObjectId 2>&1 | Tee-Object -FilePath "$LogPath\$TermUserName\$TermUserName-EmailLog.txt" -Append
    $LicenseExclude = "reseller-account:INTUNE_A"

    If ($DistributionGroups){
        Write-Host "`nLogging $TermUserName distribution group membership." -ForegroundColor Green
        $DistributionGroups | Out-File "$Logpath\$TermUserName\$TermUserName-Distribution.txt"
    }
    Else {
        Write-Host "`n$TermUserName is not a member of any 365 distribution groups." -ForegroundColor Green
        Write-Output "No distribution group membership found for $TermUserName." | Out-File "$Logpath\$TermUserName\$TermUserName-Distribution.txt"
    }

    If ($SecurityGroups){
        Write-Host "`nLogging $TermUserName security group membership." -ForegroundColor Green
        $SecurityGroups | Out-File "$Logpath\$TermUserName\$TermUserName-Security.txt"
    }
    Else {
        Write-Host "`n$TermUserName is not a member of any 365 security groups." -ForegroundColor Green
        Write-Output "No security group membership found for $TermUserName." | Out-File "$Logpath\$TermUserName\$TermUserName-Security.txt"
    }

    If ($UnifiedGroups){
        Write-Host "`nLogging $TermUserName unified group membership." -ForegroundColor Green
        $UnifiedGroups | Out-File "$Logpath\$TermUserName\$TermUserName-Unified.txt"
    }
    Else {
        Write-Host "`n$TermUserName is not a member of any 365 unified groups." -ForegroundColor Green
        Write-Output "No unified group membership found for $TermUserName." | Out-File "$Logpath\$TermUserName\$TermUserName-Unified.txt"
    }
    If ($AzureADGroups){
        Write-Host "`nLogging $TermUserName Azure AD group membership." -ForegroundColor Green
        $AzureADGroups | Out-File "$Logpath\$TermUserName\$TermUserName-Unified.txt"
    }
    Else {
        Write-Host "`n$TermUserName is not a member of any Azure AD groups." -ForegroundColor Green
        Write-Output "No unified group membership found for $TermUserName." | Out-File "$Logpath\$TermUserName\$TermUserName-Unified.txt"
    }

    Write-Host "`nRemoving user from 365 security and distribution groups." -ForegroundColor Green
    
    Get-DistributionGroup -ResultSize Unlimited -Filter $Filter | Remove-DistributionGroupMember -Member $TermEmailAddress -Confirm:$False -BypassSecurityGroupManagerCheck 2>&1 | Tee-Object -FilePath "$LogPath\$TermUserName\$TermUserName-EmailLog.txt" -Append

    #Removes unified groups from 365
    ForEach ($Group in $UnifiedGroupsExclude) {Remove-UnifiedGroupLinks -Identity $Group -LinkType Members -Links $TermEmailAddress -Confirm:$False 2>&1 | Tee-Object -FilePath "$LogPath\$TermUserName\$TermUserName-EmailLog.txt" -Append}
    #Removes Azure AD groups. Note that this command requires the ObjectID of the group and user, not the displayname. This is why we are pulling the user again.
    $AzureADUser = Get-AzureADUser -ObjectId $TermEmailAddress
    ForEach ($Group in $AzureADGroups) {
        #Doublechecks the Azure AD group membership, as the user will likely have been removed from some AzureAD groups already from the 365 removal portion.
        $GroupMembers = (Get-AzureADGroupMember -ObjectId $Group.ObjectId | Select-Object ObjectId)
        if ($GroupMembers -Match $AzureADUser.ObjectId){
            Remove-AzureADGroupMember -ObjectId $Group.ObjectId -MemberId $AzureADUser.ObjectId 2>&1 | Tee-Object -FilePath "$LogPath\$TermUserName\$TermUserName-EmailLog.txt" -Append
        } else {
            Write-Output "User $TermUserName has already been removed from "$Group.ObjectId"." | Out-File "$LogPath\$TermUserName\$TermUserName-EmailLog.txt" -Append
        }
    }

    Write-Host "`nExporting a list of shared mailboxes that the user has Send-As permissions to." -ForegroundColor Green
    $SharedMailboxes = Get-Mailbox -RecipientTypeDetails 'SharedMailbox' | Get-MailboxPermission -User $TermEmailAddress | Select-Object -ExpandProperty Identity 2>&1 | Tee-Object -FilePath "$LogPath\$TermUserName\$TermUserName-EmailLog.txt" -Append
    if ($SharedMailboxes){
        $SharedMailboxes | Out-File "$Logpath\$TermUserName\$TermUserName-Shared.txt"
        Write-Host "`nRemoving user from Send-As and Full Access permissions on shared mailboxes." -ForegroundColor Green
        Foreach ($Share in $SharedMailboxes){
            Remove-RecipientPermission "$Share" -AccessRights SendAs -Trustee $TermEmailAddress -confirm:$false 2>&1 | Tee-Object -FilePath "$LogPath\$TermUserName\$TermUserName-EmailLog.txt" -Append
            Remove-MailboxPermission "$Share" -User $TermEmailAddress -AccessRights FullAccess -Confirm:$False 2>&1 | Tee-Object -FilePath "$LogPath\$TermUserName\$TermUserName-EmailLog.txt" -Append
        }#End sharedmailboxes foreach
    }#end SharedMailboxes check If
    
    Write-Host "`nBreaking current ActiveSync mobile connections." -ForegroundColor Green
    $Mobile = Get-MobileDevice -Mailbox $TermEmailAddress 2>&1 | Tee-Object -FilePath "$LogPath\$TermUserName\$TermUserName-EmailLog.txt" -Append #Gets mobile devices attached to account for logging purposes
    If ($Mobile){
        Write-Host "`nLogging $TermUserName mobile device partnerships." -ForegroundColor Green
        $Mobile | Out-File "$Logpath\$TermUserName\$TermUserName-Mobile.txt"
    }
    Else {
        Write-Host "`n$TermUserName does not have any mobile device partnerships." -ForegroundColor Green
        Write-Output "No mobile device partnerships found for $TermUserName." | Out-File "$Logpath\$TermUserName\$TermUserName-Mobile.txt"
    }

    Get-MobileDevice -Mailbox $TermEmailAddress | ForEach-object {Remove-ActiveSyncDevice ([string]$_.Guid) -confirm:$false} 2>&1 | Tee-Object -FilePath "$LogPath\$TermUserName\$TermUserName-EmailLog.txt" -Append #Gets mobile devices attached to account and breaks sync
    Set-CASMailbox -Identity $TermEmailAddress -ActiveSyncEnabled $False 2>&1 | Tee-Object -FilePath "$LogPath\$TermUserName\$TermUserName-EmailLog.txt" -Append #Removes activesync
    
    Write-Host "`nDisabling POP, IMAP and OWA access." -ForegroundColor Green
    Set-CASMailbox -Identity $TermEmailAddress -PopEnabled $False -ImapEnabled $False -OWAEnabled $False 2>&1 | Tee-Object -FilePath "$LogPath\$TermUserName\$TermUserName-EmailLog.txt" -Append

    Write-Host "`nRemoving 365 and Skype licenses." -ForegroundColor Green
    $Licenses = Get-MsolUser -UserPrincipalName "$TermEmailAddress" | Select-Object -ExpandProperty Licenses | Where-Object {$_.AccountSkuId -notlike "$LicenseExclude"} | Select-Object -ExpandProperty AccountSkuId 2>&1 | Tee-Object -FilePath "$LogPath\$TermUserName\$TermUserName-EmailLog.txt" -Append #gets all assigned 365 licenses
    If ($Licenses){
        Write-Host "`nLogging $TermUserName license membership." -ForegroundColor Green
        $Licenses | Out-File "$Logpath\$TermUserName\$TermUserName-Licenses.txt"
    }
    Else {
        Write-Host "`n$TermUserName has no assigned licenses." -ForegroundColor Green
        Write-Output "No licenses found for $TermUserName." | Out-File "$Logpath\$TermUserName\$TermUserName-Licenses.txt"
    }

    ForEach ($License in $Licenses) {Set-MsolUserLicense -UserPrincipalName "$TermEmailAddress" -RemoveLicenses "$License" 2>&1 | Tee-Object -FilePath "$LogPath\$TermUserName\$TermUserName-EmailLog.txt" -Append }#Removes all assigned 365 licenses
    
    Write-Host "`nBlocking user login to 365" -ForegroundColor Green
    Set-MSOLUser -UserPrincipalName "$TermEmailAddress" -BlockCredential $true 2>&1 | Tee-Object -FilePath "$LogPath\$TermUserName\$TermUserName-EmailLog.txt" -Append #Prevents login

    Write-Host "`nForcing user signout." -ForegroundColor Green
    Revoke-SPOUserSession -User $TermEmailAddress -Confirm:$false 2>&1 | Tee-Object -FilePath "$LogPath\$TermUserName\$TermUserName-EmailLog.txt" -Append #Forces disconnect

    Write-Host "`nConverting user mailbox to a shared mailbox." -ForegroundColor Green
    Set-Mailbox $TermEmailAddress -Type Shared 2>&1 | Tee-Object -FilePath "$LogPath\$TermUserName\$TermUserName-EmailLog.txt" -Append #Sets mailbox to a shared mailbox

    #Write-Host "`nDisabling Azure AD Account" -ForegroundColor Green
    #Set-AzureADUser -ObjectID "$TermEmailAddress" -AccountEnabled $false

        if ($ForwardingEmail)
            {
                Write-Host "`nSetting forwarding email address to $ForwardingEmail." -ForegroundColor Green
                Set-Mailbox -Identity $TermEmailAddress -DeliverToMailboxAndForward $true -ForwardingAddress $ForwardingEmail 2>&1 | Tee-Object -FilePath "$LogPath\$TermUserName\$TermUserName-EmailLog.txt" -Append
                
                Write-Host "`nGranting Full Access permissions to $ForwardingEmail." -ForegroundColor Green
                Add-MailboxPermission -AccessRights FullAccess -Identity $TermEmailAddress -User $ForwardingEmail 2>&1 | Tee-Object -FilePath "$LogPath\$TermUserName\$TermUserName-EmailLog.txt" -Append
            }#End Forwarding Email If
    Write-Host "`nRemoving 365 powershell session." -ForegroundColor Green
    Get-PSSession | Remove-PSSession #Disconnect from 365
} #End Office365-Term function

function Domain-Term {
        param ($TermUserName, $NewPassword, $DomainVars, $Creds, $LogPath, $Ticket) #Takes variables from the calling script
        <# This section can be used if the username is input as actual firstname lastname
        $FirstName = (-Split $TermUserName | Select-Object -first 1).ToLower()
        $LastName = (-Split $TermUserName | Select-Object -last 1).ToLower()
        $FirstInitial = $FirstName.substring(0,1)
        $UserName = $FirstInitial + $LastName
        #>
        Write-Output "Domain Termination Log:" | Out-File "$LogPath\$TermUserName\$TermUserName-DomainLog.txt"
        $UserName = $TermUserName
        $DC = $DomainVars.DOMAIN_CONTROLLER
        $Domain = $DomainVars.DOMAIN
        $OUPath = $DomainVars.DISABLE_OU
        $DomainUserCN = $DomainVars.DOMAIN_USERS
        Write-Host "`nVerifying user existence in $Domain AD." -ForegroundColor Green
        $TermVerify = $null
        $TermVerify = Get-ADUser -Identity "$UserName" -Server "$DC" -Credential $Creds 2>&1 | Tee-Object -FilePath "$LogPath\$TermUserName\$TermUserName-DomainLog.txt" -Append #checks if user exists on the domain

        if ($TermVerify){ #if user exists, terminate
            $DomainUserGroup = (Get-ADGroup -Identity "$DomainUserCN" -Server "$DC" -Credential $Creds).distinguishedName 2>&1 | Tee-Object -FilePath "$LogPath\$TermUserName\$TermUserName-DomainLog.txt" -Append
            Write-Host "`nDisabling $Domain user account $UserName." -ForegroundColor Green
            Disable-ADAccount -Identity "$UserName" -Server "$DC" -Credential $Creds 2>&1 | Tee-Object -FilePath "$LogPath\$TermUserName\$TermUserName-DomainLog.txt" -Append
                   
            Write-Host "`nAdding ticket number and date to user account" -ForegroundColor Green
            $Date = Get-Date
            Set-ADUser -Identity $UserName -Server "$DC" -Credential $Creds -Description "Terminated on $Date as per ticket number $Ticket" 2>&1 | Tee-Object -FilePath "$LogPath\$TermUserName\$TermUserName-DomainLog.txt" -Append
            
            Write-Host "`nResetting $Domain user password." -ForegroundColor Green
            Set-ADAccountPassword -Identity "$UserName" -Server "$DC" -Credential $Creds -Reset -NewPassword (ConvertTo-SecureString "$NewPassword" -AsPlainText -Force) 2>&1 | Tee-Object -FilePath "$LogPath\$TermUserName\$TermUserName-DomainLog.txt" -Append
                
            Write-Host "`nRemoving user from $Domain AD groups and recording membership to $LogPath\$TermUserName\$TermUserName-Groups.txt." -ForegroundColor Green
            Write-Output "$Domain Groups:" | Out-File "$LogPath\$TermUserName\$TermUserName-Groups.txt"
            Get-ADPrincipalGroupMembership -Identity "$UserName" -Server "$DC" -Credential $Creds -ResourceContextServer "$Domain" | Select-Object name | Out-File "$LogPath\$TermUserName\$TermUserName-Groups.txt"
            Get-ADPrincipalGroupMembership -Identity "$UserName" -Server "$DC" -Credential $Creds -ResourceContextServer "$Domain" | Where-Object {$_.distinguishedName -ne "$DomainUserGroup"} | ForEach-Object {Remove-ADPrincipalGroupMembership -Identity $UserName -Server "$DC" -Credential $Creds -MemberOf $_ -Confirm:$False} 2>&1 | Tee-Object -FilePath "$LogPath\$TermUserName\$TermUserName-DomainLog.txt" -Append
                
            Write-Host "`nRemoving $Domain dial-in permissions." -ForegroundColor Green
            Set-ADUser -Identity $UserName -Server "$DC" -Credential $Creds -Replace @{msNPAllowDialIn=$False} 2>&1 | Tee-Object -FilePath "$LogPath\$TermUserName\$TermUserName-DomainLog.txt" -Append

            Write-Host "`nMoving user to $Domain Disabled Users OU." -ForegroundColor Green
            Get-ADUser $UserName -Server "$DC" -Credential $Creds | Move-ADObject -TargetPath "$OUPath" 2>&1 | Tee-Object -FilePath "$LogPath\$TermUserName\$TermUserName-DomainLog.txt" -Append
                    
            Write-Host "`nSyncing $Domain domain controllers." -ForegroundColor Green
            RepAdmin /syncall "$DC" /e | Out-Null

        
            $DisableCheck = Get-ADUser -Identity "$UserName" -Server "$DC" -Credential $Creds 
            if($DisableCheck.Enabled -eq $true) {

                Write-Host "User $TermUserName has NOT been disabled in domain $Domain! Check the user status and logs." -ForegroundColor DarkYellow
            }
            else {Write-Host "User $TermUserName has been terminated" -Foregroundcolor Green}
           

        }#end user check termination if
        else {
            Write-Output "User $TermUserName does not exist in domain $Domain" | Out-File "$LogPath\$TermUserName\$TermUserName-DomainLog.txt"
        }
 
}#end domain-term function
