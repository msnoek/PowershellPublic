
function Get-AzureKey {
    param ($VaultName, $DomainVars)
    $Pass = (Get-AzKeyVaultSecret -VaultName $VaultName -Name $DomainVars.TERM_KEY).SecretValue
    New-Object System.Management.Automation.PSCredential ($DomainVars.SERVICE_ACCOUNT, $Pass)
    }

<#Function to be able to use color for read-host variable inputs, take from https://www.powershellgallery.com/packages/Vester/1.0.0/Content/Private%5CRead-HostColor.ps1
Probably better to use function located at https://www.petri.com/tip-writing-better-script-powershell-read-host-cmdlet, but that's more than is needed
#>
function Read-HostColor ($Text) {
    Write-Host $Text -ForegroundColor Yellow -NoNewline
    Write-Output (Read-Host ' ')
}
function Show-Menu {
    Clear-Host
    Write-Host "============================= Environment Selection ============================" -ForegroundColor Yellow
    Write-Host "Enter the key for each environment the user should be created in. Enter 'Q' to finish" -ForegroundColor Yellow
    Write-Host "Press '1' for domain01 domain." -ForegroundColor Yellow
    Write-Host "Press '2' for domain02 domain." -ForegroundColor Yellow
    Write-Host "Press '3' for domain03 domain." -ForegroundColor Yellow
    Write-Host "Press '4' for domain04 domain." -ForegroundColor Yellow
    Write-Host "Press '5' for domain05 domain." -ForegroundColor Yellow
    Write-Host "Press '6' for Office 365 email" -ForegroundColor Yellow
    
    Write-Host "Enter 'done' when done." -ForegroundColor Yellow
}

function Create-ADUser {
    param ($UserNameFirst, $UserNameLast, $UserLogonName, $EmailAddress, $Password, $Contractor, $DomainVars, $Creds)
    
    $Copy = Read-HostColor "If the user permissions are being copied from an existing user, enter the existing user logon name. Otherwise, hit enter to leave blank."
    
    $DisplayName = $UserNameFirst + " " + $UserNameLast
    $PrincipalSuffix = $DomainVars.PRINCIPAL_SUFFIX
    $ContractorOU = $DomainVars.CONTRACTOR_OU
    $UserOU = $DomainVars.USER_OU
    $DC = $DomainVars.DOMAIN_CONTROLLER
    $Domain = $DomainVars.DOMAIN
    $PrincipalName = "$UserLogonName" + "$PrincipalSuffix"
    
    if ($Copy){#Checks to see if the user listed to copy from exists in the appropriate domain, and if so, pulls the OU path from that user, otherwise continues
        Write-Host "`nVerifying that user $Copy exists on domain $Domain" -ForegroundColor Green
        $CopyVerify = Get-ADUser -Identity "$Copy" -Server "$DC" -Credential $Creds #checks if the copied user exists on the domain
        if ($CopyVerify){
            $CopyOU = (((Get-ADUser -identity $Copy -Server "$DC" -Credential $Creds -Properties CanonicalName | select-object -expandproperty DistinguishedName) -split",") | select-object -Skip 1) -join ','
        }else {Write-Host "`nUser $Copy was not found in domain $Domain, continuing without copying groups" -ForegroundColor Red}#end CopyVerify if
    } #End Copy if

    #If user is a contractor, set the OU to the contractor's OU, if they are to be copied from an existing user, set the OU to the existing user's, otherwise set it to default OU
    if ($Copy){$OUPath = $CopyOU} elseif ($Contractor -eq "yes"){$OUPath = $ContractorOU} else {$OUPath = $UserOU}
    $UserHash = @{
        Name 				= "$DisplayName"
        GivenName 			= "$UserNameFirst"
        Surname				= "$UserNameLast"
        DisplayName			= "$DisplayName"
        SamAccountName		= "$UserLogonName"
        UserPrincipalName	= "$PrincipalName"
        EmailAddress		= "$EmailAddress"
        #Description		= "$Description"
        #Office				= "$Office"
        Path 				= "$OUPath"
        #Title				= "$Title"
        #Department			= "$Department"
        #Company			= "$Company"
        #Manager			= "$Manager"
    }#End UserHash

    Write-Host "`nCreating AD user $UserLogonName on domain $Domain" -ForegroundColor Green
    New-AdUser @UserHash -Server $DC -Credential $Creds -AccountPassword (ConvertTo-SecureString "$Password" -AsPlainText -Force) -ChangePasswordAtLogon $false -Enabled $true
    Write-Host "`nPausing for 30 seconds to allow for user creation to finish before copying group memberships" -ForegroundColor Green
    Start-Sleep -s 30
    $ADUser = Get-ADUser $UserLogonName | Select-Object -ExpandProperty DistinguishedName
    if ($Copy){
        Get-ADPrincipalGroupMembership -Identity $Copy | Where-Object {$_.GroupCategory -eq "Security"} | Select-Object Name | ForEach-Object {Add-ADGroupMember -Identity $_.Name -Members "$ADUser"}
        Get-ADPrincipalGroupMembership -Identity $Copy | Where-Object {$_.GroupCategory -eq "Distribution"} | Select-Object Name | ForEach-Object {Add-ADGroupMember -Identity $_.Name -Members "$ADUser"}
    }
} #End Create-ADUser function

function Create-365User {
    param ($EmailAddress, $UserNameFirst, $UserNameLast, $Creds, $Password)
    Write-Host "`nConnecting to 365. You will be prompted for MFA 365 credentials twice." -ForegroundColor Green
    #Connect-Exopssession -UserPrincipalName $Creds
    Connect-ExchangeOnline -Credential $Creds
    Connect-MsolService -Credential $Creds

    $Copy = Read-HostColor "If 365 distribution group memberships are being copied from an existing user, enter the existing user email address. Otherwise, hit enter to leave blank."
    $DisplayName = "$UserNameFirst" + " " + "$UserNameLast"

    Write-Host "Creating and licensing 365 user $EmailAddress" -ForegroundColor Green
    New-MsolUser -DisplayName $DisplayName -FirstName $UserNameFirst -LastName $UserNameLast -UserPrincipalName $EmailAddress -UsageLocation "US" -Password (ConvertTo-SecureString "$Password" -AsPlainText -Force) -LicenseAssignment "reseller-account:ENTERPRISEPREMIUM","reseller-account:NAMEHERE"

    if ($Copy){
        $DN = (Get-Mailbox -Identity $Copy).distinguishedName
        $Filter = "Members -like ""$DN"""
        Get-DistributionGroup -ResultSize Unlimited -Filter $Filter | Select-Object -ExpandProperty Name | ForEach-Object {Add-DistributionGroupMember -Identity $_ -Member $EmailAddress}
        Get-UnifiedGroup -ResultSize Unlimited -Filter $Filter | Select-Object -ExpandProperty Name | ForEach-Object {Add-UnifiedGroupLinks -Identity $_ -Links $EmailAddress -LinkType Member}
    }
}#End Create-365User function

function NewUser-Internal-Notify {
    param ($EmailAddress, $UserNameFirst, $UserNameLast, $SmtpVars, $SmtpCreds, $CurrentUser, $DomainVars)
    $Subject = "New User Creation - Internal"
    $MailBody = "$CurrentUser has created the new internal user $UsernameFirst $UserNameLast in domain $($DomainVars.Domain)"
    Send-MailMessage -smtpServer $SmtpVars.Server -Credential $SmtpCreds -usessl -Port $SmtpVars.Port -From $SmtpVars.Sender -To $SmtpVars.InternalAddress -Subject "$Subject" -Body "$MailBody"
}#End NewUser-Internal-Notify function

function NewUser-External-Notify {
    param ($EmailAddress, $UserLogonName, $SmtpVars, $SmtpCreds, $DomainVars, $DomainCheck)
    $Subject = "Company New User Creation"
    if ($DomainCheck -eq "True"){
        $MailBody = "Company has created new user $UserLogonName $($DomainVars.Domain)"
    } else {
        $MailBody = "Company has created new user $EmailAddress"
    }
    Send-MailMessage -smtpServer $SmtpVars.Server -Credential $SmtpCreds -usessl -Port $SmtpVars.Port -From $SmtpVars.Sender -To $SmtpVars.ExternalAddress -Subject "$Subject" -Body "$MailBody"
}#End NewUser-External-Notify function