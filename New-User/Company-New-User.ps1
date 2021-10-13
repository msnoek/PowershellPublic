#Requires -runasadministrator
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
#Company new user script
#Created by Matthew Snoek (matthew.snoek@gmail.com)
#NOTE: Some changes to powershell versions and Office 365 have made parts of this obsolete

#Gathers variables
Write-Host "Loading Variables" -ForegroundColor Green
Write-Host "NOTE: 'copy groups from existing user' will be prompted per-domain, not at start." -ForegroundColor Red

#Functions and module path variables
$FunctionsPath = "C:\Scripts\New-User\Functions"
$ModulePath = "C:\Scripts\New-User\Modules"

#Azure authentication variables
$VaultName = "Azure KeyVault Name"
$ResourceGroup = "ResourceGroupName"
$AutomationAccount = "AutomationAccountName"
$SubscriptionID = "SubscriptionName"
$TenantID = "Tenant GUID"

#NewUser notification email variables
$CurrentUser = $env:username
$Smtpvars = [PSCustomObject]@{
    Port = '587'
    Sender = 'mailsender@example.com'
    Server = 'mailserver.example.com'
    User = 'user'
    APIKey = ''
    InternalAddress = 'NewUser-Notification@company.com'
    ExternalAddress = 'matthew.snoek@gmail.com'
}


#Below API creds added after authenticating to Azure instead
#$smtpAPIKey = ConvertTo-SecureString (Get-AutomationVariable -Name "SendGrid-API-Key") -AsPlainText -Force
#$smtpCreds = New-Object System.Management.Automation.PSCredential $smtpUser, $smtpAPIKey

#Domain config variables
$JSONPath = "C:\Scripts\New-User\Config"
$Domain01Vars = Get-Content $JSONPath\domain01.json | ConvertFrom-Json #pulls domain01 specific variables from the relevant json file
$Domain02Vars = Get-Content $JSONPath\domain02.json | ConvertFrom-Json #pulls domain02 specific variables from the relevant json file
$Domain03Vars = Get-Content $JSONPath\domain03.json | ConvertFrom-Json #pulls domain03 specific variables from the relevant json file
$Domain04Vars = Get-Content $JSONPath\domain04.json | ConvertFrom-Json #pulls domain04 specific variables from the relevant json file
$Domain05Vars = Get-Content $JSONPath\domain05.json | ConvertFrom-Json #pulls domain05 specific variables from the relevant json file
$365Vars = Get-Content $JSONPath\365.json | ConvertFrom-Json #pulls 365 specific variables from the relevant json file

#Imports functions and module
. $FunctionsPath\New-User-Functions.ps1
#Imports the Exchange Online module that is required for MFA
Import-Module $((Get-ChildItem -Path $("$ModulePath\Apps\2.0\") -Filter CreateExoPSSession.ps1 -Recurse ).FullName | Select-Object -Last 1)

Write-Host ""
Write-Host "Importing modules." -ForegroundColor Green
Import-Module ActiveDirectory
Import-Module MSOnline
Import-Module AzureAD
Import-Module ExchangeOnlineManagement
Import-Module AZ

#Gather user information
$UserNameFirst = Read-HostColor "Enter the first name of the new user."
$UserNameLast = Read-HostColor "Enter the last name of the new user."
$UserLogonName = Read-HostColor "Enter the AD logon name of the new user, generally first initial last name."
$EmailAddress = Read-HostColor "Enter the email address of the new user."
$Password = Read-HostColor "Enter the temporary password for the new user."
$Contractor = Read-HostColor "Is the user a contractor? Type 'yes' or 'no'."

Write-Host "`nPlease review the below information and verify that it is correct." -ForegroundColor Green
Write-Host "`nNew user first name = $UserNameFirst" -ForegroundColor Green
Write-Host "`nNew user last name = $UserNameLast" -ForegroundColor Green
Write-Host "`nNew user logon = $UserLogonName" -ForegroundColor Green
Write-Host "`nNew user Syndigo email address = $EmailAddress" -ForegroundColor Green
Write-Host "`nNew user password = $Password" -ForegroundColor Green
Write-Host "`nNew user is a contractor = $Contractor" -ForegroundColor Green

$VarReview = Read-HostColor "`nIf this information is correct, type 'yes'. Otherwise, enter 'no'."

if ($VarReview -ne "yes") #Exits if the variable information has been indicated as not correct
{
    Write-Host "You have indicated that the user information entered was incorrect. Exiting script now." -ForegroundColor DarkRed
    Exit
}


#Menu to select what environments user should be added to
do
 {
    Show-Menu
    $selection = Read-HostColor "Select the environments that the user should be created in"
    switch ($selection)
    {
    '1' {
        'You have added domain01.com domain to the creation list'
        $Domain01Add = $true
    } '2' {
        'You have added domain02.com domain to the creation list'
        $Domain02Add = $true
    } '3' {
        'You have added domain03.com domain to the creation list'
        $Domain03Add = $true
    } '4' {
        'You have added domain04.com domain to the creation list'
        $Domain04Add = $true
    } '5' {
        'You have added domain05.local domain to the creation list'
        $Domain05Add = $true
    } '6' {

        'You have added externalmail.com Office 365 to the creation list'
        $365Add = $true
    }
    }
    pause
 }
 until ($selection -eq 'done')

 #Authenticates to Azure to pull various credentials and variables
Write-Host "`nEnter the password for the Azure service account. This can be found in the password manager" -ForegroundColor Yellow
$AzureCreds = Get-Credential -UserName PUT-GUID-HERE -Message "Azure SPN" #Username is the GUID of the SPN/Application, as an SPN login takes GUID, not Name
 
Write-Host "Connecting to Azure to gather needed credentials" -Foregroundcolor Green
Connect-AZAccount -Credential $AzureCreds -Tenant "$TenantID" -SubscriptionID "$SubscriptionID" -ServicePrincipal #Use an SPN account for this instead, as our Azure accounts have MFA, which means the -Credential won't work
 
Write-Host "`nGathering needed credentials from Azure KeyVault" -Foregroundcolor Green
$SmtpVars.APIKey = (Get-AzKeyVaultSecret -Name "SendGrid-API-Key" -VaultName $VaultName).SecretValue
$SmtpCreds = New-Object System.Management.Automation.PSCredential $SmtpVars.User, $SmtpVars.APIKey

#TO DO: Replace these If statements with a single function that takes parameters

Write-Host "`nProcessing new user" -Foregroundcolor Green
if ($Domain01Add -eq $true){
    Write-Host "Gathering domain specific variables from config file" -ForegroundColor Green
    $DomainVars = $Domain01Vars
    [bool]$DomainCheck = $true 
    $Creds = Get-AzureKey $VaultName $DomainVars #Runs Get-AzureKey function 
    Create-ADUser $UserNameFirst $UserNameLast $UserLogonName $EmailAddress $Password $Contractor $DomainVars $Creds
    NewUser-Internal-Notify $EmailAddress $UserNameFirst $UserNameLast $SmtpVars $SmtpCreds $CurrentUser $DomainVars
    Newuser-External-Notify $EmailAddress $UserLogonName $SmtpVars $smtpCreds $DomainVars $DomainCheck
}#end domain01add If

if ($Domain02Add -eq $true){
    Write-Host "Gathering domain specific variables from config file" -ForegroundColor Green
    $DomainVars = $Domain02Vars
    $Creds = Get-AzureKey $VaultName $DomainVars #Runs Get-AzureKey function 
    Create-ADUser $UserNameFirst $UserNameLast $UserLogonName $EmailAddress $Password $Contractor $DomainVars $Creds
    NewUser-Internal-Notify $EmailAddress $UserNameFirst $UserNameLast $SmtpVars $SmtpCreds $CurrentUser $DomainVars
}#end domain02add If

if ($Domain03Add -eq $true){
    Write-Host "Gathering domain specific variables from config file" -ForegroundColor Green
    $DomainVars = $Domain03Vars
    $Creds = Get-AzureKey $VaultName $DomainVars #Runs Get-AzureKey function 
    Create-ADUser $UserNameFirst $UserNameLast $UserLogonName $EmailAddress $Password $Contractor $DomainVars $Creds
    NewUser-Internal-Notify $EmailAddress $UserNameFirst $UserNameLast $SmtpVars $SmtpCreds $CurrentUser $DomainVars
}#end domain03add If

if ($Domain04Add -eq $true){
    Write-Host "Gathering domain specific variables from config file" -ForegroundColor Green
    $DomainVars = $Domain04Vars
    $Creds = Get-AzureKey $VaultName $DomainVars #Runs Get-AzureKey function 
    Create-ADUser $UserNameFirst $UserNameLast $UserLogonName $EmailAddress $Password $Contractor $DomainVars $Creds
    NewUser-Internal-Notify $EmailAddress $UserNameFirst $UserNameLast $SmtpVars $SmtpCreds $CurrentUser $DomainVars
}#end domain04add If

if ($Domain05Add -eq $true){
    Write-Host "Gathering domain specific variables from config file" -ForegroundColor Green
    $DomainVars = $Domain05Vars
    $Creds = Get-AzureKey $VaultName $DomainVars #Runs Get-AzureKey function 
    Create-ADUser $UserNameFirst $UserNameLast $UserLogonName $EmailAddress $Password $Contractor $DomainVars $Creds
    NewUser-Internal-Notify $EmailAddress $UserNameFirst $UserNameLast $SmtpVars $SmtpCreds $CurrentUser $DomainVars
}#end domain05add If

if ($365Add -eq $true){
    Write-Host "Gathering 365 creds" -ForegroundColor Green
    $DomainVars = $365Vars
    $Creds = Get-AzureKey $VaultName $DomainVars
    [bool]$DomainCheck = $false
    Create-365User $EmailAddress $UserNameFirst $UserNameLast $Creds $Password
    NewUser-Internal-Notify $EmailAddress $UserNameFirst $UserNameLast $SmtpVars $SmtpCreds $CurrentUser $DomainVars
    Newuser-External-Notify $EmailAddress $UserLogonName $SmtpVars $SmtpCreds $DomainVars $DomainCheck

}#end 365remove If

