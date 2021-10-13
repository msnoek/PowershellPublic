#Requires -runasadministrator
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
#Syndigo user termination script
#Created by Matthew Snoek (matthew.snoek@gmail.com)

#Gathers variables
$LogPath = "C:\Script-Logs\Term"
$ModulePath = "C:\Scripts\Termination\Modules"
$FunctionsPath = "C:\Scripts\Termination\Functions"
$JSONPath = "C:\Scripts\Termination\Config"
$Domain01Vars = Get-Content $JSONPath\domain01.json | ConvertFrom-Json #pulls domain01 specific variables from the relevant json file
$Domain02Vars = Get-Content $JSONPath\domain02.json | ConvertFrom-Json #pulls domain02 specific variables from the relevant json file
$Domain03Vars = Get-Content $JSONPath\domain03.json | ConvertFrom-Json #pulls domain03 specific variables from the relevant json file
$Domain04Vars = Get-Content $JSONPath\domain04.json | ConvertFrom-Json #pulls domain04 specific variables from the relevant json file
$Domain05Vars = Get-Content $JSONPath\domain05.json | ConvertFrom-Json #pulls domain05 specific variables from the relevant json file
$365Vars = Get-Content $JSONPath\365.json | ConvertFrom-Json #pulls 365 specific variables from the relevant json file
#$AzureADVars = Get-Content $JSONPath\AzureADjson | ConvertFrom-Json #pulls AzureAD specific variables from the relevant json file

#Imports functions and module 
. $FunctionsPath\term-functions.ps1
#Imports the Exchange Online module that is required for MFA. Need to check if still necessary after using Azure Keyvault to store creds.
Import-Module ((Get-ChildItem -Path $("$ModulePath\Apps\2.0\") -Filter CreateExoPSSession.ps1 -Recurse ).FullName | Select-Object -Last 1)

$TermUserName = Read-HostColor "Enter the logon name of the terminated user, generally first initial last name."
$TermEmailAddress = Read-HostColor "Enter the primary email address of the terminated user."
$ForwardingEmail = Read-HostColor "Enter the email address that the terminated user's mail should be forwarded to. Hit Enter to leave blank for no forwarding."
$NewPassword = Read-HostColor "Enter the new password for the terminated user."
$Ticket = Read-HostColor "Enter the termination ticket number. Leave blank if no ticket."

Write-Host "`nPlease review the below information and verify that it is correct." -ForegroundColor Green
Write-Host "`nTerminated Username = $TermUserName" -ForegroundColor Green
Write-Host "`nTerminated user Syndigo email address = $TermEmailAddress" -ForegroundColor Green
Write-Host "`nForwarding email = $ForwardingEmail" -ForegroundColor Green
Write-Host "`nNew user password = $NewPassword" -ForegroundColor Green
Write-Host "`nTicket Number = $Ticket" -ForegroundColor Green

$VarReview = Read-HostColor "If this information is correct, type 'yes'. Otherwise, enter 'no'."

if ($VarReview -ne "yes") #Exits if the variable information has been indicated as not correct
{
    Write-Host "You have indicated that the user information entered was incorrect. Exiting script now." -ForegroundColor DarkRed
    Exit
}

#Menu to select what environments user should be removed from
do
 {
    Show-Menu
    $selection = Read-HostColor "Select the environments that the user should be terminated from"
    switch ($selection)
    {
    '1' {
        'You have added Domain01 domain to the removal list' 
        $Domain01Remove = $true
    } '2' {
        'You have added Domain02 domain to the removal list' 
        $Domain02Remove = $true
    } '3' {
        'You have added Domain03 domain to the removal list'
        $Domain03Remove = $true
    } '4' {
        'You have added Domain04 domain to the removal list' 
        $Domain04Remove = $true
    } '5' {
        'You have added Domain05 domain to the removal list'
        $Domain05Remove = $true
    } '6' {
        'You have added Office 365 to the removal list'
        $365Remove = $true
    } 
    }
    pause
 }
 until ($selection -eq 'done')

Write-Host ""
Write-Host "Creating folder for logs and exports" -ForegroundColor Green
New-Item -Path "$LogPath\$TermUserName" -ItemType Directory

Write-Host ""
Write-Host "Importing modules." -ForegroundColor Green
Import-Module ActiveDirectory
Import-Module MSOnline
#Import-Module SkypeOnlineConnector
Import-Module AzureAD
Import-Module ExchangeOnlineManagement


#We've created various credential passwords in Azure keyvault to pull into script
$VaultName = "VaultName"

Write-Host "`nEnter the password for the Azure service account. This can be found in the password manager" -ForegroundColor Yellow
$AzureCreds = Get-Credential -UserName GUID-GOES-HERE -Message "Azure SPN" #Username is the GUID of the SPN/Application, as an SPN login takes GUID, not Name

Write-Host "Connecting to Azure to gather needed credentials" -Foregroundcolor Green
Connect-AZAccount -Credential $AzureCreds -Tenant "Tenant GUID here" -SubscriptionID "Subscription" -ServicePrincipal #Use an SPN account for this instead, as our Azure accounts have MFA, which means the -Credential won't work

Write-Host "`nGathering needed credentials from Azure KeyVault" -Foregroundcolor Green

if ($Domain01Remove -eq $true){
    #Creates PS Credential objects from the credentials stored in Azure Infra-Automation keyvault
    Write-Host "Gathering Domain01 domain specific variables from config file" -ForegroundColor Green
    $DomainVars = $Domain01Vars
    $Creds = Get-AzureKey $VaultName $DomainVars #Runs Get-AzureKey function 
    Domain-Term $TermUserName $NewPassword $DomainVars $Creds $LogPath $Ticket
}#end domain01remove If

if ($Domain02Remove -eq $true){
    #Creates PS Credential objects from the credentials stored in Azure Infra-Automation keyvault
    Write-Host "Gathering Domain02 domain specific variables from config file" -ForegroundColor Green
    $DomainVars = $Domain02Vars
    $Creds = Get-AzureKey $VaultName $DomainVars
    Domain-Term $TermUserName $NewPassword $DomainVars $Creds $LogPath $Ticket
}#end domain02remove If

if ($Domain03Remove -eq $true){
    #Creates PS Credential objects from the credentials stored in Azure Infra-Automation keyvault
    Write-Host "Gathering Domain03 domain specific variables from config file" -ForegroundColor Green
    $DomainVars = $Domain03Vars
    $Creds = Get-AzureKey $VaultName $DomainVars
    Domain-Term $TermUserName $NewPassword $DomainVars $Creds $LogPath $Ticket
}#end domain03remove If

if ($Domain04Remove -eq $true){
    #Creates PS Credential objects from the credentials stored in Azure Infra-Automation keyvault
    Write-Host "Gathering Domain04 domain specific variables from config file" -ForegroundColor Green
    $DomainVars = $Domain04Vars
    $Creds = Get-AzureKey $VaultName $DomainVars
    Domain-Term $TermUserName $NewPassword $DomainVars $Creds $LogPath $Ticket
}#end domain04remove If

if ($Domain05Remove -eq $true){
    #Creates PS Credential objects from the credentials stored in Azure Infra-Automation keyvault
    Write-Host "Gathering NxtGen domain specific variables from config file" -ForegroundColor Green
    $DomainVars = $Domain05Vars
    $Creds = Get-AzureKey $VaultName $DomainVars
    Domain-Term $TermUserName $NewPassword $DomainVars $Creds $LogPath $Ticket
}#end domain05remove If

if ($365Remove -eq $true){
    Write-Host "Gathering 365 specific variables from config file" -ForegroundColor Green
    $DomainVars = $365Vars
    $Creds = Get-AzureKey $VaultName $DomainVars
    Office365-Term $TermEmailAddress $TermUserName $ForwardingEmail $Creds $LogPath
}#end 365remove If
<#
if ($AzureADRemove -eq $true){
    Write-Host "Gathering AzureAD specific variables from config file" -ForegroundColor Green
    $DomainVars = $AzureADVars
    $Creds = Get-AzureKey $VaultName $DomainVars
    AzureAD-Term $TermEmailAddress $TermUserName $ForwardingEmail $Creds $LogPath
}#end 365remove If
#>
Write-Host ""
Write-Host "User termination complete." -ForegroundColor Green
Write-Host "REMOVE USER ACCESS FROM ALL THIRD PARTY SITES!" -ForegroundColor Red