$UserPath = [Environment]::GetFolderPath("UserProfile")
cd $UserPath

Write-Host -ForegroundColor Yellow ""
Write-Host -ForegroundColor Yellow "--------------------------------------------------------------------------"
Write-Host -ForegroundColor Red "Experience the fast and reliable Exchange PowerShell V2 Cmdlets via new PowerShellGallery module. Go to https://aka.ms/exops-docs"
Write-Host -ForegroundColor Yellow ""
Write-Host -ForegroundColor Yellow "This PowerShell module allows you to connect to Exchange Online service."
Write-Host -ForegroundColor Yellow "To connect, use: Connect-EXOPSSession -UserPrincipalName <your UPN>"
Write-Host -ForegroundColor Yellow "This PowerShell module allows you to connect Exchange Online Protection and Security & Compliance Center services also."
Write-Host -ForegroundColor Yellow "To connect, use: Connect-IPPSSession -UserPrincipalName <your UPN>"
Write-Host -ForegroundColor Yellow ""
Write-Host -ForegroundColor Yellow "To get additional information, use: Get-Help Connect-EXOPSSession, or Get-Help Connect-IPPSSession"
Write-Host -ForegroundColor Yellow ""
Write-Host -ForegroundColor Yellow "--------------------------------------------------------------------------"
Write-Host -ForegroundColor Yellow ""

<#
.Synopsis Validates a given Uri
#>

function Test-Uri
{
    [CmdletBinding()]
    [OutputType([bool])]
    Param
    (
        # Uri to be validated
        [Parameter(Mandatory=$true, ValueFromPipelineByPropertyName=$true, Position=0)]
        [string]
        $UriString
    )

    [Uri]$uri = $UriString -as [Uri]

    $uri.AbsoluteUri -ne $null -and $uri.Scheme -eq 'https'
}

<#
.Synopsis Is Cloud Shell Environment
#>
function global:IsCloudShellEnvironment()
{
    if ((-not (Test-Path env:"ACC_CLOUD")) -or ((get-item env:"ACC_CLOUD").Value -ne "PROD"))
    {
        return $false
    }
    return $true
}

<#
.Synopsis Override Get-PSImplicitRemotingSession function for reconnection
#>
function global:UpdateImplicitRemotingHandler()
{
    $modules = Get-Module tmp_*

    foreach ($module in $modules)
    {
        [bool]$moduleProcessed = $false
        [string] $moduleUrl = $module.Description
        [int] $queryStringIndex = $moduleUrl.IndexOf("?")

        if ($queryStringIndex -gt 0)
        {
            $moduleUrl = $moduleUrl.SubString(0,$queryStringIndex)
        }

        if ($moduleUrl.EndsWith("/PowerShell-LiveId", [StringComparison]::OrdinalIgnoreCase) -or $moduleUrl.EndsWith("/PowerShell", [StringComparison]::OrdinalIgnoreCase))
        {
            & $module { ${function:Get-PSImplicitRemotingSession} = `
            {
                param(
                    [Parameter(Mandatory = $true, Position = 0)]
                    [string]
                    $commandName
                )

                if (($script:PSSession -eq $null) -or ($script:PSSession.Runspace.RunspaceStateInfo.State -ne 'Opened'))
                {
                    Set-PSImplicitRemotingSession `
                        (& $script:GetPSSession `
                            -InstanceId $script:PSSession.InstanceId.Guid `
                            -ErrorAction SilentlyContinue )
                }
                if (($script:PSSession -ne $null) -and ($script:PSSession.Runspace.RunspaceStateInfo.State -eq 'Disconnected'))
                {
                    # If we are handed a disconnected session, try re-connecting it before creating a new session.
                    Set-PSImplicitRemotingSession `
                        (& $script:ConnectPSSession `
                            -Session $script:PSSession `
                            -ErrorAction SilentlyContinue)
                }
                if (($script:PSSession -eq $null) -or ($script:PSSession.Runspace.RunspaceStateInfo.State -ne 'Opened'))
                {
                    Write-PSImplicitRemotingMessage ('Creating a new Remote PowerShell session using MFA for implicit remoting of "{0}" command ...' -f $commandName)
                    if (($isCloudShell = IsCloudShellEnvironment) -eq $false)
                    {
                        $session = New-ExoPSSession -UserPrincipalName $global:UserPrincipalName -ConnectionUri $global:ConnectionUri -AzureADAuthorizationEndpointUri $global:AzureADAuthorizationEndpointUri -PSSessionOption $global:PSSessionOption -Credential $global:Credential -BypassMailboxAnchoring:$global:BypassMailboxAnchoring -DelegatedOrg $global:DelegatedOrganization 
                    }
                    else
                    {
                        $session = New-ExoPSSession -ConnectionUri $global:ConnectionUri -AzureADAuthorizationEndpointUri $global:AzureADAuthorizationEndpointUri -PSSessionOption $global:PSSessionOption -BypassMailboxAnchoring:$global:BypassMailboxAnchoring -DelegatedOrg $global:DelegatedOrganization
                    }

                    if ($session -ne $null)
                    {
                        Set-PSImplicitRemotingSession -CreatedByModule $true -PSSession $session
                    }

                    RemoveBrokenOrClosedPSSession
                }
                if (($script:PSSession -eq $null) -or ($script:PSSession.Runspace.RunspaceStateInfo.State -ne 'Opened'))
                {
                    throw 'No session has been associated with this implicit remoting module'
                }

                return [Management.Automation.Runspaces.PSSession]$script:PSSession
            }}
        }
    }
}

<#
.Synopsis Remove broken and closed sessions
#>
function global:RemoveBrokenOrClosedPSSession()
{
    $psBroken = Get-PSSession | where-object {$_.State -like "*Broken*"}
    $psClosed = Get-PSSession | where-object {$_.State -like "*Closed*"}

    if ($psBroken.count -gt 0)
    {
        for ($index = 0; $index -lt $psBroken.count; $index++)
        {
            Remove-PSSession -session $psBroken[$index]
        }
    }

    if ($psClosed.count -gt 0)
    {
        for ($index = 0; $index -lt $psClosed.count; $index++)
        {
            Remove-PSSession -session $psClosed[$index]
        }
    }
}

<#
.SYNOPSIS Extract organization name from UserPrincipalName
#>
function Get-OrgNameFromUPN
{
    param([string] $UPN)
    $fields = $UPN -split '@'
    return $fields[-1]
}

###### Begin Main ######

function Connect-EXOPSSession 
{
    <#
        .SYNOPSIS
            To connect in other Office 365 offerings, use the following settings:
             - Office 365 operated by 21Vianet: -ConnectionURI https://partner.outlook.cn/PowerShell-LiveID -AzureADAuthorizationEndpointUri https://login.chinacloudapi.cn/common
             - Office 365 Germany: -ConnectionURI https://outlook.office.de/PowerShell-LiveID -AzureADAuthorizationEndpointUri https://login.microsoftonline.de/common
			 - Office 365 U.S. Government GCC High: -ConnectionURI https://outlook.office365.us -AzureADAuthorizationEndpointUri https://login.microsoftonline.us/common
			 - Office 365 U.S. Government DoD: -ConnectionURI https://outlook-dod.office365.us -AzureADAuthorizationEndpointUri https://login.microsoftonline.us/common
        
            - PSSessionOption accept object created using New-PSSessionOption

            - EnableEXOTelemetry To collect telemetry on Exchange cmdlets. Default value is False.

            - TelemetryFilePath Telemetry records will be written to this file. Default value is %TMP%\EXOCmdletTelemetry\EXOCmdletTelemetry-yyyymmdd-hhmmss.csv

            - DoLogErrorMessage Switch to enable/disable error message logging in telemetry file. Default value is True.

            - DelegatedOrg Domain name of Delegated Organization if you want to manage another tenant

        .DESCRIPTION
            This PowerShell module allows you to connect to Exchange Online service
        .LINK
            https://go.microsoft.com/fwlink/p/?linkid=837645
    #>
    [CmdletBinding()]
    param(
        # Connection Uri for the Remote PowerShell endpoint
        [string] $ConnectionUri = 'https://outlook.office365.com/PowerShell-LiveId',

        # Azure AD Authorization endpoint Uri that can issue the OAuth2 access tokens
        [string] $AzureADAuthorizationEndpointUri = 'https://login.windows.net/common',
       
        # PowerShell session options to be used when opening the Remote PowerShell session
        [System.Management.Automation.Remoting.PSSessionOption] $PSSessionOption = $null,

        # Switch to bypass use of mailbox anchoring hint.
        [switch] $BypassMailboxAnchoring = $false,

		# Delegated Organization Name
		[string] $DelegatedOrganization = ''
    )
    DynamicParam
    {
        if (($isCloudShell = IsCloudShellEnvironment) -eq $false)
        {
            $attributes = New-Object System.Management.Automation.ParameterAttribute
            $attributes.Mandatory = $false

            $attributeCollection = New-Object System.Collections.ObjectModel.Collection[System.Attribute]
            $attributeCollection.Add($attributes)

            # User Principal Name or email address of the user
            $UserPrincipalName = New-Object System.Management.Automation.RuntimeDefinedParameter('UserPrincipalName', [string], $attributeCollection)
            $UserPrincipalName.Value = ''

            # User Credential to Logon
            $Credential = New-Object System.Management.Automation.RuntimeDefinedParameter('Credential', [System.Management.Automation.PSCredential], $attributeCollection)
            $Credential.Value = $null
            
            # Switch to collect telemetry on command execution. 
            $EnableEXOTelemetry = New-Object System.Management.Automation.RuntimeDefinedParameter('EnableEXOTelemetry', [switch], $attributeCollection)
            $EnableEXOTelemetry.Value = $false
            
            # Where to store EXO command telemetry data. By default telemetry is stored in 
            # %TMP%/EXOTelemetry/EXOCmdletTelemetry-yyyymmdd-hhmmss.csv.
            $TelemetryFilePath = New-Object System.Management.Automation.RuntimeDefinedParameter('TelemetryFilePath', [string], $attributeCollection)
            $TelemetryFilePath.Value = ''
            
            # Switch to Disable error message logging in telemetry file.
            $DoLogErrorMessage = New-Object System.Management.Automation.RuntimeDefinedParameter('DoLogErrorMessage', [switch], $attributeCollection)
            $DoLogErrorMessage.Value = $true
            
            $paramDictionary = New-object System.Management.Automation.RuntimeDefinedParameterDictionary
            $paramDictionary.Add('UserPrincipalName', $UserPrincipalName)
            $paramDictionary.Add('Credential', $Credential)
            $paramDictionary.Add('EnableEXOTelemetry', $EnableEXOTelemetry)
            $paramDictionary.Add('TelemetryFilePath', $TelemetryFilePath)
            $paramDictionary.Add('DoLogErrorMessage', $DoLogErrorMessage)
            return $paramDictionary
        }
        else
        {
            $attributes = New-Object System.Management.Automation.ParameterAttribute
            $attributes.Mandatory = $false

            $attributeCollection = New-Object System.Collections.ObjectModel.Collection[System.Attribute]
            $attributeCollection.Add($attributes)

            # Switch to MSI auth 
            $Device = New-Object System.Management.Automation.RuntimeDefinedParameter('Device', [switch], $attributeCollection)
            $Device.Value = $false

            $paramDictionary = New-object System.Management.Automation.RuntimeDefinedParameterDictionary
            $paramDictionary.Add('Device', $Device)
            return $paramDictionary
        }
    }
    process {

        # Validate parameters
        if (-not (Test-Uri $ConnectionUri))
        {
            throw "Invalid ConnectionUri parameter '$ConnectionUri'"
        }
        if (-not (Test-Uri $AzureADAuthorizationEndpointUri))
        {
            throw "Invalid AzureADAuthorizationEndpointUri parameter '$AzureADAuthorizationEndpointUri'"
        }

        # Keep track of error count at beginning.
        $errorCountAtStart = $global:Error.Count;
        
        try
        {
            # Cleanup old ps sessions
            Get-PSSession | Remove-PSSession

            $ExoPowershellModule = "Microsoft.Exchange.Management.ExoPowershellModule.dll";
            $ModulePath = [System.IO.Path]::Combine($PSScriptRoot, $ExoPowershellModule);

            $global:ConnectionUri = $ConnectionUri;
            $global:AzureADAuthorizationEndpointUri = $AzureADAuthorizationEndpointUri;
            $global:PSSessionOption = $PSSessionOption;
            $global:BypassMailboxAnchoring = $BypassMailboxAnchoring;
            $global:DelegatedOrganization = $DelegatedOrganization;

            if ($isCloudShell -eq $false)
            {
                $global:UserPrincipalName = $UserPrincipalName.Value;
                $global:Credential = $Credential.Value;
            }
            else
            {
                $global:Device = $Device.Value;
            }

            Import-Module $ModulePath;
            
            if ($isCloudShell -eq $false)
            {
                $PSSession = New-ExoPSSession -UserPrincipalName $UserPrincipalName.Value -ConnectionUri $ConnectionUri -AzureADAuthorizationEndpointUri $AzureADAuthorizationEndpointUri -PSSessionOption $PSSessionOption -Credential $Credential.Value -BypassMailboxAnchoring:$BypassMailboxAnchoring -DelegatedOrg $DelegatedOrganization
            }
            else
            {
                $PSSession = New-ExoPSSession -ConnectionUri $ConnectionUri -AzureADAuthorizationEndpointUri $AzureADAuthorizationEndpointUri -PSSessionOption $PSSessionOption -BypassMailboxAnchoring:$BypassMailboxAnchoring -Device:$Device.Value -DelegatedOrg $DelegatedOrganization
            }

            if ($PSSession -ne $null)
            {				
                $PSSessionModuleInfo = Import-PSSession $PSSession -AllowClobber
				UpdateImplicitRemotingHandler

                # If we are configured to collect telemetry, add telemetry wrappers. 
                if ($EnableEXOTelemetry.Value -eq $true)
                {
                    $TelemetryFilePath.Value = Add-EXOClientTelemetryWrapper -Organization (Get-OrgNameFromUPN -UPN $UserPrincipalName.Value) -PSSessionModuleName $PSSessionModuleInfo.Name -TelemetryFilePath $TelemetryFilePath.Value -DoLogErrorMessage:$DoLogErrorMessage.Value
                }
            }
        }
        catch
        {
            throw $_
        }
        Finally 
        {
            # If telemetry is enabled, log errors generated from this cmdlet also. 
            if ($EnableEXOTelemetry.Value -eq $true)
            {
                $errorCountAtProcessEnd = $global:Error.Count 

                # If we have any errors during this cmdlet execution, log it. 
                if ($errorCountAtProcessEnd -gt $errorCountAtStart)
                {
                    if (!$TelemetryFilePath.Value)
                    {
                        $TelemetryFilePath.Value = New-EXOClientTelemetryFilePath
                    }

                    # Log errors which are encountered during Connect-EXOPSSession execution. 
                    Write-Warning("Writing Connect-EXOPSSession errors to " + $TelemetryFilePath.Value)
                    
                    Push-EXOTelemetryRecord -TelemetryFilePath $TelemetryFilePath.Value -CommandName Connect-EXOPSSession -OrganizationName  $global:ExPSTelemetryOrganization -ScriptName $global:ExPSTelemetryScriptName  -ScriptExecutionGuid $global:ExPSTelemetryScriptExecutionGuid -ErrorObject $global:Error -ErrorRecordsToConsider ($errorCountAtProcessEnd - $errorCountAtStart) 
                }
            }
        }
    }
}

function Connect-IPPSSession
{
    <#
        .SYNOPSIS
            Connect-IPPSSession -ConnectionURI https://ps.compliance.protection.outlook.com/PowerShell-LiveId -AzureADAuthorizationEndpointUri https://login.windows.net/common
            NOTE: PSSessionOption accept object created using New-PSSessionOption
                  Please add -DelegatedOrganization para name and its value (domain name) if you want manage another tenant

        .DESCRIPTION
            This cmdlet allows you to connect to Exchange Online Protection Service
    #>
    [CmdletBinding()]
    param(
        # Connection Uri for the Remote PowerShell endpoint
        [string] $ConnectionUri = 'https://ps.compliance.protection.outlook.com/PowerShell-LiveId',

        # Azure AD Authorization endpoint Uri that can issue the OAuth2 access tokens
        [string] $AzureADAuthorizationEndpointUri = 'https://login.windows.net/common',

        # Delegated Organization Name
        [string] $DelegatedOrganization = '',

        # PowerShell session options to be used when opening the Remote PowerShell session
        [System.Management.Automation.Remoting.PSSessionOption] $PSSessionOption = $null,

        # Switch to bypass use of mailbox anchoring hint.
        [switch] $BypassMailboxAnchoring = $false
    )
    DynamicParam
    {
        if (($isCloudShell = IsCloudShellEnvironment) -eq $false)
        {
            $attributes = New-Object System.Management.Automation.ParameterAttribute
            $attributes.Mandatory = $false

            $attributeCollection = New-Object System.Collections.ObjectModel.Collection[System.Attribute]
            $attributeCollection.Add($attributes)

            # User Principal Name or email address of the user
            $UserPrincipalName = New-Object System.Management.Automation.RuntimeDefinedParameter('UserPrincipalName', [string], $attributeCollection)
            $UserPrincipalName.Value = ''
            # User Credential to Logon
            $Credential = New-Object System.Management.Automation.RuntimeDefinedParameter('Credential', [System.Management.Automation.PSCredential], $attributeCollection)
            $Credential.Value = $null

            $paramDictionary = New-object System.Management.Automation.RuntimeDefinedParameterDictionary
            $paramDictionary.Add('UserPrincipalName', $UserPrincipalName)
            $paramDictionary.Add('Credential', $Credential)
            return $paramDictionary
        }
        else
        {
            $attributes = New-Object System.Management.Automation.ParameterAttribute
            $attributes.Mandatory = $false

            $attributeCollection = New-Object System.Collections.ObjectModel.Collection[System.Attribute]
            $attributeCollection.Add($attributes)

            # Switch to MSI auth 
            $Device = New-Object System.Management.Automation.RuntimeDefinedParameter('Device', [switch], $attributeCollection)
            $Device.Value = $false

            $paramDictionary = New-object System.Management.Automation.RuntimeDefinedParameterDictionary
            $paramDictionary.Add('Device', $Device)
            return $paramDictionary
        }
    }
    process {
        [string]$newUri = $null;

        if (![string]::IsNullOrWhiteSpace($DelegatedOrganization))
        {
            [UriBuilder] $uriBuilder = New-Object -TypeName UriBuilder -ArgumentList $ConnectionUri;
            [string] $queryToAppend = "DelegatedOrg={0}" -f $DelegatedOrganization;
            if ($uriBuilder.Query -ne $null -and $uriBuilder.Query.Length -gt 0)
            {
                [string] $existingQuery = $uriBuilder.Query.Substring(1);
                $uriBuilder.Query = $existingQuery + "&" + $queryToAppend;
            }
            else
            {
                $uriBuilder.Query = $queryToAppend;
            }

            $newUri = $uriBuilder.ToString();
        }
        else
        {
           $newUri = $ConnectionUri;
        }

        if ($isCloudShell -eq $false)
        {
            Connect-EXOPSSession -ConnectionUri $newUri -AzureADAuthorizationEndpointUri $AzureADAuthorizationEndpointUri -UserPrincipalName $UserPrincipalName.Value -PSSessionOption $PSSessionOption -Credential $Credential.Value -BypassMailboxAnchoring:$BypassMailboxAnchoring
        }
        else
        {
            Connect-EXOPSSession -ConnectionUri $newUri -AzureADAuthorizationEndpointUri $AzureADAuthorizationEndpointUri -PSSessionOption $PSSessionOption -BypassMailboxAnchoring:$BypassMailboxAnchoring -Device:$Device.Value
        }
    }
}
# SIG # Begin signature block
# MIIjigYJKoZIhvcNAQcCoIIjezCCI3cCAQExDzANBglghkgBZQMEAgEFADB5Bgor
# BgEEAYI3AgEEoGswaTA0BgorBgEEAYI3AgEeMCYCAwEAAAQQH8w7YFlLCE63JNLG
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCBRI+yjnZSKrFUE
# 5TmTEWj4VWB02jeSAVdqXgOdYGwNraCCDYUwggYDMIID66ADAgECAhMzAAABUptA
# n1BWmXWIAAAAAAFSMA0GCSqGSIb3DQEBCwUAMH4xCzAJBgNVBAYTAlVTMRMwEQYD
# VQQIEwpXYXNoaW5ndG9uMRAwDgYDVQQHEwdSZWRtb25kMR4wHAYDVQQKExVNaWNy
# b3NvZnQgQ29ycG9yYXRpb24xKDAmBgNVBAMTH01pY3Jvc29mdCBDb2RlIFNpZ25p
# bmcgUENBIDIwMTEwHhcNMTkwNTAyMjEzNzQ2WhcNMjAwNTAyMjEzNzQ2WjB0MQsw
# CQYDVQQGEwJVUzETMBEGA1UECBMKV2FzaGluZ3RvbjEQMA4GA1UEBxMHUmVkbW9u
# ZDEeMBwGA1UEChMVTWljcm9zb2Z0IENvcnBvcmF0aW9uMR4wHAYDVQQDExVNaWNy
# b3NvZnQgQ29ycG9yYXRpb24wggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIB
# AQCxp4nT9qfu9O10iJyewYXHlN+WEh79Noor9nhM6enUNbCbhX9vS+8c/3eIVazS
# YnVBTqLzW7xWN1bCcItDbsEzKEE2BswSun7J9xCaLwcGHKFr+qWUlz7hh9RcmjYS
# kOGNybOfrgj3sm0DStoK8ljwEyUVeRfMHx9E/7Ca/OEq2cXBT3L0fVnlEkfal310
# EFCLDo2BrE35NGRjG+/nnZiqKqEh5lWNk33JV8/I0fIcUKrLEmUGrv0CgC7w2cjm
# bBhBIJ+0KzSnSWingXol/3iUdBBy4QQNH767kYGunJeY08RjHMIgjJCdAoEM+2mX
# v1phaV7j+M3dNzZ/cdsz3oDfAgMBAAGjggGCMIIBfjAfBgNVHSUEGDAWBgorBgEE
# AYI3TAgBBggrBgEFBQcDAzAdBgNVHQ4EFgQU3f8Aw1sW72WcJ2bo/QSYGzVrRYcw
# VAYDVR0RBE0wS6RJMEcxLTArBgNVBAsTJE1pY3Jvc29mdCBJcmVsYW5kIE9wZXJh
# dGlvbnMgTGltaXRlZDEWMBQGA1UEBRMNMjMwMDEyKzQ1NDEzNjAfBgNVHSMEGDAW
# gBRIbmTlUAXTgqoXNzcitW2oynUClTBUBgNVHR8ETTBLMEmgR6BFhkNodHRwOi8v
# d3d3Lm1pY3Jvc29mdC5jb20vcGtpb3BzL2NybC9NaWNDb2RTaWdQQ0EyMDExXzIw
# MTEtMDctMDguY3JsMGEGCCsGAQUFBwEBBFUwUzBRBggrBgEFBQcwAoZFaHR0cDov
# L3d3dy5taWNyb3NvZnQuY29tL3BraW9wcy9jZXJ0cy9NaWNDb2RTaWdQQ0EyMDEx
# XzIwMTEtMDctMDguY3J0MAwGA1UdEwEB/wQCMAAwDQYJKoZIhvcNAQELBQADggIB
# AJTwROaHvogXgixWjyjvLfiRgqI2QK8GoG23eqAgNjX7V/WdUWBbs0aIC3k49cd0
# zdq+JJImixcX6UOTpz2LZPFSh23l0/Mo35wG7JXUxgO0U+5drbQht5xoMl1n7/TQ
# 4iKcmAYSAPxTq5lFnoV2+fAeljVA7O43szjs7LR09D0wFHwzZco/iE8Hlakl23ZT
# 7FnB5AfU2hwfv87y3q3a5qFiugSykILpK0/vqnlEVB0KAdQVzYULQ/U4eFEjnis3
# Js9UrAvtIhIs26445Rj3UP6U4GgOjgQonlRA+mDlsh78wFSGbASIvK+fkONUhvj8
# B8ZHNn4TFfnct+a0ZueY4f6aRPxr8beNSUKn7QW/FQmn422bE7KfnqWncsH7vbNh
# G929prVHPsaa7J22i9wyHj7m0oATXJ+YjfyoEAtd5/NyIYaE4Uu0j1EhuYUo5VaJ
# JnMaTER0qX8+/YZRWrFN/heps41XNVjiAawpbAa0fUa3R9RNBjPiBnM0gvNPorM4
# dsV2VJ8GluIQOrJlOvuCrOYDGirGnadOmQ21wPBoGFCWpK56PxzliKsy5NNmAXcE
# x7Qb9vUjY1WlYtrdwOXTpxN4slzIht69BaZlLIjLVWwqIfuNrhHKNDM9K+v7vgrI
# bf7l5/665g0gjQCDCN6Q5sxuttTAEKtJeS/pkpI+DbZ/MIIHejCCBWKgAwIBAgIK
# YQ6Q0gAAAAAAAzANBgkqhkiG9w0BAQsFADCBiDELMAkGA1UEBhMCVVMxEzARBgNV
# BAgTCldhc2hpbmd0b24xEDAOBgNVBAcTB1JlZG1vbmQxHjAcBgNVBAoTFU1pY3Jv
# c29mdCBDb3Jwb3JhdGlvbjEyMDAGA1UEAxMpTWljcm9zb2Z0IFJvb3QgQ2VydGlm
# aWNhdGUgQXV0aG9yaXR5IDIwMTEwHhcNMTEwNzA4MjA1OTA5WhcNMjYwNzA4MjEw
# OTA5WjB+MQswCQYDVQQGEwJVUzETMBEGA1UECBMKV2FzaGluZ3RvbjEQMA4GA1UE
# BxMHUmVkbW9uZDEeMBwGA1UEChMVTWljcm9zb2Z0IENvcnBvcmF0aW9uMSgwJgYD
# VQQDEx9NaWNyb3NvZnQgQ29kZSBTaWduaW5nIFBDQSAyMDExMIICIjANBgkqhkiG
# 9w0BAQEFAAOCAg8AMIICCgKCAgEAq/D6chAcLq3YbqqCEE00uvK2WCGfQhsqa+la
# UKq4BjgaBEm6f8MMHt03a8YS2AvwOMKZBrDIOdUBFDFC04kNeWSHfpRgJGyvnkmc
# 6Whe0t+bU7IKLMOv2akrrnoJr9eWWcpgGgXpZnboMlImEi/nqwhQz7NEt13YxC4D
# dato88tt8zpcoRb0RrrgOGSsbmQ1eKagYw8t00CT+OPeBw3VXHmlSSnnDb6gE3e+
# lD3v++MrWhAfTVYoonpy4BI6t0le2O3tQ5GD2Xuye4Yb2T6xjF3oiU+EGvKhL1nk
# kDstrjNYxbc+/jLTswM9sbKvkjh+0p2ALPVOVpEhNSXDOW5kf1O6nA+tGSOEy/S6
# A4aN91/w0FK/jJSHvMAhdCVfGCi2zCcoOCWYOUo2z3yxkq4cI6epZuxhH2rhKEmd
# X4jiJV3TIUs+UsS1Vz8kA/DRelsv1SPjcF0PUUZ3s/gA4bysAoJf28AVs70b1FVL
# 5zmhD+kjSbwYuER8ReTBw3J64HLnJN+/RpnF78IcV9uDjexNSTCnq47f7Fufr/zd
# sGbiwZeBe+3W7UvnSSmnEyimp31ngOaKYnhfsi+E11ecXL93KCjx7W3DKI8sj0A3
# T8HhhUSJxAlMxdSlQy90lfdu+HggWCwTXWCVmj5PM4TasIgX3p5O9JawvEagbJjS
# 4NaIjAsCAwEAAaOCAe0wggHpMBAGCSsGAQQBgjcVAQQDAgEAMB0GA1UdDgQWBBRI
# bmTlUAXTgqoXNzcitW2oynUClTAZBgkrBgEEAYI3FAIEDB4KAFMAdQBiAEMAQTAL
# BgNVHQ8EBAMCAYYwDwYDVR0TAQH/BAUwAwEB/zAfBgNVHSMEGDAWgBRyLToCMZBD
# uRQFTuHqp8cx0SOJNDBaBgNVHR8EUzBRME+gTaBLhklodHRwOi8vY3JsLm1pY3Jv
# c29mdC5jb20vcGtpL2NybC9wcm9kdWN0cy9NaWNSb29DZXJBdXQyMDExXzIwMTFf
# MDNfMjIuY3JsMF4GCCsGAQUFBwEBBFIwUDBOBggrBgEFBQcwAoZCaHR0cDovL3d3
# dy5taWNyb3NvZnQuY29tL3BraS9jZXJ0cy9NaWNSb29DZXJBdXQyMDExXzIwMTFf
# MDNfMjIuY3J0MIGfBgNVHSAEgZcwgZQwgZEGCSsGAQQBgjcuAzCBgzA/BggrBgEF
# BQcCARYzaHR0cDovL3d3dy5taWNyb3NvZnQuY29tL3BraW9wcy9kb2NzL3ByaW1h
# cnljcHMuaHRtMEAGCCsGAQUFBwICMDQeMiAdAEwAZQBnAGEAbABfAHAAbwBsAGkA
# YwB5AF8AcwB0AGEAdABlAG0AZQBuAHQALiAdMA0GCSqGSIb3DQEBCwUAA4ICAQBn
# 8oalmOBUeRou09h0ZyKbC5YR4WOSmUKWfdJ5DJDBZV8uLD74w3LRbYP+vj/oCso7
# v0epo/Np22O/IjWll11lhJB9i0ZQVdgMknzSGksc8zxCi1LQsP1r4z4HLimb5j0b
# pdS1HXeUOeLpZMlEPXh6I/MTfaaQdION9MsmAkYqwooQu6SpBQyb7Wj6aC6VoCo/
# KmtYSWMfCWluWpiW5IP0wI/zRive/DvQvTXvbiWu5a8n7dDd8w6vmSiXmE0OPQvy
# CInWH8MyGOLwxS3OW560STkKxgrCxq2u5bLZ2xWIUUVYODJxJxp/sfQn+N4sOiBp
# mLJZiWhub6e3dMNABQamASooPoI/E01mC8CzTfXhj38cbxV9Rad25UAqZaPDXVJi
# hsMdYzaXht/a8/jyFqGaJ+HNpZfQ7l1jQeNbB5yHPgZ3BtEGsXUfFL5hYbXw3MYb
# BL7fQccOKO7eZS/sl/ahXJbYANahRr1Z85elCUtIEJmAH9AAKcWxm6U/RXceNcbS
# oqKfenoi+kiVH6v7RyOA9Z74v2u3S5fi63V4GuzqN5l5GEv/1rMjaHXmr/r8i+sL
# gOppO6/8MO0ETI7f33VtY5E90Z1WTk+/gFcioXgRMiF670EKsT/7qMykXcGhiJtX
# cVZOSEXAQsmbdlsKgEhr/Xmfwb1tbWrJUnMTDXpQzTGCFVswghVXAgEBMIGVMH4x
# CzAJBgNVBAYTAlVTMRMwEQYDVQQIEwpXYXNoaW5ndG9uMRAwDgYDVQQHEwdSZWRt
# b25kMR4wHAYDVQQKExVNaWNyb3NvZnQgQ29ycG9yYXRpb24xKDAmBgNVBAMTH01p
# Y3Jvc29mdCBDb2RlIFNpZ25pbmcgUENBIDIwMTECEzMAAAFSm0CfUFaZdYgAAAAA
# AVIwDQYJYIZIAWUDBAIBBQCgga4wGQYJKoZIhvcNAQkDMQwGCisGAQQBgjcCAQQw
# HAYKKwYBBAGCNwIBCzEOMAwGCisGAQQBgjcCARUwLwYJKoZIhvcNAQkEMSIEIPaa
# twplylgHHcsSWVZ4BMC4zNO4x5muZAWV7RU4glheMEIGCisGAQQBgjcCAQwxNDAy
# oBSAEgBNAGkAYwByAG8AcwBvAGYAdKEagBhodHRwOi8vd3d3Lm1pY3Jvc29mdC5j
# b20wDQYJKoZIhvcNAQEBBQAEggEADLrEDqTaImbgpdOAu7wWaMDHH3MCL67yVyi9
# JHsqmMANe9k3D3KsHfZ/e72CkBWNmBcnrUSNq3kNP5+qkIumuoT1vU9yax1it/Bk
# oq6vkVmghTGB34HiwT01oN5RlRQRyTEfYJyAjs5Dvr81O72Ce70QwGu9V6NIF8oD
# SaJf8/MPRgIoQ+bcgPyVsV7pgnSC2+2mE1+RqP+OdX5GYgdz9fa9uEaYvhyk1YJw
# zlkBsUjO/kFhQ0FX/q7sgOxhxLgGnc30CNzEBDgZkPcaf+PQGyAuH3uXvGdq50Zg
# KNUgrYaVKM7CwW+7ZLkjz4WOBovolyK0zSexhkdvnJfFqX4kLaGCEuUwghLhBgor
# BgEEAYI3AwMBMYIS0TCCEs0GCSqGSIb3DQEHAqCCEr4wghK6AgEDMQ8wDQYJYIZI
# AWUDBAIBBQAwggFRBgsqhkiG9w0BCRABBKCCAUAEggE8MIIBOAIBAQYKKwYBBAGE
# WQoDATAxMA0GCWCGSAFlAwQCAQUABCB6sLh3I4yZAQpeQiVfYFWAWF7lO2uzZ1vj
# hc0DKuxN/AIGXfvfvBW9GBMyMDIwMDEwNDA1NDEzNC4zOTZaMASAAgH0oIHQpIHN
# MIHKMQswCQYDVQQGEwJVUzETMBEGA1UECBMKV2FzaGluZ3RvbjEQMA4GA1UEBxMH
# UmVkbW9uZDEeMBwGA1UEChMVTWljcm9zb2Z0IENvcnBvcmF0aW9uMSUwIwYDVQQL
# ExxNaWNyb3NvZnQgQW1lcmljYSBPcGVyYXRpb25zMSYwJAYDVQQLEx1UaGFsZXMg
# VFNTIEVTTjoyMjY0LUUzM0UtNzgwQzElMCMGA1UEAxMcTWljcm9zb2Z0IFRpbWUt
# U3RhbXAgU2VydmljZaCCDjwwggTxMIID2aADAgECAhMzAAABGP4699kb1LEzAAAA
# AAEYMA0GCSqGSIb3DQEBCwUAMHwxCzAJBgNVBAYTAlVTMRMwEQYDVQQIEwpXYXNo
# aW5ndG9uMRAwDgYDVQQHEwdSZWRtb25kMR4wHAYDVQQKExVNaWNyb3NvZnQgQ29y
# cG9yYXRpb24xJjAkBgNVBAMTHU1pY3Jvc29mdCBUaW1lLVN0YW1wIFBDQSAyMDEw
# MB4XDTE5MTExMzIxNDAzNVoXDTIxMDIxMTIxNDAzNVowgcoxCzAJBgNVBAYTAlVT
# MRMwEQYDVQQIEwpXYXNoaW5ndG9uMRAwDgYDVQQHEwdSZWRtb25kMR4wHAYDVQQK
# ExVNaWNyb3NvZnQgQ29ycG9yYXRpb24xJTAjBgNVBAsTHE1pY3Jvc29mdCBBbWVy
# aWNhIE9wZXJhdGlvbnMxJjAkBgNVBAsTHVRoYWxlcyBUU1MgRVNOOjIyNjQtRTMz
# RS03ODBDMSUwIwYDVQQDExxNaWNyb3NvZnQgVGltZS1TdGFtcCBTZXJ2aWNlMIIB
# IjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAwvgDXBF/PzUY9beWJF2AdWRz
# 8UEsK4Tjn119XOWnrNLdoEyOjnh+J7XMKck70pO/vQQVaKk7x8H2w2Zm9eZ0PeKv
# lD3wamv/JtbXrP+hW7dQHlR8uActQFRYumItb1nd21UcmNkgHlaJyMxBRhrUL3kb
# 9mI+o2whxNvsT90PgHIMcHhPJev5wDeUv5kwyldn5RzUIPneV/UkjezHSwuTgCYE
# st++CIvwJ2BCsiIJzhSVZCMZCw8Tsq51f4DkZaGsclRpQ3ppywTWocLMZ5pK6QoX
# MLw4ngMeIP2dXydPgvsHQPhLQO664J0ZI4Sh31pGY+NG5seBqUHSZhdcwGdBcQID
# AQABo4IBGzCCARcwHQYDVR0OBBYEFPFb5bAuD2AJ2DlP9OYj6/i0xyg+MB8GA1Ud
# IwQYMBaAFNVjOlyKMZDzQ3t8RhvFM2hahW1VMFYGA1UdHwRPME0wS6BJoEeGRWh0
# dHA6Ly9jcmwubWljcm9zb2Z0LmNvbS9wa2kvY3JsL3Byb2R1Y3RzL01pY1RpbVN0
# YVBDQV8yMDEwLTA3LTAxLmNybDBaBggrBgEFBQcBAQROMEwwSgYIKwYBBQUHMAKG
# Pmh0dHA6Ly93d3cubWljcm9zb2Z0LmNvbS9wa2kvY2VydHMvTWljVGltU3RhUENB
# XzIwMTAtMDctMDEuY3J0MAwGA1UdEwEB/wQCMAAwEwYDVR0lBAwwCgYIKwYBBQUH
# AwgwDQYJKoZIhvcNAQELBQADggEBAHMlnb4OnILP/wJsaEGZvlgEqSc1FxD4TKd9
# G1nOR8gsEAfjGumD53EqBXXLf+VdSuKf6zHDCwZ+S8xC1R/rs7YOhESuPGLWyW/Q
# OyafnyWY+5aF2j/ZlT+7SbNrRrrm3F6Rm4KORxgo5+4MzAR2OOUPC0nH2tSRUBAI
# ktoAiikZayjLBmiG4vlLgbbG0PCZJ75ohMAgsEpkU19L4gGbrJuJiVaigXtwZo/s
# gQyVVnL9DMqxGEO+KGtFUltyQXPsUq6k9iYJtgnOiJUm5vALIlRP1XOMmoX5i3nh
# R303KytH5bulRs439RjQNUg10eG1Ip6wZYt5X4cLSoceseXkbEowggZxMIIEWaAD
# AgECAgphCYEqAAAAAAACMA0GCSqGSIb3DQEBCwUAMIGIMQswCQYDVQQGEwJVUzET
# MBEGA1UECBMKV2FzaGluZ3RvbjEQMA4GA1UEBxMHUmVkbW9uZDEeMBwGA1UEChMV
# TWljcm9zb2Z0IENvcnBvcmF0aW9uMTIwMAYDVQQDEylNaWNyb3NvZnQgUm9vdCBD
# ZXJ0aWZpY2F0ZSBBdXRob3JpdHkgMjAxMDAeFw0xMDA3MDEyMTM2NTVaFw0yNTA3
# MDEyMTQ2NTVaMHwxCzAJBgNVBAYTAlVTMRMwEQYDVQQIEwpXYXNoaW5ndG9uMRAw
# DgYDVQQHEwdSZWRtb25kMR4wHAYDVQQKExVNaWNyb3NvZnQgQ29ycG9yYXRpb24x
# JjAkBgNVBAMTHU1pY3Jvc29mdCBUaW1lLVN0YW1wIFBDQSAyMDEwMIIBIjANBgkq
# hkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAqR0NvHcRijog7PwTl/X6f2mUa3RUENWl
# CgCChfvtfGhLLF/Fw+Vhwna3PmYrW/AVUycEMR9BGxqVHc4JE458YTBZsTBED/Fg
# iIRUQwzXTbg4CLNC3ZOs1nMwVyaCo0UN0Or1R4HNvyRgMlhgRvJYR4YyhB50YWeR
# X4FUsc+TTJLBxKZd0WETbijGGvmGgLvfYfxGwScdJGcSchohiq9LZIlQYrFd/Xcf
# PfBXday9ikJNQFHRD5wGPmd/9WbAA5ZEfu/QS/1u5ZrKsajyeioKMfDaTgaRtogI
# Neh4HLDpmc085y9Euqf03GS9pAHBIAmTeM38vMDJRF1eFpwBBU8iTQIDAQABo4IB
# 5jCCAeIwEAYJKwYBBAGCNxUBBAMCAQAwHQYDVR0OBBYEFNVjOlyKMZDzQ3t8RhvF
# M2hahW1VMBkGCSsGAQQBgjcUAgQMHgoAUwB1AGIAQwBBMAsGA1UdDwQEAwIBhjAP
# BgNVHRMBAf8EBTADAQH/MB8GA1UdIwQYMBaAFNX2VsuP6KJcYmjRPZSQW9fOmhjE
# MFYGA1UdHwRPME0wS6BJoEeGRWh0dHA6Ly9jcmwubWljcm9zb2Z0LmNvbS9wa2kv
# Y3JsL3Byb2R1Y3RzL01pY1Jvb0NlckF1dF8yMDEwLTA2LTIzLmNybDBaBggrBgEF
# BQcBAQROMEwwSgYIKwYBBQUHMAKGPmh0dHA6Ly93d3cubWljcm9zb2Z0LmNvbS9w
# a2kvY2VydHMvTWljUm9vQ2VyQXV0XzIwMTAtMDYtMjMuY3J0MIGgBgNVHSABAf8E
# gZUwgZIwgY8GCSsGAQQBgjcuAzCBgTA9BggrBgEFBQcCARYxaHR0cDovL3d3dy5t
# aWNyb3NvZnQuY29tL1BLSS9kb2NzL0NQUy9kZWZhdWx0Lmh0bTBABggrBgEFBQcC
# AjA0HjIgHQBMAGUAZwBhAGwAXwBQAG8AbABpAGMAeQBfAFMAdABhAHQAZQBtAGUA
# bgB0AC4gHTANBgkqhkiG9w0BAQsFAAOCAgEAB+aIUQ3ixuCYP4FxAz2do6Ehb7Pr
# psz1Mb7PBeKp/vpXbRkws8LFZslq3/Xn8Hi9x6ieJeP5vO1rVFcIK1GCRBL7uVOM
# zPRgEop2zEBAQZvcXBf/XPleFzWYJFZLdO9CEMivv3/Gf/I3fVo/HPKZeUqRUgCv
# OA8X9S95gWXZqbVr5MfO9sp6AG9LMEQkIjzP7QOllo9ZKby2/QThcJ8ySif9Va8v
# /rbljjO7Yl+a21dA6fHOmWaQjP9qYn/dxUoLkSbiOewZSnFjnXshbcOco6I8+n99
# lmqQeKZt0uGc+R38ONiU9MalCpaGpL2eGq4EQoO4tYCbIjggtSXlZOz39L9+Y1kl
# D3ouOVd2onGqBooPiRa6YacRy5rYDkeagMXQzafQ732D8OE7cQnfXXSYIghh2rBQ
# Hm+98eEA3+cxB6STOvdlR3jo+KhIq/fecn5ha293qYHLpwmsObvsxsvYgrRyzR30
# uIUBHoD7G4kqVDmyW9rIDVWZeodzOwjmmC3qjeAzLhIp9cAvVCch98isTtoouLGp
# 25ayp0Kiyc8ZQU3ghvkqmqMRZjDTu3QyS99je/WZii8bxyGvWbWu3EQ8l1Bx16HS
# xVXjad5XwdHeMMD9zOZN+w2/XU/pnR4ZOC+8z1gFLu8NoFA12u8JJxzVs341Hgi6
# 2jbb01+P3nSISRKhggLOMIICNwIBATCB+KGB0KSBzTCByjELMAkGA1UEBhMCVVMx
# EzARBgNVBAgTCldhc2hpbmd0b24xEDAOBgNVBAcTB1JlZG1vbmQxHjAcBgNVBAoT
# FU1pY3Jvc29mdCBDb3Jwb3JhdGlvbjElMCMGA1UECxMcTWljcm9zb2Z0IEFtZXJp
# Y2EgT3BlcmF0aW9uczEmMCQGA1UECxMdVGhhbGVzIFRTUyBFU046MjI2NC1FMzNF
# LTc4MEMxJTAjBgNVBAMTHE1pY3Jvc29mdCBUaW1lLVN0YW1wIFNlcnZpY2WiIwoB
# ATAHBgUrDgMCGgMVAM3Xm9cgL2tpCSdphXw3XknxSTHcoIGDMIGApH4wfDELMAkG
# A1UEBhMCVVMxEzARBgNVBAgTCldhc2hpbmd0b24xEDAOBgNVBAcTB1JlZG1vbmQx
# HjAcBgNVBAoTFU1pY3Jvc29mdCBDb3Jwb3JhdGlvbjEmMCQGA1UEAxMdTWljcm9z
# b2Z0IFRpbWUtU3RhbXAgUENBIDIwMTAwDQYJKoZIhvcNAQEFBQACBQDhuiSZMCIY
# DzIwMjAwMTA0MDQzNzQ1WhgPMjAyMDAxMDUwNDM3NDVaMHcwPQYKKwYBBAGEWQoE
# ATEvMC0wCgIFAOG6JJkCAQAwCgIBAAICBtMCAf8wBwIBAAICEZIwCgIFAOG7dhkC
# AQAwNgYKKwYBBAGEWQoEAjEoMCYwDAYKKwYBBAGEWQoDAqAKMAgCAQACAwehIKEK
# MAgCAQACAwGGoDANBgkqhkiG9w0BAQUFAAOBgQCnb9DkD+O4VTIevVh32vDDGE2B
# 9mWeNT1fQiL78F0JazOww+tQI4/V6nz/etgaMn3WXLdVQryJNeU97UWf3rmBCDWr
# qyGEJ3EKIUeRLUBC+N6TLaU6miCDD08TSvL21CtplSwBoq8lFhUEHzFZXTqs9fDZ
# CLWtAW5PJUCiMK9fhTGCAw0wggMJAgEBMIGTMHwxCzAJBgNVBAYTAlVTMRMwEQYD
# VQQIEwpXYXNoaW5ndG9uMRAwDgYDVQQHEwdSZWRtb25kMR4wHAYDVQQKExVNaWNy
# b3NvZnQgQ29ycG9yYXRpb24xJjAkBgNVBAMTHU1pY3Jvc29mdCBUaW1lLVN0YW1w
# IFBDQSAyMDEwAhMzAAABGP4699kb1LEzAAAAAAEYMA0GCWCGSAFlAwQCAQUAoIIB
# SjAaBgkqhkiG9w0BCQMxDQYLKoZIhvcNAQkQAQQwLwYJKoZIhvcNAQkEMSIEIAkf
# 7T6/gMu1/JEAgjvQjCABTcq1kyHnWgjgChKGL6OwMIH6BgsqhkiG9w0BCRACLzGB
# 6jCB5zCB5DCBvQQgoM8HFJuqUgOPAFUvvZuWfpOnBx+1sjY7z4pdKDINB/cwgZgw
# gYCkfjB8MQswCQYDVQQGEwJVUzETMBEGA1UECBMKV2FzaGluZ3RvbjEQMA4GA1UE
# BxMHUmVkbW9uZDEeMBwGA1UEChMVTWljcm9zb2Z0IENvcnBvcmF0aW9uMSYwJAYD
# VQQDEx1NaWNyb3NvZnQgVGltZS1TdGFtcCBQQ0EgMjAxMAITMwAAARj+OvfZG9Sx
# MwAAAAABGDAiBCAL4ins/C/ba40BUOrWVV5qyEBpTLv1NYfIj5JptEem7jANBgkq
# hkiG9w0BAQsFAASCAQC7zASl6PD9iUgYyBkChVAcpqN5OQVJqMnhmQp5DdCkGrvk
# pu4hCbdaoj2jf2h06DfnQmIMI4NyIgrduuFdjQ5RM/94DPig9jqeFd2MfvdyqxYa
# MBE/AZfd/CM945suDVtEF5zZYWtz+8QfZr0GdERJZJPzMhaalWMk4PE4uJtNGgHE
# 17UxDqpXRrkw2IHfwr8Wj7a4SC2/Pa6eOkH7YHRTEj3iOXd+m1PROJk0qtptasNE
# ING3+ZKG1CDXaCbrKii5fYKkdQj9DZRpSI2cHFEe55LyIXoBEqqWSosbkXQgqLd1
# 4e3fBqVhYGfjzxeOA01QZ+XuGCaGWzJubLMo/+jJ
# SIG # End signature block
