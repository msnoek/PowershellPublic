#this script has been sanitized to remove references to actual addresses and security agents used in production.

param (
    [Parameter (Mandatory = $false)]
    [object] $WebHookData
)
#Webhook address "redacted"
#Webhook is good until date redacted

Disable-AzContextAutosave –Scope Process #this prevents some issues with rapid subscription switching

#Establish connection to Azure
$connection = Get-AutomationConnection -Name AzureRunAsConnection 

#Checks Azure connection, makes sure we're actually connected. Could be improved by adding an Exit command with a failure message if the connection fails
while(!($connectionResult) -and ($logonAttempt -le 10))
{
    $LogonAttempt++
    # Logging in to Azure...
    $connectionResult = Connect-AzAccount `
                            -ServicePrincipal `
                            -Tenant $connection.TenantID `
                            -ApplicationId $connection.ApplicationID `
                            -CertificateThumbprint $connection.CertificateThumbprint

    Start-Sleep -Seconds 30
}

#Creates a script block that we will use to create a temporary installer ps1 script that will get deleted after run. We do this because we need the installer script to be "local" in order to use invoke-azvmruncommand
#We can't use Custom Script Extension to push the install because a VM can only have one Custom Script Extension associated with it at once, and Security team has their own extension they push out that would overwrite an agent install extension

$functionscriptblock = {
    #Function to check if the agent is installed already. We're using a generalized function with the parameter "$Software" so that we can re-use it elsewhere.
    function Check-Install {
        param (
            [Parameter(Mandatory)]
            [string]$Software
        )

	    $installed = (Get-ItemProperty HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\* | Where { $_.DisplayName -eq $Software }) -ne $null

	    If(-Not $installed) {
	     return $false 
	    } else {
	    return $true 
	    }
    }
    #Function to install security agent
    function Install-Agent01 {
        #Forces Windows to use TLS1, 1.1, and 1.2 to connect and download software installer. Depending on the webhost, this may need to be adjusted to only 1.2
        [System.Net.ServicePointManager]::CertificatePolicy = New-Object TrustAllCertsPolicy
        [Net.ServicePointManager]::SecurityProtocol = "Tls, Tls11, Tls12"

        $TempFolder = $env:TEMP #Gets the temp folder from the local environment variable
        $Installer = "$TempFolder\Agent01-Installer.exe"
        Invoke-WebRequest -uri 'https://address.of.webhost/Agent01/Agent01-Installer.exe' -OutFile $Installer #Downloads the installer file. Invoke-WebRequest works fine on the Azure runbook workers, but if you need to repurpose this on a machine that has an older version of powershell, you would need to use the (new-object System.Net.WebClient).DownloadFile method
        Invoke-Expression "$Installer /install /quiet /norestart CID=redacted VDI=1" #Runs install
        Start-Sleep -Seconds 300
    }

    $Software = "Agent01 Registry Name"
    $Installed = Check-Install -Software $Software #runs the check-install function to see if the software is already installed
    if($Installed -eq $true) {
        write-output "$($Software) already installed.  Exiting."
    }
    else {
        write-host "$($Software) missing.  Installing."
        Install-Agent01 #Runs the security agent installer if it is not installed already
        $Installed = Check-Install -Software $Software #Check to make sure installed successfully
        if($Installed -eq $true) {
            write-output "$Software successfully installed on server $VMName."
        }
        else {
            write-output "Failed to install $Software on server $VMName."
        }
    }
}#end script block

<#Test section. Uncomment this and comment out the other $functionscriptblock to test.
$functionscriptblock = {
    $TempFolder = $env:TEMP
    Write-Output "This is a test" | Out-File "$TempFolder\test.txt"
}
#>

#Gets the path that the runbook is running in on the Azure runbook worker and uses that path for "local" storage of the script we want to push to the VM
$TempPath = Get-Location | Select-Object -ExpandProperty Path
$TempPS1 = "$TempPath\Temp-Push-Install.ps1"

$functionscriptblock | Out-File $TempPS1 #Takes our functionscriptblock from above and makes a powershell script out of it

Write-Output "Temporary installer script created at $TempPS1"

#Takes the Webhook data and pulls the relevant information from it to run the agent install script against
if ($WebHookData -eq $null){
    Write-Output 'No data received'
}
else{
    $VMList = ConvertFrom-Json -InputObject $WebHookData.RequestBody
    $jobs = @() #Creates a jobs array to store the -asjob information of the invoke-azvmruncommands

#This would be much better run as a parallel job, but the Powershell Core that Azure uses can't handle it yet.
#Runs ForEach against each VM in the list pulled from the webhook data and pushes an agent install via Invoke-AzVMRunCommand. Using the invoke command rather than a custom extension script because only one custom extension can be present on a VM at a time
    ForEach ($VM in $VMList){
        $VMName = $VM.Name
        $Subscription = $VM.subscription
        $ResourceGroupName = $VM.ResourceGroup
        $OSType = $VM.OS
        $Lifespan = $VM.tags.Lifespan #Note, the "Lifespan" property of the VM object is case sensitive. Not quite sure why.

        $context = Set-AZContext -Subscription $Subscription

        if ($VM.Power -ne "VM running") #Makes sure the VM is running. Note: This is not a reflection of VM run state AT THE TIME OF SCRIPT RUN, but rather at the time that the data in the webhook was collected.
        {
            Write-Output "Virtual Machine $VMName (Sub: $Subscription RG: $ResourceGroupName) is not powered on. Skipping."
            Continue
        }
        if ( ( ($lifespan -eq "days") -or  ($lifespan -eq "hours")) -eq $true) #Checks if the VM has a lifespan of years, rather than days or hours. Don't want to install on an ephemeral machine.
        {
            Write-Output "Virtual Machine $VMName (Sub: $Subscription RG: $ResourceGroupName) is ephemeral. Lifespan = $lifespan.  Skipping."
            Continue
        }
        if ($OSType -eq "Linux") { #checks to see if the VM is Linux, and sends a failure message if it is. This part can easily be repurposed to run a bash script to install on Linux, just haven't written it yet
            Write-Output "$VMName is a Linux machine. Skipping"

        }
        if ($OSType -eq "Windows"){ #Invokes the Windows install script if VM is Windows
            Write-Output "Running Invoke-AzVMRunCommand to install the Security Agent on Windows Azure VM $VMName in Resource Group $ResourceGroupName"
            #Runs the Invoke-AzVMRunCommand and adds it to the $Jobs array
            $JobObject = [PSCustomObject]@{
                Name                = $VMName
                ResourceGroupName   = $ResourceGroupName
                JobID               = (Invoke-AzVMRunCommand -ResourceGroupName $ResourceGroupName -VMName $VMName -CommandId 'RunPowerShellScript' -ScriptPath $TempWindowsScript -AsJob)
            }
            #Invoke-AzVMRunCommand -ResourceGroupName $ResourceGroupName -VMName $VMName -CommandId 'RunPowerShellScript' -ScriptPath $TempWindowsScript -AsJob
            $Jobs += $JobObject
        }
    }
}

Start-Sleep 900 #Sleep for 15 minutes to allow jobs to process

#Runs the invoke-azvmruncommand commands that against all the VMs that have been gathered above.
ForEach ($Job in $Jobs) {
    $CheckJob = Get-Job $Job.JobID
    Write-Output "Invoke-AzVMRunCommand results for VM $($Job.Name) in Resource Group $($Job.ResourceGroupName): $Checkjob"
}

Write-Output "Removing temporary installer script $TempPS1"
Remove-Item $TempPS1

<#
WEBHOOK PORTION
This is how the webhook with a list of VMs to run the installer against is created on a local machine.
This could be fairly easily repurposed to be automatically run on the creation of a new VM, or regularly scheduled to get a list of all Azure VMs
$uri = "https://redacted"
$import = import-csv "path to csv"
$body = convertto-json @($import) #<- the @() forces the convertto-json to bring it in as an array 
$header = @{ message = "Agent01-Installer Webhook"}
Invoke-RestMethod -Method post -Uri $uri -Body $body -Headers $header

#>

<#
#List of machines can be pulled from Azure using something similar to the following:
$vmlist = @()
Foreach ($sub in $subscriptionlist){
    Set-AZContext -Subscription $sub
    $vms = get-azvm -status
    ForEach ($vm in $vms){
        Write-Host "Gathering info for virtual machine $($vm.name)"
        $VMNicIP = "No IP"
        if ($vm.PowerState -eq "VM Running"){
            $VMNicIP = (Get-AzNetworkInterface -ResourceId $vm.NetworkProfile.NetworkInterfaces[0].Id).IpConfigurations[0].PrivateIPAddress
        }
        $vminfo = $vm | select-object Name,@{Name="OSType"; Expression={$_.StorageProfile.OSDisk.OSType}}, Location, ResourceGroupName, @{Name="Subscription"; Expression={$_.Id.split('/')[2]}}, PowerState
        $vmwithip = [PSCustomObject]@{
            Name            = $vminfo.Name
            OS              = $vminfo.OSType
            Location        = $vminfo.Location
            ResourceGroup   = $vminfo.ResourceGroupName
            Subscription    = $vminfo.Subscription
            Power           = $vminfo.PowerState
            IP              = $VMNicIP
        }
        $vmlist += $vmwithip
    }
}

$vmlist | Export-csv csv-file-here.csv
#>
