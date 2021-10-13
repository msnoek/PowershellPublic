function HV-Create-VM {
    param ($Creds, $VMConfig, $NumberVM, $ClusterVars, $NodeMembers)

    #We've created various credentials in an Azure KeyVault using the technique found https://toastit.dev/2020/05/22/azure-key-vault-1/ and https://github.com/Azure/azure-powershell/issues/10434, and are pulling them with the same mentioned methods
    #NOTE: If you need to change the password in the vault, you will have to use the methods above, not just change it from the Azure UI.    
    #This credential part should maybe be split out into another function?
    $VaultName = "Infra-Automation"
    $Subscription = "Infrastructure"
    $VaultUserName = "TemplateAdmin"
    $TemplateVM = "2019-Template-Base"
    
    #Manually enter the password for the Azure SPN account here
    #This part can be skipped if you are not using Azure KeyVault to store domain/local credentials for the rest of the script
    Write-Host "`nEnter the password for the Azure svcInfraAutomateSPN service account. This can be found in PasswordState" -ForegroundColor Green
    $AzureCreds = Get-Credential -UserName guid-of-Azure-SPN-here -Message "Azure SPN" #Username is the GUID of the SPN/Application, as an SPN login takes GUID, not Name

    Write-Host "Connecting to Azure" -Foregroundcolor Yellow
    Connect-AZAccount -Credential $AzureCreds -Tenant "azure-tenant-guid-here" -SubscriptionID "Azure-Subscription-Here" -ServicePrincipal #Using an SPN account for this, as our Azure accounts have MFA, which means the -Credential won't work

    Write-Host "`nGathering needed credentials from Azure KeyVault" -Foregroundcolor Yellow
    $LocalAdminCred = New-Object System.Management.Automation.PSCredential (
    ((Get-AzKeyVaultSecret -VaultName $VaultName -Name $VaultUserName).SecretValueText -Split "`v")[0],
    (ConvertTo-SecureString ((Get-AzKeyVaultSecret -VaultName $VaultName -Name $VaultUserName).SecretValueText -Split "`v")[1] -AsPlainText -Force)
    )
    
    foreach ($VM in $NumberVM){
        $Date = Get-Date
        $RAMHash = $null #Creates a hash table to populate with the members of the clusters with their free RAM
        $RAMHash = @{}
        $NodeMembers | ForEach { #Checks each member of the cluster and gets the amount of free RAM. This will then be used to determine what host to put the new VM on 
            $FreeMem = Invoke-Command -ComputerName $_ -Credential $Creds -ScriptBlock {Get-WMIObject Win32_Operatingsystem | Select-Object -ExpandProperty FreePhysicalMemory}
                $RamHash.add($_, $FreeMem)
        }#End NodeMembers ForEach
        $HighestRam = $RAMHash.GetEnumerator() | Sort-Object -Property Value -Descending | Select-Object -First 1
        $HostTarget = $HighestRAM.Name + "." + $ClusterVars.Domain
    
        #Converts the VMConfig RAM property to bytes. Normally powershell would translate (example) 4GB as the bytes by default if the variable was created with quotes, but since we're pulling it from the
        #JSON file it's automatically quoted out. So we do a workaround found here: https://stackoverflow.com/questions/52186448/unusual-variable-type-mismatches
        $VMConfig.$VM.RAM = $VMConfig.$VM.RAM / 1

        $VMFolderPath = $ClusterVars.CSVPath + "\" + $VMConfig.$VM.VMName
        
        $HostSession = New-PSSession -ComputerName $HostTarget -Credential $Creds -Authentication Credssp

        Invoke-Command -Session $HostSession -ArgumentList $VM, $ClusterVars, $VMConfig, $VMFolderPath, $HostTarget -ScriptBlock  {
            param($VM, $ClusterVars, $VMConfig, $VMFolderPath, $HostTarget)
            Write-Host "`nCreating directory" $VMConfig.$VM.VMName -ForegroundColor Yellow
            New-Item -Path $ClusterVars.CSVPath -Name $VMConfig.$VM.VMName -ItemType "directory"

            Write-Host "`nCreating directory Virtual Hard Disks" -ForegroundColor Yellow
            New-Item -Path ($ClusterVars.CSVPath + "\" + $VMConfig.$VM.VMName) -Name "Virtual Hard Disks" -ItemType "directory"

            Write-Host "`nCopying template VHDX from "$ClusterVars.TemplatePath" TO" ("$VMFolderPath" + "\" + "Virtual Hard Disks" + "\" + $VMConfig.$VM.VMName + ".vhdx")". Please be patient, it will take around 10 minutes per VM." -ForegroundColor Yellow
            $VHDFullPath = ("$VMFolderPath" + "\" + "Virtual Hard Disks" + "\" + $VMConfig.$VM.VMName + ".vhdx")
            Copy-Item -Path $ClusterVars.TemplatePath -Destination ("$VMFolderPath" + "\" + "Virtual Hard Disks" + "\" + $VMConfig.$VM.VMName + ".vhdx")

            Write-Host "Creating virtual machine "$VMConfig.$VM.VMName"" -ForegroundColor Yellow
            New-VM -Name $VMConfig.$VM.VMName -ComputerName $HostTarget -BootDevice VHD -VHDPath "$VHDFullPath" -MemoryStartupBytes $VMConfig.$VM.RAM -Path $Clustervars.CSVPath -Generation 2 -Switch $ClusterVars.Switch

            Write-Host "`nAdding VM to VLAN "$VMConfig.$VM.VLAN"." -Foregroundcolor Yellow
            Set-VMNetworkAdapterVlan -VMName $VMConfig.$VM.VMName -Access -VLANID $VMConfig.$VM.VLAN

            Write-Host "`nConfiguring virtual machine "$VMConfig.$VM.VMName"" -ForegroundColor Yellow
            Set-VM -Name $VMConfig.$VM.VMName -ComputerName $HostTarget -ProcessorCount $VMConfig.$VM.CPU -AutomaticStartAction StartIfRunning -Notes ($VMConfig.$VM.VMName + "`nVM created by HyperV-New-VM script on $Date")
            Start-VM -Name $VMConfig.$VM.VMName
            Write-Host "Adding VM to cluster "$ClusterVars.ClusterName"." -ForegroundColor Yellow
            Add-ClusterVirtualMachineRole -VMName $VMConfig.$VM.VMName -Cluster $ClusterVars.ClusterName
            
            Write-Host "`nAdding some notes to the VM" -Foregroundcolor Yellow
            $Notes = "VM created by script on $Date, ticket number " + $VMConfig.$VM.Ticket
            Set-VM -Name $VMConfig.$VM.VMName -Notes $Notes

            Write-Host "`nSleeping for 5 minutes to allow new VM to go through OOBE and boot" -Foregroundcolor Yellow
            Start-Sleep -Seconds 300            

        }#End Hyper-V Host Invoke-Command

        #Another invoke to get the IP address of the newly created server from the hyper-v host
        $IP = Invoke-Command -Session $HostSession -ArgumentList $VM, $VMConfig -ScriptBlock {
            param($VM, $VMConfig)
            (Get-VM -Name $VMConfig.$VM.VMName | Select -ExpandProperty NetworkAdapters).IPAddresses[0] #the NetworkAdapters property will generally have both an IPv4 and IPv6 address, we only want the IPv4, so we're only selecting the first object in the property array
            }#End IP address invoke command

        #This one doesn't like using credssp
        #Using the IP address instead of the template VM name because DNS might not catch up quickly enough to update the new IP address of the VM
        #We're using this separate invoke command to the VM to join the domain rather than putting it in the runonce powershell script located on the machine itself so that we don't have credentials put in plaintext
        Write-Host "`nEstablishing new Powershell session to VM" -ForegroundColor Yellow
        $VMSession = New-PSSession -Computername $IP -Credential $LocalAdminCred 

        Write-Host "`nRenaming VM and joining to domain" -ForegroundColor Yellow
        Invoke-Command -Session $VMSession -ArgumentList $VM, $VMConfig, $Creds -ScriptBlock {
            param($VM, $VMConfig, $Creds)
            Add-Computer -DomainName $VMConfig.$VM.Domain -Credential $Creds -NewName $VMConfig.$VM.VMName -OUPath $VMConfig.$VM.OU -Restart

        }#End VM Invoke-Command
    
    }#End VM ForEach
}#End Function

