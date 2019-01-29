#Script to pull netstat info from all VMs on a cluster
#By Matthew Snoek, matthew.snoek at gmail.com

$ErrorActionPreference = "silentlycontinue"
Function Merge-CSVFiles
{
Param(
$CSVPath = "C:\CSV", ## Soruce CSV Folder
$XLOutput="c:\temp.xlsx" ## Output file name
)

$csvFiles = Get-ChildItem ("$CSVPath\*") -Include *.csv
$Excel = New-Object -ComObject excel.application 
$Excel.visible = $false
$Excel.sheetsInNewWorkbook = $csvFiles.Count
$workbooks = $excel.Workbooks.Add()
$CSVSheet = 1

Foreach ($CSV in $Csvfiles)

{
$worksheets = $workbooks.worksheets
$CSVFullPath = $CSV.FullName
$SheetName = ($CSV.name -split "\.")[0]
$worksheet = $worksheets.Item($CSVSheet)
$worksheet.Name = $SheetName
$TxtConnector = ("TEXT;" + $CSVFullPath)
$CellRef = $worksheet.Range("A1")
$Connector = $worksheet.QueryTables.add($TxtConnector,$CellRef)
$worksheet.QueryTables.item($Connector.name).TextFileCommaDelimiter = $True
$worksheet.QueryTables.item($Connector.name).TextFileParseType  = 1
$worksheet.QueryTables.item($Connector.name).Refresh()
$worksheet.QueryTables.item($Connector.name).delete()
$worksheet.UsedRange.EntireColumn.AutoFit()
$CSVSheet++

}

$workbooks.SaveAs($XLOutput,51)
$workbooks.Saved = $true
$workbooks.Close()
[System.Runtime.Interopservices.Marshal]::ReleaseComObject($workbooks) | Out-Null
$excel.Quit()
[System.Runtime.Interopservices.Marshal]::ReleaseComObject($excel) | Out-Null
[System.GC]::Collect()
[System.GC]::WaitForPendingFinalizers()

}


#Gets credentials for running against the various domains. Might want to adjust this to a service account?
$Cluster = Read-Host "Enter the non-FQDN of the cluster to check against."
$OutputLoc = Read-Host "Enter the output location, no trailing \"
$PRIMARYCreds = Get-Credential PRIMARYDOMAIN\username
$DEVCreds = Get-Credential DEVDOMAIN\username
$COLOCreds = Get-Credential COLODOMAIN\username
$Data = ""
$Date = Get-Date -Format FileDate
$ErrorCheck = "True" #using ErrorCheck variable instead of the built-in $? because I was experimenting with sleep commands before an error check if statement, and the successful sleep command would clear the default error check variable

#Gets a list of VMs running on the cluster. Currently need to adjust this for each cluster
Write-Host "Getting list of virtual machines running in cluster $Cluster." -ForegroundColor Cyan
$VMList = get-clusterresource -cluster "$Cluster.FQDNdomainsuffix" | where ResourceType -eq "Virtual Machine" | Select -expandproperty OwnerGroup | Select -expandproperty Name
$VMList > "$OutputLoc\VMList.txt"
 
ForEach ($VM in $VMList)#Loops through each VM in the list of VMs in the cluster
{
#Uses Get-WMIObject to get the domain of the computer prior to actually authenticating to the computer, Get-CIMInstance can also work, but requires different target machine naming, FQDN vs NETBIOS
Write-Host "Checking Domain for Virtual Machine $VM" -ForegroundColor Cyan
$Domain = Get-WMIObject -Class Win32_ComputerSystem -ComputerName $VM | Select -ExpandProperty Domain
$ErrorCheck = $?
if ($ErrorCheck -ne "True")#Checks the error status of the last command, since the various Dev machines will throw an error and not return a domain
	{
	#Start-Job starts a background job under Dev domain credentials, Receive-Job pulls that job result
	#Haven't yet figured out a way to do it in the foreground under different creds
	#Invoke-Command will only work on a remote computer
	Write-Host "Initial Domain check failed, assuming either DEV domain or mismatched name between VM and OS, running Start-Job cmdlet on $VM to get Domain. This background command will fail if names are mismatched." -ForegroundColor Yellow
    $DevScriptBlock = [scriptblock]::Create("Get-WMIObject -Class Win32_ComputerSystem -ComputerName $vm.FQDNDEVdomainsuffix")	
    Start-Job -Name "$VM-dev" -Credential $DEVCreds -ScriptBlock $DevScriptBlock  #Have to use the Create script block here because the normal script block won't expand variables
	Write-Host "Running Receive-Job on $VM with DEV creds" -ForegroundColor Yellow
    $Domain = Receive-Job "$VM-Dev" | Select -ExpandProperty Domain
    #Checks to see if the job failed, likely indicating that the machine is either offline or there is a mismatch between the VM and OS names
	#If failed, appends an error message to a log file
	$ErrorCheck = $?
	if ($ErrorCheck -ne "True")
		{
		Write-Host "$VM failed Receive-Job with DEV credentials, attempting COLO creds." -ForegroundColor Red
        Write-Output "$VM failed Receive-Job with DEV credentials, attempting with COLO creds.." >> "$OutputLoc\_ERRORLOG.txt"
        $ColoScriptBlock = [scriptblock]::Create("Get-WMIObject -Class Win32_ComputerSystem -ComputerName $vm.FQDNCOLOdomainsuffix") #Have to use the Create script block here because the normal script block won't expand variables
        Start-Job -Name "$VM-Colo" -Credential $COLOCreds -ScriptBlock $ColoScriptBlock
		Write-Host "Running Receive-Job on $VM with COLO creds" -ForegroundColor Yellow
        $Domain = Receive-Job "$VM-Colo" | Select -ExpandProperty Domain
        #Checks to see if the job failed, likely indicating that the machine is either offline or there is a mismatch between the VM and OS names
	    #If failed, appends an error message to a log file
        $ErrorCheck = $?
		if ($ErrorCheck -ne "True")
		    {
		    Write-Host "$VM failed Receive-Job with COLO credentials." -ForegroundColor Red
            Write-Output "$VM failed Receive-Job with COLO credentials." >> "$OutputLoc\_ERRORLOG.txt"
		    }#End If
		}#End If
	}#End If

if ($Domain -eq "[FQDNPRIMARYdomainsuffix")#Checks to see if domain is FQDNPRIMARYdomainsuffix, if so, uses Primary domain creds
	{
	
	#Can't use Invoke-Command to directly export to CSV, since this will export it to the local machine running the command. Could save it to network share, but better option is save to variable
	#$Data = Invoke-Command -ComputerName "$VM.FQDNPRIMARYdomainsuffix" -Credential $PRIMARYCredsCreds -ScriptBlock {Get-NetTCPConnection | Select State,CreationTime,LocalAddress,LocalPort,RemotePort,OwningProcess}
	Write-Host "Using Invoke-Command to run Netstat -ano on machine $VM in the PRIMARYDOMAIN." -ForegroundColor Green
	$Data = Invoke-Command -ComputerName "$VM.FQDNPRIMARYdomainsuffix" -Credential $PRIMARYCreds -ScriptBlock {netstat -ano}
		#Checks to see if the job failed, likely indicating that the machine is either offline or there is a mismatch between the VM and OS names
		#If failed, appends an error message to a log file
		$ErrorCheck = $?
		if ($ErrorCheck -ne "True")
		{
        Write-Host "$VM Invoke-Command failed, likely due to being offline, a mismatch between VM and OS name, or Linux box" -ForegroundColor Red
		Write-Output "$VM failed to enumerate or experienced RPC failure, likely due to being either offline, a mismatch between VM and OS name, or Linux box" >> "$OutputLoc\_ERRORLOG.txt"
		}
	$Data > "$OutputLoc\$VM-$Date.txt"
	(Get-Content "$OutputLoc\$VM-$Date.txt" | Select-Object -Skip 1) | Set-Content "$OutputLoc\$VM-$Date.csv" #This line removes the header from the CSV file, makes it cleaner ALSO: If using Netstat and exporting to a txt file due to formatting, will change it a CSV. Won't have proper formatting, but will have actual data
	}#End If

if ($Domain -eq "FQDNCOLOdomainsuffix")#Checks to see if domain is FQDNCOLOdomainsuffix, if so, uses COLO creds
	{
	
	#$Data = Invoke-Command -ComputerName "$VM.FQDNCOLOdomainsuffix" -Credential $COLOCreds -ScriptBlock {Get-NetTCPConnection | Select State,CreationTime,LocalAddress,LocalPort,RemotePort,OwningProcess}
	Write-Host "Using Invoke-Command to run Netstat -ano on machine $VM in the FQDNCOLOdomainsuffix Domain." -ForegroundColor Green
	$Data = Invoke-Command -ComputerName "$VM.FQDNCOLOdomainsuffix" -Credential $COLOCreds -ScriptBlock {netstat -ano}
		#Checks to see if the job failed, likely indicating that the machine is either offline or there is a mismatch between the VM and OS names
		#If failed, appends an error message to a log file
		$ErrorCheck = $?
		if ($ErrorCheck -ne "True")
		{
        Write-Host "$VM Invoke-Command failed, likely due to being offline or a mismatch between VM and OS name" -ForegroundColor Red
		Write-Output "$VM failed to enumerate or experienced RPC failure, likely due to being either offline, or a mismatch between VM and OS name" >> "$OutputLoc\_ERRORLOG.txt"
		}
	$Data > "$OutputLoc\$VM-$Date.txt"
	(Get-Content "$OutputLoc\$VM-$Date.txt" | Select-Object -Skip 1) | Set-Content "$OutputLoc\$VM-$Date.csv" #This line removes the header from the CSV file, makes it cleaner
	}#End If

if ($Domain -eq "FQDNDEVdomainsuffix")#Checks to see if domain is FQDNDEVdomainsuffix, if so, uses DEV creds
	{
	
	#$Data = Invoke-Command -ComputerName "$VM.FQDNDEVdomainsuffix" -Credential $DEVCreds -ScriptBlock {Get-NetTCPConnection | Select State,CreationTime,LocalAddress,LocalPort,RemotePort,OwningProcess}
	Write-Host "Using Invoke-Command to run Netstat -ano on machine $VM in the FQDNDEVdomainsuffix." -ForegroundColor Green
	$Data = Invoke-Command -ComputerName "$VM.FQDNDEVdomainsuffix" -Credential $DEVCreds -ScriptBlock {netstat -ano}
		#Checks to see if the job failed, likely indicating that the machine is either offline or there is a mismatch between the VM and OS names
		#If failed, appends an error message to a log file
		$ErrorCheck = $?
		if ($ErrorCheck -ne "True")
		{
        Write-Host "$VM Invoke-Command failed, likely due to being offline or a mismatch between VM and OS name" -ForegroundColor Red
		Write-Output "$VM failed to enumerate or experienced RPC failure, likely due to being either offline, or a mismatch between VM and OS name" >> "$OutputLoc\_ERRORLOG.txt"
		}
	$Data > "$OutputLoc\$VM-$Date.txt"
	(Get-Content "$OutputLoc\$VM-$Date.txt" | Select-Object -Skip 1) | Set-Content "$OutputLoc\$VM-$Date.csv" #This line removes the header from the CSV file, makes it cleaner, and converts the text file to CSV
	}#End If
}#End Loop


Write-Host "Merging CSVs into a single Excel file"
Merge-CSVFiles -CSVPath "$OutputLoc" -XLOutput "$OutputLoc\_Report-$Date.xlsx"

Write-Host "Sorry, not sure how to get rid of all of those True's yet" -ForegroundColor Green
