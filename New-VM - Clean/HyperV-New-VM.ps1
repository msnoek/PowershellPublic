param(
    [Parameter(Mandatory=$true)]
    [string]$ClusterTarget,
    [Parameter(Mandatory=$true)]
    [string]$ConfigPath
)

#Run the script with two arguments. The fqdn of the cluster you are building the VMs on, and the full path to the VM configuration JSON file

Install-Module -Name Az -AllowClobber -Force
Import-Module AZ -Force

Write-Host "Please enter domain credentials that have permission on the target Hyper-V or VMWare cluster." -ForegroundColor Green
$Creds = Get-Credential
#Adjust the functions path to the location of your Functions folder
$FunctionsPath = "C:\Path\To\Functions\Folder"

#Adjust the JSON path to the location of your JSON config files
$JSONPath = "C:\Path\To\Config\Folder"

#Loads the functions
. $FunctionsPath\HV-Create-VM-Functions.ps1

$VMConfig = Get-Content $ConfigPath | ConvertFrom-Json
$NumberVM = $VMConfig | Get-Member | Where-Object {$_.Name -like "VM*"} | Select-Object -ExpandProperty Name #Gets the number of VMs to be created

$ClusterVars = Get-Content ($JSONPath + '\' + $ClusterTarget + ".json") | ConvertFrom-Json #Put this in an if statement or list to pick the correct cluster variables, rather than hard coding ues-cluster

$NodeMembers = Invoke-Command -ComputerName $ClusterVars.Host -Credential $Creds -ScriptBlock {Get-ClusterNode | Select-Object -ExpandProperty Name} #Gets all the members of the cluster

#Run the function
HV-Create-VM $Creds $VMConfig $NumberVM $ClusterVars $NodeMembers