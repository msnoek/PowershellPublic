#Checks the directory sizes of remote shares
#Written by Matt Snoek matthew.snoek at gmail.com

Write-Host "WARNING: THIS SCRIPT WILL HAVE THE FILE PERMISSIONS OF THE USER ACCOUNT USED TO RUN IT"
Write-Host ""
Write-Host ""
Write-Host "--------------------------------------------------------------------------------------"
$Server = Read-Host "Enter the server name to check against, no '\\'"
$Path = Read-Host "Enter the directory to be checked. Example, if the server was entered as 'FILE01', the path could be 'Shares\Installs'"
$OutputLoc = Read-Host "Enter the output location, no trailing \"

$properties = @( #This sets an array for properties, to make the file sizes a bit easier to read
    'FullName'
    @{
        Label = 'Size'
        Expression = {
            if ($_.Length -ge 1GB)
            {
                '{0:F2} GB' -f ($_.Length / 1GB)
            }
            elseif ($_.Length -ge 1MB)
            {
                '{0:F2} MB' -f ($_.Length / 1MB)
            }
            elseif ($_.Length -ge 1KB)
            {
                '{0:F2} KB' -f ($_.Length / 1KB)
            }
            else
            {
                '{0} bytes' -f $_.Length
            }
        }
    }
)

Get-ChildItem -Path "\\$Server\$Path" -Recurse | Select-Object -Property $Properties | Export-CSV "$OutputLoc\$Server-File-Size.csv" -NoTypeInformation
