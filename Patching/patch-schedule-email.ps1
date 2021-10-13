$ResourceGroup = "ResourceGroupName"
$AutomationAccount = "AutomationAccountName"

$smtpPort = "587"
$smtpSender = "patch.info@company.com"
$smtpServer = "smtp.sendgrid.net"
$smtpUser = "apikey"
$smtpAPIKey = ConvertTo-SecureString (Get-AutomationVariable -Name "SendGrid-API-Key" -ResourceGroup $ResourceGroup -AutomationAccount $AutomationAccount | Select-Object -Expandproperty Value) -AsPlainText -Force
$smtpCreds = New-Object System.Management.Automation.PSCredential $smtpUser, $smtpAPIKey

$CheckTime = (Get-Date).adddays(+3)

#Using get-azautomationschedule and narrowing down the results and NOT get-azautomationscheduledrunbook because running it against the runbook does not return a NextRun time
$UpcomingTasks = Get-AzAutomationSchedule -ResourceGroupName "$ResourceGroup" -AutomationAccountName "$AutomationAccount" | Where-Object {$_.NextRun -lt $CheckTime -and $_.Name -like "*Patch*" -and $_.Frequency -notlike "OneTime"}

ForEach ($Task in $UpcomingTasks){
    if ($Task.Name -like "*Prod*"){$Environment = "Production"}
    if ($Task.Name -like "*Stage*"){$Environment = "Staging"} 
    if ($Task.Name -like "*Test*"){$Environment = "Test"} 
    if ($Task.Name -like "*Dev*"){$Environment = "Development"}
    if ($Task.Name -like "*DevTest*"){$Environment = "Development and Test"}
    if ($Task.Name -like "*App01*"){$Application = "App01"; $smtpRecipient = "App01-Patch-Notifications@company.com"}
    if ($Task.Name -like "*App02*"){$Application = "App02"; $smtpRecipient = "App02-Patch-Notifications@company.com"}
    if ($Task.Name -like "*App03*"){$Application = "App03"; $smtpRecipient = "App03-Patch-Notifications@company.com"}
    if ($Task.Name -like "*App04*"){$Application = "App04"; $smtpRecipient = "App04-Patch-Notifications@company.com"}
 
    #going to need to get the runbook schedule id in order to get the paramters value to then get the variable list, as the get-azautomationschedule command is bugged to not give the parameters without the -jobscheduleid https://github.com/Azure/azure-powershell/issues/9497
    $RunTime = $Task.NextRun.DateTime
    $RunbookTaskName = $Task.Name
    $RunbookName = Get-AzAutomationScheduledRunbook -ResourceGroupName $ResourceGroup -AutomationAccountName $AutomationAccount -ScheduleName $RunbookTaskName
    $RunbookID = $RunbookName.JobScheduleId
    $RunbookScheduleID = Get-AzAutomationScheduledRunbook -ResourceGroupName $ResourceGroup -AutomationAccountName $AutomationAccount -JobScheduleId $RunbookID
    $AzureVariableParameter = $RunbookScheduleID.Parameters.Values 
    $ServerList = (Get-AzAutomationVariable -ResourceGroupName $ResourceGRoup -AutomationAccountName $AutomationAccount -Name $AzureVariableParameter | Select-Object -ExpandProperty Value).Split(",")


    $Subject = "$Application $Environment patching " + $Task.NextRun.DateTime
    $MailBody = "The following $Application servers in the $Environment environment will be patching and rebooting at $RunTime. Please inform IT if this will present an issue. `n`n`n$ServerList"
        
    Send-MailMessage -smtpServer $smtpServer -Credential $smtpCreds -usessl -Port $smtpPort -From "$smtpSender" -To "$smtpRecipient" -Subject "$Subject" -Body "$MailBody" -bcc "Infrastructure@company.com" -Priority "High"
}
