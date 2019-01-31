#Run as a scheduled task to check Hyper-V VM replication status
#Written by Matt Snoek matthew.snoek at gmail.com


#Variables
$smtpSender = "SendingEmail@company.com"
$smtpRecipient = "Recipient@company.com"
$smtpServer = "mail.company.com"
$MessageBody = @()

#Gets list of nodes for each cluster, then combines them
$HVNodes01 = Get-ClusterNode -Cluster "cluster01.internal.company.com" | Select-Object -ExpandProperty Name
$HVNodes02 = Get-ClusterNode -Cluster "cluster02.internal.company.com" | Select-Object -ExpandProperty Name
$HVNodes = $HVNodes01 + $HVNodes02

ForEach ($Node in $HVNodes)
{
    $ReplicaCritical = Get-VMReplication -ComputerName "$Node.internal.company.com" | Select-Object Name,State,Health,PrimaryServer,ReplicaServer | Where-Object -Property Health -eq "Critical"
    $MessageBody = $MessageBody + $ReplicaCritical 
}

$MessageBody = $MessageBody | Out-String

if ($MessageBody)
{
    Send-MailMessage -To $smtpRecipient -From $smtpSender -Subject "Hyper-V Critical Replication Errors" -SMTPServer $smtpServer -Body "$MessageBody"
}
