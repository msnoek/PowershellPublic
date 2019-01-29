#Created by Matt Snoek matthew.snoek at gmail.com
#Script to check the health of AD replication

Import-Module ActiveDirectory

$Time = (Get-Date).AddDays(-1)
$smtpSender = "info@company.com"
$smtpServer = "mail.company.com"
$Domain1 = "internal.company.com"
$Domain2 = "internal2.company.com"
$Domain3 = "dev.company.com"

$Domain1Errors = Get-ADReplicationFailure -Target "$Domain1" -scope Domain | Where-Object {$_.FirstFailureTime -gt $Time} | Out-String
$Domain2Errors = Get-ADReplicationFailure -Target "$Domain2" -scope Domain | Where-Object {$_.FirstFailureTime -gt $Time} | Out-String
$Domain3Errors = Get-ADReplicationFailure -Target "$Domain3" -scope Domain | Where-Object {$_.FirstFailureTime -gt $Time} | Out-String

$Body = "The following errors have been found with AD Replication in the past 24 hours: `n`n$Domain1 `n$Domain1Errors `n`n$Domain2 `n$Domain2Errors `n`n$Domain3 `n$Domain3Errors"

$Body = "The following errors have been found with AD Replication in the past 24 hours: " + "`n$Domain1" + "`n$Domain1Errors" + "`n`n$Domain2" + "`n$Domain2Errors" + "`n`n$Domain3" + "`n$Domain3Errors"

if (($Domain1Errors) -or ($Domain2Errors) -or ($Domain3Errors))
{
    Send-MailMessage -To "IT@company.com" -From $smtpSender -Subject "AD Replication Errors" -SMTPServer $smtpServer -Body "$Body"
}