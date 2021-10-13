#Input Variables
$PayloadName = "Microsoft-ASR_UA_9.32.0.0_Windows_GA_10Jan2020_Release.exe"
$ConnPassName = "p10asrconf01-connection.passphrase"
$ASRConfServerIP = "10.125.2.115"
$RemoteServersPath = $PSScriptRoot + "\asr-servers.csv"

#Derived Variables
$PayloadPath = $PSScriptRoot + "\" + $PayloadName
$ConnPassPath = $PSScriptRoot + "\" + $ConnPassName

$Creds = Get-Credential

$RemoteServers = Import-Csv -Path $RemoteServersPath

$RemoteServers | ForEach-Object {

    $CurrentSession = $null
    $CurrentSession = New-PSSession -ComputerName $_.ComputerName -Credential $Creds
    
    Invoke-Command -Session $CurrentSession -ScriptBlock {

        $TestPath = Test-Path -Path $($using:_.RemotePath)
        If ($TestPath -eq $False) {New-Item -ItemType Directory -Path $($using:_.RemotePath) -Force}

    }

    Copy-Item -Path $PayloadPath -Destination $_.RemotePath -ToSession $CurrentSession -Force
    Copy-Item -Path $ConnPassPath -Destination $_.RemotePath -ToSession $CurrentSession -Force

    Start-Sleep -Seconds 5

    Invoke-Command -Session $CurrentSession -ScriptBlock {
            
        $ExtractPath = $($using:_.RemotePath) + "\Extracted"
        $PassPath = '"{0}"' -f ($($using:_.RemotePath) + "\" + $($using:ConnPassName))
        $AgentPath = "C:\Program Files (x86)\Microsoft Azure Site Recovery\agent"
        $InstallationPath = "`"C:\Program Files (x86)\Microsoft Azure Site Recovery`""
        $PayloadLocalPath = ".\" + $($using:PayloadName)
        
        cd $($using:_.RemotePath)
        Invoke-Expression -Command "$PayloadLocalPath /q /x:$ExtractPath"
        Start-Sleep -Seconds 10
        cd $ExtractPath
        Invoke-Expression -Command ".\UnifiedAgent.exe /Role MS /InstallLocation $InstallationPath /Platform `"VmWare`" /Silent"
        Start-Sleep -Seconds 10
        cd $AgentPath
        Invoke-Expression -Command ".\UnifiedAgentConfigurator.exe /CSEndPoint $($using:ASRConfServerIP) /PassphraseFilePath $PassPath"
        Start-Sleep -Seconds 30
        Remove-Item -Path $($using:_.RemotePath) -Recurse -Force
    
    }

    Remove-PSSession -Session $CurrentSession
    Write-Host "`n`nInstall attempt on $($_.ComputerName) has finished.  Please review log for details.`n`n"

}
