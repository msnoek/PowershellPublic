<#In order to re-sysprep a VM, do the following:
1. Copy the pre-sysprep template base VHDX from \\ueshvs2d01\c$\ClusterStorage\CSV1\Template-VHDX\2019
2. Boot template VM from that disk
3. Place this file in C:\Automation
4. Place the unattend.xml file in C:\Windows\Panther (Editted as necessary)
5. Run sysprep with options /generalize /oobe /mode:vm /shutdown
#>
Enable-PSRemoting -Force
Get-NetConnectionProfile | Set-NetConnectionProfile -NetworkCategory "Private"
Enable-WSManCredSSP -Role Server -Force
slmgr.vbs //B -ipk 2019-license-key-here
Start-Sleep -Seconds 10
slmgr.vbs //B -ato