#Need Chrome, Notepad++, Firefox, Traps, IIS, Prometheus, Firewall rules
configuration dsc_win_web_traps
{
    Import-DscResource -ModuleName cChoco
    Import-DscResource -ModuleName NetworkingDSC
    Node base_config
    {
        cChocoinstaller InstallChoco
        {
            InstallDir  = 'C:\Choco'
        }

        cChocoPackageInstaller googlechrome
        {
            Name        = 'googlechrome'
            Ensure      = 'Present'
            AutoUpgrade = $True
            Source      = 'https://chocolatey.org/api/v2'
            DependsOn   = '[cChocoinstaller]InstallChoco'
        }
        cChocoPackageInstaller firefox
        {
            Name        = 'firefox'
            Ensure      = 'Present'
            AutoUpgrade = $True
            Source      = 'https://chocolatey.org/api/v2'
            DependsOn   = '[cChocoinstaller]InstallChoco'
        }
        cChocoPackageInstaller notepadplusplus
        {
            Name        = 'notepadplusplus'
            Ensure      = 'Present'
            AutoUpgrade = $True
            Source      = 'https://chocolatey.org/api/v2'
            DependsOn   = '[cChocoinstaller]InstallChoco'
        }
        File CortexFile
        {
            Ensure      = 'Present'
            Type        = 'File'
            SourcePath  = '\\path\to\file\PACortex.msi'
            DestinationPath = 'C:\Automation\PACortex.msi'
        }
        Package CortexInstall
        {
            Name        = 'Cortex XDR 7.2.0.63060'
            Ensure      = 'Present'
            Path        = 'C:\Automation\PACortex.msi'
            DependsOn   = '[File]CortexFile'
            ProductID   = '08E60AAF-4624-40B0-A898-26B525C1D74F'
        }
        Firewall WebIn
        {
            Name                  = 'Web Traffic In'
            DisplayName           = 'Firewall Rule for Web Traffic'
            Ensure                = 'Present'
            Enabled               = 'True'
            Profile               = 'Domain'
            Direction             = 'Inbound'
            LocalPort             = ('80', '443')
            Protocol              = 'TCP'
            Description           = 'Firewall Rule for HTTP/HTTPS'
        }
        WindowsFeature IIS
        {
            Ensure               = 'Present'
            Name                 = 'Web-Server'
            IncludeAllSubFeature = $true
        }
    }
}