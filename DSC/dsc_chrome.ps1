configuration dsc_chrome
{
    Import-DscResource -ModuleName cChoco
    Node chrome_install
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
    }
}