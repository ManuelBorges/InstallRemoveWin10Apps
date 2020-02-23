# ##################################################################################################################### #
#                                                                                                                       #
# [en] Notes: runs with Administrator powers and goes thru the apps we want to install, finds the path and writes it to #
# a text file (line by line) so that after it can be read by the main script function. This is needed because a         #
# limited user account does not have permissions to read such information.                                              #
# TODO: comments in [en] and [pt]                                                                                        #
#                                                                                                                       #
# ##################################################################################################################### #

# [en] Restart script with admin powers (asks for Admin account and auth)
# credits: somewhere on stackoverflow...
If (!([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) 
{
    # TODO: In production version will add "-WindowStyle Hidden"
    Start-Process powershell.exe "-NoProfile -ExecutionPolicy Bypass -File `"$PSCommandPath`"" -Verb RunAs
    Exit
}

# [en] list of apps we want installed on our limited user account
# ? here we'll use this to grab the "installLocation"
$appsadd=@(
	"*WindowsCalculator*"
	"*Windows.Photos*"
	"*ScreenSketch*"
	"*MicrosoftStickyNotes*"
	"*SkypeApp*" 
	"*Messaging*" 
	"*MSPaint*"
	"*Print3D*"
	"*Microsoft3DViewer*"
	"*3DBuilder*"
	"*Office.Sway*"
);

# [en] some variables for better code handling
$utilizadorRef = "confadmin"; # TODO: get current logged username (not the admin) to whom the apps will be installed
$ficheiroTemp = "D:\TMP-Texto.txt"; # the file where the InstallLocation will be written to be used later by the user script

# [en] Import-Module instead of load script for better integration, but no direct Intellisense in VSCode :(
# credits for intellisense: https://www.reddit.com/r/PowerShell/comments/5yysft/for_anyone_writing_modules_in_vscode/ 
Import-Module -Name "$PSScriptRoot\CommonPowerShellStuff.ps1"
#. "$PSScriptRoot\CommonPowerShellStuff.ps1"

# notes on function params: 
# https://stackoverflow.com/questions/4988226/how-do-i-pass-multiple-parameters-into-a-function-in-powershell/44731765#44731765
# https://www.reddit.com/r/PowerShell/comments/73wi5e/how_to_write_a_script_that_takes_a_variable/ number of args

# [en] 
Function escreveInstallLocation
{
    Param([string]$ficheiro,[string]$appNome)
    If ( [string]::IsNullorEmpty($appNome) -Or [String]::IsNullOrWhiteSpace($appNome) )
    {
        Write-Host "Funcao tem um valor nulo ou vazio" -ForeGroundColor Red
        Pause # to pause and alert
        Exit
    }
    If ( [string]::IsNullorEmpty($ficheiro) -Or [String]::IsNullOrWhiteSpace($ficheiro) )
    {
        $ficheiro = $ficheiroTemp
    }

    # [en] TODO: less could be more
    $localInstalacaoAppSemManifest = (Get-AppxPackage -AllUsers $appNome).InstallLocation
    $localInstalacaoApp = "$($localInstalacaoAppSemManifest)\AppxManifest.xml"
    $localInstalacaoApp | Out-File -Force -Append -Encoding UTF8 -FilePath $ficheiro 
    Start-Sleep -Seconds 1 # because writing to HDD is slow

    $dependenciasApp = (Get-AppxPackage -AllUsers $appNome).Dependencies
    If ( ! ( [string]::IsNullorEmpty($dependenciasApp) -Or [String]::IsNullOrWhiteSpace($dependenciasApp) ) )
    {
        foreach ($dependencia in $dependenciasApp)
        {
            # needed because complete PATH cannot bet caught from the dependency info
            # FIXME: might be troublesome in x86
            $localInstalacao = "C:\Program Files\WindowsApps\$($dependencia)\AppxManifest.xml"
            $localInstalacao | Out-File -Force -Append -Encoding UTF8 -FilePath $ficheiro 
            Start-Sleep -Seconds 1 # because writing to HDD is slow

        }
    }
}

Function instalaAppGlobal
{

    param([string]$appNome)

    Write-Host "APP: $($appNome)"

    If ( [string]::IsNullorEmpty($appNome) -Or [String]::IsNullOrWhiteSpace($appNome) )
    {
        Write-Host "Funcao instalaAppsEDependencias tem um valor nulo ou vazio" -ForeGroundColor Red
        pause
        exit
    }

    $dependenciasApp = (Get-AppxPackage -AllUsers $appNome).Dependencies

    If ( [string]::IsNullorEmpty($dependenciasApp) -Or [String]::IsNullOrWhiteSpace($dependenciasApp) )
    {
        Get-AppxPackage -AllUsers $appNome | Foreach { Add-AppxPackage -DisableDevelopmentMode -Register “$($_.InstallLocation)\AppXManifest.xml” }
        Write-Host "SEM DEPENDENCIAS: $($appNome)"
    }
    Else
    {
        foreach ($dependencia in $dependenciasApp)
        {
            Write-Host "COM DEPENDENCIAS: $($dependencia)"
            instalaAppGlobal -appNome $dependencia
        }
    }
    $appNome = $dependenciasApp = $null
}

Function instalaAppUser
{
    param([string]$appNome)

    Write-Host "APP: $($appNome)"

    If ( [string]::IsNullorEmpty($appNome) -Or [String]::IsNullOrWhiteSpace($appNome) )
    {
        Write-Host "Funcao instalaAppsEDependencias tem um valor nulo ou vazio" -ForeGroundColor Red
        pause
        exit
    }

    $dependenciasApp = (Get-AppxPackage $appNome).Dependencies

    If ( [string]::IsNullorEmpty($dependenciasApp) -Or [String]::IsNullOrWhiteSpace($dependenciasApp) )
    {
        Get-AppxPackage $appNome | Foreach { Add-AppxPackage -DisableDevelopmentMode -Register “$($_.InstallLocation)\AppXManifest.xml” }
        Write-Host "SEM DEPENDENCIAS: $($appNome)"
    }
    Else
    {
        foreach ($dependencia in $dependenciasApp)
        {
            Write-Host "COM DEPENDENCIAS: $($dependencia)"
            instalaAppUser -appNome $dependencia
        }
    }
    $appNome = $dependenciasApp = $null
}

Function instalaAppsEDependencias
{
    param([string]$appNome, [int]$global)

    If ( $global -eq 1 )
    {
        instalaAppGlobal -appNome $appNome
    }

    If ( $global -eq 0 )
    {
        instalaAppGlobal -appNome $appNome
    } 
}


#emptyFicheiro -ficheiro $ficheiroTemp
#foreach ($aplicacao in $appsadd) 
#{
#    $localizacao = (Get-AppxPackage -AllUsers -Name $aplicacao).InstallLocation
#    If ( ! ([string]::IsNullorEmpty($localizacao) -Or [String]::IsNullOrWhiteSpace($localizacao)) )
#    {
#        Add-AppxPackage -DisableDevelopmentMode -register "$($localizacao)\AppxManifest.xml"
#    } 
#    Else
#    {
#        Write-Host "Instalacao de App falhou pois InstallLocation tem um valor nulo ou vazio" -ForeGroundColor Red
#        pause
#        exit
#    }
    #Get-AppxPackage -allusers $aplicacao | Foreach {Add-AppxPackage -DisableDevelopmentMode -Register “$($_.InstallLocation)\AppXManifest.xml”}
    #instalaAppsEDependencias -appNome $aplicacao 1
#    escreveInstallLocation -ficheiro $ficheiroTemp -appNome $aplicacao
#}

Write-Host "Teste"
pause




# Garbage for reference
#Add-AppxPackage -register "$($localizacao)\AppxManifest.xml" -DisableDevelopmentMode
#Get-AppxPackage -Name "Microsoft.WindowsCalculator" -AllUsers 
#Add-AppxPackage -DisableDevelopmentMode -register | Get-AppxPackage -Name "$($_.InstallLocation)\AppxManifest.xml"
#Get-AppxPackage -AllUsers | where-object {$_.name -like "Microsoft.WindowsCalculator"} | Select Name, PackageFullName
#Get-AppxPackage | where-object {$_.name -like "Microsoft.MicrosoftOfficeHub"} | Select PackageFullName