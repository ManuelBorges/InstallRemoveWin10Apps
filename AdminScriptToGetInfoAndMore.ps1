# ##################################################################################################################### #
#                                                                                                                       #
# [en] Notes: runs with Administrator powers and goes thru the apps we want to install, finds the path and writes it to #
# a text file (line by line) so that after it can be read by the main script function. This is needed because a         #
# limited user account does not have permissions to read such information.                                              #
#                                                                                                                       #
# TODO: coments in [en] and [pt]                                                                                                #
#                                                                                                                       #
# ##################################################################################################################### #

# [en] Restart script with admin powers (asks for Admin account and auth)
# credits: somewhere on stackoverflow...
If (!([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) 
    {
        # TODO: In production version will add "-WindowStyle Hidden"
        Start-Process powershell.exe "-NoProfile -ExecutionPolicy Bypass -File `"$PSCommandPath`"" -Verb RunAs;
        Exit;
    }

# [en] list of apps we want installed on our limited user account
# the * is usefull for easier find app
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

# [en] empty working file
Function emptyFicheiro
{
    Param([string]$ficheiro);
    If ( [string]::IsNullorEmpty($ficheiro) -Or [String]::IsNullOrWhiteSpace($ficheiro) )
    {
        $ficheiro = $ficheiroTemp;
    }
    $null | Out-File -Force -Encoding UTF8 -FilePath $ficheiro;
    $ficheiro = $null;
    # TODO: if file ! exists
}

# [en] delete temp file
Function delFicheiro
{
    Param([string]$ficheiro);
    If ( [string]::IsNullorEmpty($ficheiro) -Or [String]::IsNullOrWhiteSpace($ficheiro) )
    {
        $ficheiro = $ficheiroTemp;
    }
    # TODO: TUDO!!!

    $ficheiro = $null;
}

Function permissoesFicheiro
{
    # Setup file ACL
    # credits: https://blog.netwrix.com/2018/04/18/how-to-manage-file-system-acls-with-powershell-scripts/
    # notes on ACL
    # Access Right                          # Access Right's Name in PowerShell
    # Full Control                          # FullControl
    # Traverse Folder I Execute File        # ExecuteFile
    # List Folder / Read Data               # ReadData
    # Read Attributes                       # ReadAttributes
    # Read Extended Attributes              # ReadExtendedAttributes
    # Create Files / Write Data             # CreateFiles
    # Create Folders / Append Data          # AppendData
    # Write Attributes                      # WriteAttributes
    # Write Extended Attributes             # WriteExtendedAttributes
    # Delete Subfolders and Files           # DeleteSubdirectonesAndFiles
    # Delete                                # Delete
    # Read Permissions                      # ReadPermissions

    Param ([string]$ficheiro, [string]$utilizador, [string]$permissoes);
    If ( [string]::IsNullorEmpty($ficheiro) -Or [String]::IsNullOrWhiteSpace($ficheiro) )
    {
        $ficheiro = $ficheiroTemp;
    }
    If ( [string]::IsNullorEmpty($utilizador) -Or [String]::IsNullOrWhiteSpace($utilizador) )
    {
        $utilizador = $utilizadorRef;
    }
    If ( [string]::IsNullorEmpty($permissoes) -Or [String]::IsNullOrWhiteSpace($permissoes) )
    {
        $permissoes = "FullControl";
    }
    $permissoesFicheiro = Get-Acl $ficheiro
    $novaPermissao = New-Object System.Security.AccessControl.FileSystemAccessRule("$($utilizador)","$($permissoes)","Allow")
    $permissoesFicheiro.SetAccessRuleProtection($true,$true)
    $permissoesFicheiro.SetAccessRule($novaPermissao)
    $permissoesFicheiro | Set-Acl $ficheiro

    $ficheiro = $utilizador = $permissoes = $null
}

# [en] 
Function escreveInstallLocation
{
    Param([string]$ficheiro, [string]$appNome);
    If ( [string]::IsNullorEmpty($appNome) -Or [String]::IsNullOrWhiteSpace($appNome) )
    {
        Write-Host "Funcao tem um valor nulo ou vazio" -ForeGroundColor Red;
        Pause; # to pause and alert
        Exit;
    }
    If ( [string]::IsNullorEmpty($ficheiro) -Or [String]::IsNullOrWhiteSpace($ficheiro) )
    {
        $ficheiro = $ficheiroTemp;
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


emptyFicheiro -ficheiro $ficheiroTemp
foreach ($aplicacao in $appsadd) 
{
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
    escreveInstallLocation -ficheiro $ficheiroTemp -appNome $aplicacao
}

pause




# Garbage for reference
#Add-AppxPackage -register "$($localizacao)\AppxManifest.xml" -DisableDevelopmentMode
#Get-AppxPackage -Name "Microsoft.WindowsCalculator" -AllUsers 
#Add-AppxPackage -DisableDevelopmentMode -register | Get-AppxPackage -Name "$($_.InstallLocation)\AppxManifest.xml"
#Get-AppxPackage -AllUsers | where-object {$_.name -like "Microsoft.WindowsCalculator"} | Select Name, PackageFullName
#Get-AppxPackage | where-object {$_.name -like "Microsoft.MicrosoftOfficeHub"} | Select PackageFullName