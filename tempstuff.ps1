# concatenate of all stuff as I test
# will be going to main files as cleanup occurs  


# ################################################################################################################### #
# Elevacao de permissões para correr script em Admin                                                                  #
# ################################################################################################################### # 
If (!([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]"Administrator")) 
{
    Start-Process powershell.exe "-NoProfile -ExecutionPolicy Bypass -File `"$PSCommandPath`"" -Verb RunAs
    Exit
}
# ################################################################################################################### #
# Arrays com a lista de apps                                                                                          #
# ################################################################################################################### #
$appsdel=@(
	"Microsoft.MicrosoftOfficeHub" 
	"microsoft.windowscommunicationsapps" 
	"Microsoft.OneConnect*" 
	"Microsoft.BingSports" 
	"Microsoft.BingFinance" 
	"Microsoft.WindowsFeedbackHub" 
	"Microsoft.BingWeather" 
	"Microsoft.BingNews" 
	"Microsoft.MixedReality.Portal" 
	"Microsoft.Office.OneNote" 
	"Microsoft.People" 
	"Microsoft.ZuneVideo" 
    "Microsoft.ZuneMusic" 
    "*xbox*"
)

$appsadd=@(
	"Microsoft.WindowsCalculator"
	"Microsoft.Windows.Photos"
	"Microsoft.ScreenSketch"
	"Microsoft.MicrosoftStickyNotes"
	"Microsoft.SkypeApp" 
	"Microsoft.Messaging" 
	"Microsoft.MSPaint"
	"Microsoft.Print3D"
	"Microsoft.Microsoft3DViewer"
	"Microsoft.3DBuilder"
	"Microsoft.Office.Sway"
)

$appStore="*store*"

# ################################################################################################################### #
# Funcao para validar se chave de registo existe                                                                      #
# ################################################################################################################### #
Function validaChaveRegistoEEscreve
{
    param([string]$chave, [string]$valorNome, [string]$tipo, [string]$valorValor)

    If ( [string]::IsNullorEmpty($valorValor) -Or [String]::IsNullOrWhiteSpace($valorValor) -Or [string]::IsNullorEmpty($chave) -Or [String]::IsNullOrWhiteSpace($chave) -Or [string]::IsNullorEmpty($valorNome) -Or [String]::IsNullOrWhiteSpace($valorNome) -Or [string]::IsNullorEmpty($tipo) -Or [String]::IsNullOrWhiteSpace($tipo) )
    {
        Write-Host "Funcao validaChaveRegistoEEscreve tem um valor nulo ou vazio" -ForeGroundColor Red
        pause
        exit
    }
    If (!(Test-Path $chave)) 
    {
        New-Item -Path $chave -Force | Out-Null
    }
    If ((Test-Path $chave)) 
    {
        Set-ItemProperty -Path $chave -Name $valorNome -Type $tipo -Value $valorValor -Force
    }
    $chave = $valorNome = $tipo = $valorValor = $valorString = $null
}
# validaChaveRegistoEEscreve -chave "aChave" -valorNome "oNome" -tipo "oTipo" -valorValor "oValor"

# ################################################################################################################### #
# Funcao para instalar Apps e dependencias                                                                            #
# ################################################################################################################### #
Function instalaAppsEDependencias
{
    param([string]$appNome)

    If ( [string]::IsNullorEmpty($appNome) -Or [String]::IsNullOrWhiteSpace($appNome) )
    {
        Write-Host "Funcao instalaAppsEDependencias tem um valor nulo ou vazio" -ForeGroundColor Red
        pause
        exit
    }

    $dependenciasApp = (Get-AppxPackage -AllUsers $appNome).Dependencies

    If ( [string]::IsNullorEmpty($dependenciasApp) -Or [String]::IsNullOrWhiteSpace($dependenciasApp) )
    {
        Get-AppxPackage -allusers $appNome | Foreach { Add-AppxPackage -DisableDevelopmentMode -Register “$($_.InstallLocation)\AppXManifest.xml” -WhatIf }
    }
    Else
    {
        Get-AppxPackage -allusers $appNome | Foreach { Add-AppxPackage -DisableDevelopmentMode -Register “$($_.InstallLocation)\AppXManifest.xml” -DependencyPackages $dependenciasApp -WhatIf } 
    }
    
    $appNome = $dependenciasApp = $null
}



# Notas: Registry Types
# REG_SZ = String
# REG_BINARY = Binary
# REG_DWORD = Dword
# REG_QWORD = QWord
# REG_MULTI_SZ = MultiString
# REG_EXPAND_SZ = ExpandString
# Get-ItemProperty -Path "HKLM:\PATH"
# (Get-Item -Path Registry::HKEY_LOCAL_MACHINE\PATH).GetValueKind("Key")

# ################################################################################################################### #
# USER POLICY                                                                                                         #
# Disable auto update e download de store Apps                                                                        #
# ################################################################################################################### #
validaChaveRegistoEEscreve -chave "HKCU:\SOFTWARE\Policies\Microsoft\WindowsStore" -valorNome "AutoDownload" -tipo "Dword" -valorValor "2"
#Reg Add "HKCU\SOFTWARE\Policies\Microsoft\WindowsStore" /T REG_DWORD /V "AutoDownload" /D 2 /F



# ################################################################################################################### #
# USER POLICY                                                                                                         #
# Disable suggested apps, feedback, ads, instalacao auto de apps, etc                                                 #
# ################################################################################################################### #
$disableSugestedFeedbackAutoInstallApps = @(
    "HKCU:\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager"
    "HKCU:\Software\Microsoft\CurrentVersion\ContentDeliveryManager"
    "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced"
)
$contentDeliveryManagerOptions = @(
    "SoftLandingEnabled"
    "RotatingLockScreenEnable"
    "PreInstalledAppsEnabled"
    "SilentInstalledAppsEnabled"
    "ContentDeliveryAllowed"
)

foreach ($chave in $disableSugestedFeedbackAutoInstallApps) {
    If ($chave -eq $disableSugestedFeedbackAutoInstallApps[0]) {
        validaChaveRegistoEEscreve -chave $chave -valorNome "SystemPaneSuggestionsEnabled" -tipo "Dword" -valorValor "0"
    }
    If ($chave -eq $disableSugestedFeedbackAutoInstallApps[1]) {
        foreach ($nome in $contentDeliveryManagerOptions) {
            validaChaveRegistoEEscreve -chave $chave -valorNome $nome -tipo "Dword" -valorValor "0"
        }
    }
    If ($chave -eq $disableSugestedFeedbackAutoInstallApps[2]) {
        validaChaveRegistoEEscreve -chave $chave -valorNome "ShowSyncProviderNotifications" -tipo "Dword" -valorValor "0"
    }
}
#Reg Add "HKCU\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager\" /T REG_DWORD /V "SystemPaneSuggestionsEnabled" /D 0 /F
#Reg Add "HKCU\Software\Microsoft\CurrentVersion\ContentDeliveryManager\" /T REG_DWORD /V "SoftLandingEnabled" /D 0 /F
#Reg Add "HKCU\Software\Microsoft\CurrentVersion\ContentDeliveryManager\" /T REG_DWORD /V "RotatingLockScreenEnable" /D 0 /F
#Reg Add "HKCU\Software\Microsoft\CurrentVersion\ContentDeliveryManager\" /T REG_DWORD /V "PreInstalledAppsEnabled" /D 0 /F
#Reg Add "HKCU\Software\Microsoft\CurrentVersion\ContentDeliveryManager\" /T REG_DWORD /V "SilentInstalledAppsEnabled" /D 0 /F
#Reg Add "HKCU\Software\Microsoft\CurrentVersion\ContentDeliveryManager\" /T REG_DWORD /V "ContentDeliveryAllowed" /D 0 /F
#Reg Add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced\" /T REG_DWORD /V "ShowSyncProviderNotifications" /D 0 /F



# ################################################################################################################### #
# MACHINE POLICY                                                                                                      #
# Disable cloud crap                                                                                                  #
# ################################################################################################################### #
# https://community.spiceworks.com/scripts/show/3298-windows-10-decrapifier-version-1
validaChaveRegistoEEscreve -chave "HKLM:\SOFTWARE\Policies\Microsoft\Windows\CloudContent" -valorNome "DisableWindowsConsumerFeatures" -tipo "Dword" -valorValor "1"
#Reg Add "HKLM\SOFTWARE\Policies\Microsoft\Windows\CloudContent\" /T REG_DWORD /V "DisableWindowsConsumerFeatures" /D 1 /F


# ################################################################################################################### #
# MACHINE POLICY                                                                                                      #
# Disable OneDrive                                                                                                    #
# ################################################################################################################### #
$onedriveDesactivarGlobal = @(
    "DisableFileSyncNGSC"
    "DisableFileSync"
)
foreach ($nome in $onedriveDesactivarGlobal) {
    validaChaveRegistoEEscreve -chave "HKLM:\Software\Policies\Microsoft\Windows\OneDrive" -valorNome $nome -tipo "Dword" -valorValor "1"
}
#Reg Add "HKLM\Software\Policies\Microsoft\Windows\OneDrive" /T REG_DWORD /V "DisableFileSyncNGSC" /D 1 /F
#Reg Add "HKLM\Software\Policies\Microsoft\Windows\OneDrive" /T REG_DWORD /V "DisableFileSync" /D 1 /F

# ################################################################################################################### #
# USER POLICY                                                                                                         #
# Disable startup OneDrive                                                                                            #
# ################################################################################################################### #
validaChaveRegistoEEscreve -chave "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\StartupApproved\Run" -valorNome "OneDrive" -tipo "Binary" -valorValor "0300000021B9DEB396D7D001"
# Reg Add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\StartupApproved\Run" /T REG_BINARY /V "OneDrive" /D 0300000021B9DEB396D7D001 /F

pause




# testes
# Get-AppxPackage | where-object {$_.nonremovable -like "False" -and $_.name -like "*sim*"}

# pede admin
If (!([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]"Administrator")) {
    Start-Process powershell.exe "-NoProfile -ExecutionPolicy Bypass -File `"$PSCommandPath`"" -Verb RunAs
    Exit
}

# lista de apps
$appsdel=@(
	"Microsoft.MicrosoftOfficeHub" 
	"microsoft.windowscommunicationsapps" 
	"Microsoft.OneConnect*" 
	"Microsoft.BingSports" 
	"Microsoft.BingFinance" 
	"Microsoft.WindowsFeedbackHub" 
	"Microsoft.BingWeather" 
	"Microsoft.MixedReality.Portal" 
	"Microsoft.BingNews" 
	"Microsoft.Office.OneNote" 
	"Microsoft.People" 
	"Microsoft.ZuneVideo" 
	"Microsoft.ZuneMusic" 
)
$appsdel2=@(
	"*xbox*" 
)
$appsadd=@(
	"Microsoft.WindowsCalculator"
	"Microsoft.Windows.Photos"
	"Microsoft.ScreenSketch"
	"Microsoft.MicrosoftStickyNotes"
	"Microsoft.SkypeApp" 
	"Microsoft.Messaging" 
	"Microsoft.MSPaint"
	"Microsoft.Print3D"
	"Microsoft.Microsoft3DViewer"
	"Microsoft.3DBuilder"
	"Microsoft.Office.Sway"
)
$appsadd2=@(
	"*store*"
)
foreach ($app in $appsdel) {    
    Get-AppxPackage -Name $app -AllUsers | Where-Object {$_.nonremovable -like "False"} | Remove-AppxPackage -AllUsers -erroraction silentlycontinue
    Get-AppXProvisionedPackage -Online | where DisplayName -EQ $app | Remove-AppxProvisionedPackage -Online -erroraction silentlycontinue
            
    $appPath="$Env:LOCALAPPDATA\Packages\$app*"
    Remove-Item $appPath -Recurse -Force -ErrorAction 0
}






# Disabling auto update and download of Windows Store Apps
Reg Add "HKCU\SOFTWARE\Policies\Microsoft\WindowsStore" /T REG_DWORD /V "AutoDownload" /D 2 /F

# Disabling Suggested Apps, Feedback, Lockscreen Spotlight, File Explorer ads, and unwanted app installs for this user
Reg Add "HKCU\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager\" /T REG_DWORD /V "SystemPaneSuggestionsEnabled" /D 0 /F
Reg Add "HKCU\Software\Microsoft\CurrentVersion\ContentDeliveryManager\" /T REG_DWORD /V "SoftLandingEnabled" /D 0 /F
Reg Add "HKCU\Software\Microsoft\CurrentVersion\ContentDeliveryManager\" /T REG_DWORD /V "RotatingLockScreenEnable" /D 0 /F
Reg Add "HKCU\Software\Microsoft\CurrentVersion\ContentDeliveryManager\" /T REG_DWORD /V "PreInstalledAppsEnabled" /D 0 /F
Reg Add "HKCU\Software\Microsoft\CurrentVersion\ContentDeliveryManager\" /T REG_DWORD /V "SilentInstalledAppsEnabled" /D 0 /F
Reg Add "HKCU\Software\Microsoft\CurrentVersion\ContentDeliveryManager\" /T REG_DWORD /V "ContentDeliveryAllowed" /D 0 /F
Reg Add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced\" /T REG_DWORD /V "ShowSyncProviderNotifications" /D 0 /F

# Disabling Cloud-Content for this machine...
# https://community.spiceworks.com/scripts/show/3298-windows-10-decrapifier-version-1
Reg Add "HKLM\SOFTWARE\Policies\Microsoft\Windows\CloudContent\" /T REG_DWORD /V "DisableWindowsConsumerFeatures" /D 1 /F

#Disabling OneDrive for local machine...
Reg Add "HKLM\Software\Policies\Microsoft\Windows\OneDrive" /T REG_DWORD /V "DisableFileSyncNGSC" /D 1 /F
Reg Add "HKLM\Software\Policies\Microsoft\Windows\OneDrive" /T REG_DWORD /V "DisableFileSync" /D 1 /F

#Disabling Onedrive startup run for this user...
Reg Add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\StartupApproved\Run" /T REG_BINARY /V "OneDrive" /D 0300000021B9DEB396D7D001 /F

#Disabling telemetry for local machine...
Reg Add "HKLM\Software\Policies\Microsoft\Windows\DataCollection" /T REG_DWORD /V "AllowTelemetry" /D 0 /F
Reg Add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Device Metadata" /V "PreventDeviceMetadataFromNetwork" /T REG_DWORD /D 1 /F
Reg Add "HKLM\SOFTWARE\Policies\Microsoft\MRT" /V "DontOfferThroughWUAU" /T REG_DWORD /D 1 /F
Reg Add "HKLM\SOFTWARE\Policies\Microsoft\SQMClient\Windows" /V "CEIPEnable" /T REG_DWORD /D 0 /F
Reg Add "HKLM\SOFTWARE\Policies\Microsoft\Windows\AppCompat" /V "AITEnable" /T REG_DWORD /D 0 /F
Reg Add "HKLM\SOFTWARE\Policies\Microsoft\Windows\AppCompat" /V "DisableUAR" /T REG_DWORD /D 1 /F

#Setting Windows 10 privacy options for this user...
Reg Add "HKLM\Software\Policies\Microsoft\Windows\AppPrivacy" /T REG_DWORD /V "LetAppsAccessAccountInfo" /D 2 /F
Reg Add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\AdvertisingInfo" /T REG_DWORD /V "Enabled" /D 0 /F
Reg Add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\AppHost" /T REG_DWORD /V "EnableWebContentEvaluation" /D 0 /F
Reg Add "HKCU\SOFTWARE\Microsoft\Input\TIPC" /T REG_DWORD /V "Enabled" /D 0  /F
Reg Add "HKCU\Control Panel\International\User Profile" /T REG_DWORD /V "HttpAcceptLanguageOptOut" /D 1 /F
Reg Add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\DeviceAccess\Global\{BFA794E4-F964-4FDB-90F6-51056BFE4B44}" /T REG_SZ /V Value /D DENY /F
Reg Add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\DeviceAccess\Global\{E5323777-F976-4f5b-9B55-B94699C46E44}" /T REG_SZ /V Value /D DENY /F
Reg Add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\DeviceAccess\Global\{2EEF81BE-33FA-4800-9670-1CD474972C3F}" /T REG_SZ /V Value /D DENY /F
Reg Add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\DeviceAccess\Global\{C1D23ACC-752B-43E5-8448-8D0E519CD6D6}" /T REG_SZ /V Value /D DENY /F
Reg Add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\DeviceAccess\Global\{E5323777-F976-4f5b-9B55-B94699C46E44}" /T REG_SZ /V Value /D DENY /F
Reg Add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\DeviceAccess\Global\{D89823BA-7180-4B81-B50C-7E471E6121A3}" /T REG_SZ /V Value /D DENY /F
Reg Add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\DeviceAccess\Global\{992AFA70-6F47-4148-B3E9-3003349C1548}" /T REG_SZ /V Value /D DENY /F
Reg Add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\DeviceAccess\Global\{A8804298-2D5F-42E3-9531-9C8C39EB29CE}" /T REG_SZ /V Value /D DENY /F
Reg Add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\DeviceAccess\Global\LooselyCoupled" /T REG_SZ /V Value /D DENY /F
Reg Add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\DeviceAccess\Global\{D89823BA-7180-4B81-B50C-7E471E6121A3}" /T REG_SZ /V Value /D DENY /F
Reg Add "HKCU\SOFTWARE\Microsoft\Personalization\Settings" /T REG_DWORD /V "AcceptedPrivacyPolicy" /D 0 /F
Reg Add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\SettingSync\Groups\Language" /T REG_DWORD /V "Enabled" /D 0 /F
Reg Add "HKCU\SOFTWARE\Microsoft\InputPersonalization" /T REG_DWORD /V "RestrictImplicitTextCollection" /D 1 /F
Reg Add "HKCU\SOFTWARE\Microsoft\InputPersonalization" /T REG_DWORD /V "RestrictImplicitInkCollection" /D 1 /F
Reg Add "HKCU\SOFTWARE\Microsoft\InputPersonalization\TrainedDataStore" /T REG_DWORD /V "HarvestContacts" /D 0 /F
Reg Add "HKCU\SOFTWARE\Microsoft\Siuf\Rules" /T REG_DWORD /V "NumberOfSIUFInPeriod" /D 0 /F

#Disallowing apps from accessing account info on this machine
Reg Add "HKLM\Software\Policies\Microsoft\Windows\AppPrivacy" /T REG_DWORD /V "LetAppsAccessAccountInfo" /D 2 /F

#Disallowing Cortana and web connected search through local machine policy
Reg Add "HKLM\SOFTWARE\Policies\Microsoft\Windows\Windows Search" /V "AllowCortana" /T REG_DWORD /D 0 /F
Reg Add "HKLM\SOFTWARE\Policies\Microsoft\Windows\Windows Search" /V "ConnectedSearchUseWeb" /T REG_DWORD /D 0 /F

#Disabling Cortana and Bing search for this user
Reg Add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Search" /V "CortanaEnabled" /T REG_DWORD /D 0 /F
Reg Add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Search" /V "SearchboxTaskbarMode" /T REG_DWORD /D 0 /F
Reg Add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Search" /V "BingSearchEnabled" /T REG_DWORD /D 0 /F
Reg Add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Search" /V "DeviceHistoryEnabled" /T REG_DWORD /D 0 /F

#Disabling some unecessary scheduled tasks
Get-Scheduledtask "SmartScreenSpecific","Microsoft Compatibility Appraiser","Consolidator","KernelCeipTask","UsbCeip","Microsoft-Windows-DiskDiagnosticDataCollector", "GatherNetworkInfo","QueueReporting" | Disable-scheduledtask 

#Stopping and disabling diagnostics tracking services, Onedrive sync service, various Xbox services, Distributed Link Tracking, and Windows Media Player network sharing (you can turn this back on if you share your media libraries with WMP)
Get-Service Diagtrack,OneSyncSvc,XblAuthManager,XblGameSave,XboxNetApiSvc,TrkWks,WMPNetworkSvc | stop-service -passthru | set-service -startuptype disabled

