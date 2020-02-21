# ##################################################################################################################### #
#                                                                                                                       #
# [en] Notes: main script                                                                                               #
#                                                                                                                       #
# TODO: coments in [en] and [pt]                                                                                        #
#                                                                                                                       #
# ##################################################################################################################### #

# Open another PS1 INLINE
# credits: https://stackoverflow.com/questions/6816450/call-powershell-script-ps1-from-another-ps1-script-inside-powershell-ise
Invoke-Expression -Command "$($PSScriptRoot)\AdminScriptToGetInfoAndMore.ps1";

Function instalaAppUser
{
    param([string]$caminhoDaAPP)

    If ( [string]::IsNullorEmpty($caminhoDaAPP) -Or [String]::IsNullOrWhiteSpace($caminhoDaAPP) )
    {
        Write-Host "Funcao tem um valor nulo ou vazio" -ForeGroundColor Red
        Pause;  # to pause and alert
        Exit;
    }

    Add-AppxPackage -DisableDevelopmentMode -Register $caminhoDaAPP
    
    $caminhoDaAPP = $null
}

# [en] some variables for better code handling
$ficheiroTemp = "D:\TMP-Texto.txt"; # the file where the InstallLocation will be written to be used later by the user script

foreach($line in [System.IO.File]::ReadLines("$($ficheiroTemp)")) {
    $caminho = $line
    instalaAppUser -appCaminho $caminho
    Start-Sleep -Seconds 5
}