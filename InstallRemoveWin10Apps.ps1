# Open another ps1
# credits: https://stackoverflow.com/questions/6816450/call-powershell-script-ps1-from-another-ps1-script-inside-powershell-ise

#local path : $PSScriptRoot

invoke-expression -Command "$($PSScriptRoot)\Untitled2.ps1"

Function instalaAppUser
{
    param([string]$appCaminho)

    Write-Host "APP: $($appCaminho)"

    If ( [string]::IsNullorEmpty($appCaminho) -Or [String]::IsNullOrWhiteSpace($appCaminho) )
    {
        Write-Host "Funcao instalaAppUser tem um valor nulo ou vazio" -ForeGroundColor Red
        pause
        exit
    }

    Add-AppxPackage -DisableDevelopmentMode -Register $appCaminho
    
    $appNome = $null
}

Write-Host $env:USERNAME


foreach($line in [System.IO.File]::ReadLines("D:\TMP-Texto.txt")) {
    $caminho = $line
    Write-Host $caminho
    instalaAppUser -appCaminho $caminho
    Start-Sleep -Seconds 5
}