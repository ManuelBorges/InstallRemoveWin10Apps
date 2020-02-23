# ##################################################################################################################### #
#                                                                                                                       #
# [en] Main script 																										#
# The goal is to remove a set of predefined Windows Apps and install another predefined set and to Disable many of 		#
# Windows crap Microsoft decided to add. This will be self explanatory in the comments. 								#
# This will run in USER namespace and call external scripts when Admin powers are necessary which might need to write 	#
# info to a file on disk for cross namespace usage of such info. This is needed because our users are limited and when 	#
# Admin is needed a new user credentials are needed changing the namespace making all data available in memory gone 	#
# from the new namespace as expected. The option -AllUsers should, to my understanding, install the App to every user 	#
# in the current PC but after the App is manually removed this does not happen. 										#
# Might be a better way but for now it is the best I can do. 															#
# TODO: comments in [en] and [pt]                                                                                       #
#                                                                                                                       #
# ##################################################################################################################### #

# Open another PS1 INLINE. Credits: https://stackoverflow.com/questions/6816450/call-powershell-script-ps1-from-another-ps1-script-inside-powershell-ise
# The following script will gather info, in Admin userspace, about the InstallLocation of the App we want installed and write it to a file
Invoke-Expression -Command "$($PSScriptRoot)\AdminScriptToGetInfoAboutWinApps.ps1"

# [en] list of apps we want removed on our limited user account
$appsdel=@(
	"*MicrosoftOfficeHub*"
    "*Office.OneNote*" 
    "*windowscommunicationsapps*" 
	"*OneConnect*" 
	"*BingSports*" 
	"*BingFinance*" 
	"*BingWeather*" 
    "*BingNews*" 
    "*WindowsFeedbackHub*" 
	"*MixedReality.Portal*" 
	"*People*" 
	"*ZuneVideo*" 
    "*ZuneMusic*" 
    "*xbox*"
)

# [en] list of apps we want installed on our limited user account
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
$ficheiroTemp = "D:\TMP-Texto.txt" # the file where the InstallLocation will be written to be used later by the user script

# [en] install app in user namespace (no using the -AllUsers) here we need the path gathered to the text file
Function instalaAppUser
{
    param([string]$caminhoDaAPP)
    If ( [string]::IsNullorEmpty($caminhoDaAPP) -Or [String]::IsNullOrWhiteSpace($caminhoDaAPP) )
    {
        Write-Host "Funcao tem um valor nulo ou vazio" -ForeGroundColor Red
        Pause  # to pause and alert
        Exit
    }
    Add-AppxPackage -DisableDevelopmentMode -Register $caminhoDaAPP
    $caminhoDaAPP = $null
}

foreach($line in [System.IO.File]::ReadLines("$($ficheiroTemp)")) {
    $caminho = $line
    instalaAppUser -appCaminho $caminho
    Start-Sleep -Seconds 5
}