# ##################################################################################################################### #
#                                                                                                                       #
# [en] Common Powershell stuf that might be usefull to other scripts                                                    #
#                                                                                                                       #
# TODO: coments in [en] and [pt]                                                                                        #
#                                                                                                                       #
# ##################################################################################################################### #

# [en] empty temp file
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
    Write-Host "inside delFicheiro"

    $ficheiro = $null;
}

# [en] setup file ACL
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
