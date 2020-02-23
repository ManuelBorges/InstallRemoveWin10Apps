# tests, ignore

Function funcaoParamsMandatory
{
        Param
        (
            [Parameter(Mandatory=$true,ValueFromRemainingArguments=$true)]
            [ValidateNotNullOrEmpty()]
            [string[]]$listaArgs
        )

        Write-Host "Numero Argumentos: $(@($listaArgs).Length)"
        foreach ($arg in $listaArgs)
        {
            Write-Host "Argumento: $($arg)"
        }
}

$argumentoNulo = $null
$argumentoVazio = " "
funcaoParamsMandatory