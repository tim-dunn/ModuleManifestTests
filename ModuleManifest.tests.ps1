#requires -Version 3.0 -Modules Pester
<#
        .SYNOPSIS
        This is a PowerShell Unit Test file for a PSModule's manifest file (.psd1)

        .DESCRIPTION
        You need a unit test framework such as Pester to run PowerShell Unit tests. 
        You can download Pester from http://go.microsoft.com/fwlink/?LinkID=534084

        .NOTES
        // Copyright (c) Microsoft Corporation. All rights reserved.
        // Licensed under the MIT license.

        # Who             What            When            Why
        # timdunn         v1.0.0          2018-09-12      FunctionsToExport should not be '*'

        Drop this fine in the PSModule's root folder. Invoke-Pester will test it
        against all the functions the root module exports.
#>

[CmdletBinding()]
param
(
    [string]$ModuleManifestPath = $null
)

begin
{
    $_MyInvocation = $MyInvocation

    [string]$basename = Split-Path -Path $MyInvocation.InvocationName -Leaf

    Write-Verbose -Message "$basename started."

    $ErrorActionPreference = 'Stop'

    # we'll use this to read in .psd1 files
    [string]$tempPs1Path = "$env:TEMP\$( [Guid]::NewGuid().ToString() ).ps1"

    #region load test settings file, if present

    [string]$testSettingsPath = $PSCommandPath -replace '\.ps1', '.psd1'

    [hashtable]$script:testSettings = @{}
    if ( Test-Path -Path $testSettingsPath )
    {
        Write-Verbose -Message "Loading '$testSettingsPath'"

        try
        {
            Copy-Item -Path $testSettingsPath -Destination $tempPs1Path -Force
            [hashtable]$script:testSettings = . $tempPs1Path
        }

        catch
        {
            Write-Warning "Loading '$testSettingsPath' hit exception:"
            $_ |
            Write-Warning
    
        }
    }

    #endregion load test settings file, if present
    #region load module manifest

    [string]$moduleName = Split-Path -Path $PSScriptRoot -Leaf

    if ( $ModuleManifestPath -eq '' )
    {
        $ModuleManifestPath = "$PSScriptRoot\$moduleName.psd1"
    }

    Write-Verbose -Message "Loading '$testSettingsPath'"

    [hashtable]$script:moduleManifest = @{}
    try
    {
        Copy-Item -Path $ModuleManifestPath -Destination $tempPs1Path -Force
        [hashtable]$script:moduleManifest = . $tempPs1Path
    }

    catch
    {
        Write-Warning "Loading '$ModuleManifestPath' hit exception:"
        $_ |
        Write-Warning

        # if we can't load the module manifest, there's no point continuing
        return    
    }

    #endregion load module manifest

    Import-Module -Force -Name $ModuleManifestPath -Global
    

}

process
{
    try
    {
        if ( $script:moduleManifest.Keys.Count -eq 0 )
        {
            # we failed to load the .PSD1 file, so why bother?
            return
        }

        Describe "$moduleName.psd1" `
        {
            # initialize some strings
            [string]$_cmdName = [string]$_cmdToExport = [string]$subPath = $null

            # needed to map module manifest's '<whatever>ToExport' key to a Get-Command -CommandType argument
            [hashtable]$getCommandType = @{
                AliasesToExport   = 'Alias'
                CmdletsToExport   = 'Cmdlet'
                FunctionsToExport = 'Function'
            }


            foreach ( $_cmdToExport in (
                    $script:moduleManifest.Keys -match 'ToExport$' -notmatch 'VariablesToExport' |
                    Sort-Object
            ) )
            {
                # possible values: AliasesToExport, CmdletsToExport, and FunctionsToExport

                # when we Get-Command for the particular command, what -CommandType are we querying?
                $cmdType = $getCommandType.$_cmdToExport

                # Functions, Aliases, Cmdlets
                $pluralCmdType = $_cmdToExport -replace 'ToExport$'

                # list of commands (alias, cmdlet, or function) this hashkey exports
                [string[]]$exportedCmds = $script:moduleManifest.$_cmdToExport

                if ( $exportedCmds.Count -eq 0 )
                {
                    Write-Verbose -Message "$moduleName contains no $pluralCmdType, skipping."
                    continue
                }

                [Management.Automation.CommandInfo[]]$actualCmds = Get-Command -Module $moduleName -CommandType $cmdType

                Context "$moduleName's.psd1's $_cmdToExport" `
                {
                    It "$_cmdToExport enumerates commands by name" `
                    {
                        # FunctionsToExport = '*'
                        #
                        # is very bad when the PSModule contains many functions, aliases, or cmdlets. If a module
                        # exports by name, then tab-completion is much faster than if PSH has to search through
                        # every .PSM1 and .DLL under $env:PSModulePath without a PSD1, or has a PSD1 using '*'

                        $exportedCmds -contains '*' |
                        Should Be $false
                    }
                }

                if ( $exportedCmds -contains '*' )
                {
                    # if we DO have a '*', there's no point testing exported commands further
                    Write-Verbose -Message "$moduleName's $_cmdToExport contains a '*', skipping other $cmdType tests."
                    continue
                }

                Context "$moduleName's exported $pluralCmdType" `
                {
                    foreach ( $_cmdName in $exportedCmds )
                    {
                        It "$_cmdName is defined in $moduleName" `
                        {
                            {
                                Get-Command -Module $moduleName -CommandType $cmdType -Name $_cmdName
                            } |
                            Should Not Throw
                        }
                    }
                }

                Context "$moduleName.psd1's listed $pluralCmdType" `
                {
                    foreach ( $_cmdName in $actualCmds.Name )
                    {
                        It "$_cmdName is listed in $moduleName.psd1" `
                        {
                            $_cmdName -in $exportedCmds |
                            Should Be $true
                        }
                    }
                }

            } # foreach ( $_cmdToExport in (...


            if  ( '*' -notin [string[]]$script:moduleManifest.AliasesToExport )
            {
                # we've validated that all AliasesToExport exist, now let's test for all [Alias()] attributes
                # decorating functions are exported via AliasesToExport

                Context 'All [Alias()] defined in functions are exported' `
                {
                    $exportedAliases = $script:moduleManifest.AliasesToExport

                    [Management.Automation.FunctionInfo]$functionInfo = $null

                    foreach ( $functionInfo in Get-Command -Module $moduleName -CommandType Function )
                    {
                        [string]$functionName = $functionInfo.Name

                        [string[]]$aliasNames = $functionInfo.ScriptBlock.Attributes.AliasNames

                        if ( $aliasNames.Count -eq 0 )
                        {
                            Write-Verbose -Message "$moduleName's $functionName does not have any aliases, skipping."
                            continue
                        }

                        [string]$_aliasName = $null

                        foreach ( $_aliasName in $aliasNames )
                        {
                            It "$functionName function's $_aliasName alias is exported" `
                            {
                                $_aliasName -in $exportedAliases |
                                Should Be $true
                            }
                        }

                    } # foreach ( $functionInfo in Get-Command -Module $moduleName -CommandType Function )

                } # Context 'All [Alias()] defined in functions are exported' `

            } # if  ( '*' -notin [string[]]$script:moduleManifest.AliasesToExport )


            Context 'Files listed in FileList exist' `
            {
                foreach ( $subPath in $script:moduleManifest.FileList )
                {
                    It "$subPath exists" `
                    {
                        Test-Path -Path "$PSScriptRoot\$subPath" |
                        Should Be $true
                    }
                }
            }


            Context 'All files are listed in FileList' `
            {
                [string]$psScriptRootRegEx = $PSScriptRoot -replace '(\W)', "\`$1"

                [string[]]$childItemList = (
                    Get-ChildItem -Recurse -File -Path $PSScriptRoot |
                    Select-Object -ExpandProperty FullName 
                ) -replace "^$psScriptRootRegEx\\"

                foreach ( $subpath in $childItemList )
                {
                    if ( $subpath -in $script:testSettings.IgnoreFile)
                    {
                        Write-Verbose -Message "$subpath found in IgnoreFile, skipping."
                        continue
                    }
                    
                    $folder = Split-Path -Path $subpath -Parent

                    if ( $folder -in $script:testSettings.IgnoreFolder )
                    {
                        Write-Verbose -Message "$subpath found in IgnoreFolder, skipping."
                        continue
                    }

                    $extension = $subpath -replace '.*\.'

                    if ( $extension -in $script:testSettings.IgnoreExtension )
                    {
                        Write-Verbose -Message "$subpath found in IgnoreExtension, skipping."
                        continue
                    }

                    if ( $script:testSettings.ContainsKey( 'IgnorePattern' ) )
                    {
                        $continue = $false

                        foreach ( $pattern in $script:testSettings.IgnorePattern )
                        {
                            if ( $subpath -match $pattern )
                            {
                                Write-Verbose -Message "$subpath matched by '$pattern' in IgnorePattern, skipping."
                                $continue = $true
                                break
                            }
                        }

                        if ( $continue )
                        {
                            continue
                        }
                    }

                    It "$subpath is in FileList" `
                    {
                        $subPath -in $script:moduleManifest.FileList |
                        Should Be $true
                    }

                } # foreach ( $subpath in $childItemList )

            } # Context 'All files are listed in FileList'

        } # Describe "$moduleName.psd1"

    } # try

    catch
    {

        Write-Warning -Message "$basename hit exception:"
        $_ |
        Write-Warning
        return

    }
}

end
{
    try
    {
        if ( $script:moduleManifest.Keys.Count -eq 0 )
        {
            return
        }
    }

    finally
    {
        Write-Verbose -Message "$basename finished."
    }

}


# SIG # Begin signature block
# MIIcXgYJKoZIhvcNAQcCoIIcTzCCHEsCAQExCzAJBgUrDgMCGgUAMGkGCisGAQQB
# gjcCAQSgWzBZMDQGCisGAQQBgjcCAR4wJgIDAQAABBAfzDtgWUsITrck0sYpfvNR
# AgEAAgEAAgEAAgEAAgEAMCEwCQYFKw4DAhoFAAQUKCmSfd7EOJ82lROdw1R5Xef6
# 3I+ggheNMIIFFjCCA/6gAwIBAgIQBvCMmhZtT5VpGdBVvL78DzANBgkqhkiG9w0B
# AQsFADByMQswCQYDVQQGEwJVUzEVMBMGA1UEChMMRGlnaUNlcnQgSW5jMRkwFwYD
# VQQLExB3d3cuZGlnaWNlcnQuY29tMTEwLwYDVQQDEyhEaWdpQ2VydCBTSEEyIEFz
# c3VyZWQgSUQgQ29kZSBTaWduaW5nIENBMB4XDTE4MDgyOTAwMDAwMFoXDTIwMDEw
# MzEyMDAwMFowUzELMAkGA1UEBhMCVVMxCzAJBgNVBAgTAldBMREwDwYDVQQHEwhC
# ZWxsZXZ1ZTERMA8GA1UEChMIVGltIER1bm4xETAPBgNVBAMTCFRpbSBEdW5uMIIB
# IjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA1agFn56KigoW66r4WrzLD/ih
# f6SozX/XGXcQDXv4Ru5lba+L98p6m5AsfnSKTR4iJvT5pA4gZH+UyVuuxxKHXcnk
# pNUnEFhpumgkyCmP2dMDbBKxuyMT6jR/WsHar5IugW5+G/nBmwB9QCB805f4SQmB
# ob1gq8w+WAsNbY8yGIKSP4zKV5pB/5skTEv6UNkR58eZPOAI+3xqBo609RDSIHCt
# bYzSOPyKdo6iUy0NWN1vjEZ/X0RlTopM4FbBmVxdH1PeLqnGa5cw2BltgGPC+AEl
# wHxgLkRokcnEPiV7e79aqQtLne5yB6rnpGG2Q+/W22y4axep3AkuJ/vMVI5hyQID
# AQABo4IBxTCCAcEwHwYDVR0jBBgwFoAUWsS5eyoKo6XqcQPAYPkt9mV1DlgwHQYD
# VR0OBBYEFNHVUCqbfCNHU/OhZt+SjDkK5TpdMA4GA1UdDwEB/wQEAwIHgDATBgNV
# HSUEDDAKBggrBgEFBQcDAzB3BgNVHR8EcDBuMDWgM6Axhi9odHRwOi8vY3JsMy5k
# aWdpY2VydC5jb20vc2hhMi1hc3N1cmVkLWNzLWcxLmNybDA1oDOgMYYvaHR0cDov
# L2NybDQuZGlnaWNlcnQuY29tL3NoYTItYXNzdXJlZC1jcy1nMS5jcmwwTAYDVR0g
# BEUwQzA3BglghkgBhv1sAwEwKjAoBggrBgEFBQcCARYcaHR0cHM6Ly93d3cuZGln
# aWNlcnQuY29tL0NQUzAIBgZngQwBBAEwgYQGCCsGAQUFBwEBBHgwdjAkBggrBgEF
# BQcwAYYYaHR0cDovL29jc3AuZGlnaWNlcnQuY29tME4GCCsGAQUFBzAChkJodHRw
# Oi8vY2FjZXJ0cy5kaWdpY2VydC5jb20vRGlnaUNlcnRTSEEyQXNzdXJlZElEQ29k
# ZVNpZ25pbmdDQS5jcnQwDAYDVR0TAQH/BAIwADANBgkqhkiG9w0BAQsFAAOCAQEA
# NsxgWz7VOX7L8oJr7U1utb+FdoIfVerJG11LezE7YWj2vJZIoT038DghGQoSacbm
# An3WzRL60tXAeb6H6GDQqnYMgdUyNPJroRCv7F5TgR1xZIk18xC5kFgoDLTLWa5n
# IuN/AjO4uzp3QR9xxEDljYOaNEa8mZ6JrKzrYtxuIsk6ifTjAmPV18Q+JSM8U+S5
# emUoF/4PK8FAfO0XUvYQzU9PkBoFv+w8WV2en3SuWQKemzlq7ma9k/kflLS9mChS
# RdRoWNx+ngCcw3BTgiOqz1KV50YkqPR1dyNnSv5B+E7CVu9CN2x+6MO/BgVlkOBo
# abV0eqp5RzJPKgimDztMHDCCBTAwggQYoAMCAQICEAQJGBtf1btmdVNDtW+VUAgw
# DQYJKoZIhvcNAQELBQAwZTELMAkGA1UEBhMCVVMxFTATBgNVBAoTDERpZ2lDZXJ0
# IEluYzEZMBcGA1UECxMQd3d3LmRpZ2ljZXJ0LmNvbTEkMCIGA1UEAxMbRGlnaUNl
# cnQgQXNzdXJlZCBJRCBSb290IENBMB4XDTEzMTAyMjEyMDAwMFoXDTI4MTAyMjEy
# MDAwMFowcjELMAkGA1UEBhMCVVMxFTATBgNVBAoTDERpZ2lDZXJ0IEluYzEZMBcG
# A1UECxMQd3d3LmRpZ2ljZXJ0LmNvbTExMC8GA1UEAxMoRGlnaUNlcnQgU0hBMiBB
# c3N1cmVkIElEIENvZGUgU2lnbmluZyBDQTCCASIwDQYJKoZIhvcNAQEBBQADggEP
# ADCCAQoCggEBAPjTsxx/DhGvZ3cH0wsxSRnP0PtFmbE620T1f+Wondsy13Hqdp0F
# LreP+pJDwKX5idQ3Gde2qvCchqXYJawOeSg6funRZ9PG+yknx9N7I5TkkSOWkHeC
# +aGEI2YSVDNQdLEoJrskacLCUvIUZ4qJRdQtoaPpiCwgla4cSocI3wz14k1gGL6q
# xLKucDFmM3E+rHCiq85/6XzLkqHlOzEcz+ryCuRXu0q16XTmK/5sy350OTYNkO/k
# tU6kqepqCquE86xnTrXE94zRICUj6whkPlKWwfIPEvTFjg/BougsUfdzvL2FsWKD
# c0GCB+Q4i2pzINAPZHM8np+mM6n9Gd8lk9ECAwEAAaOCAc0wggHJMBIGA1UdEwEB
# /wQIMAYBAf8CAQAwDgYDVR0PAQH/BAQDAgGGMBMGA1UdJQQMMAoGCCsGAQUFBwMD
# MHkGCCsGAQUFBwEBBG0wazAkBggrBgEFBQcwAYYYaHR0cDovL29jc3AuZGlnaWNl
# cnQuY29tMEMGCCsGAQUFBzAChjdodHRwOi8vY2FjZXJ0cy5kaWdpY2VydC5jb20v
# RGlnaUNlcnRBc3N1cmVkSURSb290Q0EuY3J0MIGBBgNVHR8EejB4MDqgOKA2hjRo
# dHRwOi8vY3JsNC5kaWdpY2VydC5jb20vRGlnaUNlcnRBc3N1cmVkSURSb290Q0Eu
# Y3JsMDqgOKA2hjRodHRwOi8vY3JsMy5kaWdpY2VydC5jb20vRGlnaUNlcnRBc3N1
# cmVkSURSb290Q0EuY3JsME8GA1UdIARIMEYwOAYKYIZIAYb9bAACBDAqMCgGCCsG
# AQUFBwIBFhxodHRwczovL3d3dy5kaWdpY2VydC5jb20vQ1BTMAoGCGCGSAGG/WwD
# MB0GA1UdDgQWBBRaxLl7KgqjpepxA8Bg+S32ZXUOWDAfBgNVHSMEGDAWgBRF66Kv
# 9JLLgjEtUYunpyGd823IDzANBgkqhkiG9w0BAQsFAAOCAQEAPuwNWiSz8yLRFcgs
# fCUpdqgdXRwtOhrE7zBh134LYP3DPQ/Er4v97yrfIFU3sOH20ZJ1D1G0bqWOWuJe
# JIFOEKTuP3GOYw4TS63XX0R58zYUBor3nEZOXP+QsRsHDpEV+7qvtVHCjSSuJMbH
# JyqhKSgaOnEoAjwukaPAJRHinBRHoXpoaK+bp1wgXNlxsQyPu6j4xRJon89Ay0BE
# pRPw5mQMJQhCMrI2iiQC/i9yfhzXSUWW6Fkd6fp0ZGuy62ZD2rOwjNXpDd32ASDO
# mTFjPQgaGLOBm0/GkxAG/AeB+ova+YJJ92JuoVP6EpQYhS6SkepobEQysmah5xik
# mmRR7zCCBmowggVSoAMCAQICEAMBmgI6/1ixa9bV6uYX8GYwDQYJKoZIhvcNAQEF
# BQAwYjELMAkGA1UEBhMCVVMxFTATBgNVBAoTDERpZ2lDZXJ0IEluYzEZMBcGA1UE
# CxMQd3d3LmRpZ2ljZXJ0LmNvbTEhMB8GA1UEAxMYRGlnaUNlcnQgQXNzdXJlZCBJ
# RCBDQS0xMB4XDTE0MTAyMjAwMDAwMFoXDTI0MTAyMjAwMDAwMFowRzELMAkGA1UE
# BhMCVVMxETAPBgNVBAoTCERpZ2lDZXJ0MSUwIwYDVQQDExxEaWdpQ2VydCBUaW1l
# c3RhbXAgUmVzcG9uZGVyMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA
# o2Rd/Hyz4II14OD2xirmSXU7zG7gU6mfH2RZ5nxrf2uMnVX4kuOe1VpjWwJJUNmD
# zm9m7t3LhelfpfnUh3SIRDsZyeX1kZ/GFDmsJOqoSyyRicxeKPRktlC39RKzc5YK
# Z6O+YZ+u8/0SeHUOplsU/UUjjoZEVX0YhgWMVYd5SEb3yg6Np95OX+Koti1ZAmGI
# YXIYaLm4fO7m5zQvMXeBMB+7NgGN7yfj95rwTDFkjePr+hmHqH7P7IwMNlt6wXq4
# eMfJBi5GEMiN6ARg27xzdPpO2P6qQPGyznBGg+naQKFZOtkVCVeZVjCT88lhzNAI
# zGvsYkKRrALA76TwiRGPdwIDAQABo4IDNTCCAzEwDgYDVR0PAQH/BAQDAgeAMAwG
# A1UdEwEB/wQCMAAwFgYDVR0lAQH/BAwwCgYIKwYBBQUHAwgwggG/BgNVHSAEggG2
# MIIBsjCCAaEGCWCGSAGG/WwHATCCAZIwKAYIKwYBBQUHAgEWHGh0dHBzOi8vd3d3
# LmRpZ2ljZXJ0LmNvbS9DUFMwggFkBggrBgEFBQcCAjCCAVYeggFSAEEAbgB5ACAA
# dQBzAGUAIABvAGYAIAB0AGgAaQBzACAAQwBlAHIAdABpAGYAaQBjAGEAdABlACAA
# YwBvAG4AcwB0AGkAdAB1AHQAZQBzACAAYQBjAGMAZQBwAHQAYQBuAGMAZQAgAG8A
# ZgAgAHQAaABlACAARABpAGcAaQBDAGUAcgB0ACAAQwBQAC8AQwBQAFMAIABhAG4A
# ZAAgAHQAaABlACAAUgBlAGwAeQBpAG4AZwAgAFAAYQByAHQAeQAgAEEAZwByAGUA
# ZQBtAGUAbgB0ACAAdwBoAGkAYwBoACAAbABpAG0AaQB0ACAAbABpAGEAYgBpAGwA
# aQB0AHkAIABhAG4AZAAgAGEAcgBlACAAaQBuAGMAbwByAHAAbwByAGEAdABlAGQA
# IABoAGUAcgBlAGkAbgAgAGIAeQAgAHIAZQBmAGUAcgBlAG4AYwBlAC4wCwYJYIZI
# AYb9bAMVMB8GA1UdIwQYMBaAFBUAEisTmLKZB+0e36K+Vw0rZwLNMB0GA1UdDgQW
# BBRhWk0ktkkynUoqeRqDS/QeicHKfTB9BgNVHR8EdjB0MDigNqA0hjJodHRwOi8v
# Y3JsMy5kaWdpY2VydC5jb20vRGlnaUNlcnRBc3N1cmVkSURDQS0xLmNybDA4oDag
# NIYyaHR0cDovL2NybDQuZGlnaWNlcnQuY29tL0RpZ2lDZXJ0QXNzdXJlZElEQ0Et
# MS5jcmwwdwYIKwYBBQUHAQEEazBpMCQGCCsGAQUFBzABhhhodHRwOi8vb2NzcC5k
# aWdpY2VydC5jb20wQQYIKwYBBQUHMAKGNWh0dHA6Ly9jYWNlcnRzLmRpZ2ljZXJ0
# LmNvbS9EaWdpQ2VydEFzc3VyZWRJRENBLTEuY3J0MA0GCSqGSIb3DQEBBQUAA4IB
# AQCdJX4bM02yJoFcm4bOIyAPgIfliP//sdRqLDHtOhcZcRfNqRu8WhY5AJ3jbITk
# WkD73gYBjDf6m7GdJH7+IKRXrVu3mrBgJuppVyFdNC8fcbCDlBkFazWQEKB7l8f2
# P+fiEUGmvWLZ8Cc9OB0obzpSCfDscGLTYkuw4HOmksDTjjHYL+NtFxMG7uQDthSr
# 849Dp3GdId0UyhVdkkHa+Q+B0Zl0DSbEDn8btfWg8cZ3BigV6diT5VUW8LsKqxzb
# XEgnZsijiwoc5ZXarsQuWaBh3drzbaJh6YoLbewSGL33VVRAA5Ira8JRwgpIr7DU
# buD0FAo6G+OPPcqvao173NhEMIIGzTCCBbWgAwIBAgIQBv35A5YDreoACus/J7u6
# GzANBgkqhkiG9w0BAQUFADBlMQswCQYDVQQGEwJVUzEVMBMGA1UEChMMRGlnaUNl
# cnQgSW5jMRkwFwYDVQQLExB3d3cuZGlnaWNlcnQuY29tMSQwIgYDVQQDExtEaWdp
# Q2VydCBBc3N1cmVkIElEIFJvb3QgQ0EwHhcNMDYxMTEwMDAwMDAwWhcNMjExMTEw
# MDAwMDAwWjBiMQswCQYDVQQGEwJVUzEVMBMGA1UEChMMRGlnaUNlcnQgSW5jMRkw
# FwYDVQQLExB3d3cuZGlnaWNlcnQuY29tMSEwHwYDVQQDExhEaWdpQ2VydCBBc3N1
# cmVkIElEIENBLTEwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQDogi2Z
# +crCQpWlgHNAcNKeVlRcqcTSQQaPyTP8TUWRXIGf7Syc+BZZ3561JBXCmLm0d0nc
# icQK2q/LXmvtrbBxMevPOkAMRk2T7It6NggDqww0/hhJgv7HxzFIgHweog+SDlDJ
# xofrNj/YMMP/pvf7os1vcyP+rFYFkPAyIRaJxnCI+QWXfaPHQ90C6Ds97bFBo+0/
# vtuVSMTuHrPyvAwrmdDGXRJCgeGDboJzPyZLFJCuWWYKxI2+0s4Grq2Eb0iEm09A
# ufFM8q+Y+/bOQF1c9qjxL6/siSLyaxhlscFzrdfx2M8eCnRcQrhofrfVdwonVnwP
# YqQ/MhRglf0HBKIJAgMBAAGjggN6MIIDdjAOBgNVHQ8BAf8EBAMCAYYwOwYDVR0l
# BDQwMgYIKwYBBQUHAwEGCCsGAQUFBwMCBggrBgEFBQcDAwYIKwYBBQUHAwQGCCsG
# AQUFBwMIMIIB0gYDVR0gBIIByTCCAcUwggG0BgpghkgBhv1sAAEEMIIBpDA6Bggr
# BgEFBQcCARYuaHR0cDovL3d3dy5kaWdpY2VydC5jb20vc3NsLWNwcy1yZXBvc2l0
# b3J5Lmh0bTCCAWQGCCsGAQUFBwICMIIBVh6CAVIAQQBuAHkAIAB1AHMAZQAgAG8A
# ZgAgAHQAaABpAHMAIABDAGUAcgB0AGkAZgBpAGMAYQB0AGUAIABjAG8AbgBzAHQA
# aQB0AHUAdABlAHMAIABhAGMAYwBlAHAAdABhAG4AYwBlACAAbwBmACAAdABoAGUA
# IABEAGkAZwBpAEMAZQByAHQAIABDAFAALwBDAFAAUwAgAGEAbgBkACAAdABoAGUA
# IABSAGUAbAB5AGkAbgBnACAAUABhAHIAdAB5ACAAQQBnAHIAZQBlAG0AZQBuAHQA
# IAB3AGgAaQBjAGgAIABsAGkAbQBpAHQAIABsAGkAYQBiAGkAbABpAHQAeQAgAGEA
# bgBkACAAYQByAGUAIABpAG4AYwBvAHIAcABvAHIAYQB0AGUAZAAgAGgAZQByAGUA
# aQBuACAAYgB5ACAAcgBlAGYAZQByAGUAbgBjAGUALjALBglghkgBhv1sAxUwEgYD
# VR0TAQH/BAgwBgEB/wIBADB5BggrBgEFBQcBAQRtMGswJAYIKwYBBQUHMAGGGGh0
# dHA6Ly9vY3NwLmRpZ2ljZXJ0LmNvbTBDBggrBgEFBQcwAoY3aHR0cDovL2NhY2Vy
# dHMuZGlnaWNlcnQuY29tL0RpZ2lDZXJ0QXNzdXJlZElEUm9vdENBLmNydDCBgQYD
# VR0fBHoweDA6oDigNoY0aHR0cDovL2NybDMuZGlnaWNlcnQuY29tL0RpZ2lDZXJ0
# QXNzdXJlZElEUm9vdENBLmNybDA6oDigNoY0aHR0cDovL2NybDQuZGlnaWNlcnQu
# Y29tL0RpZ2lDZXJ0QXNzdXJlZElEUm9vdENBLmNybDAdBgNVHQ4EFgQUFQASKxOY
# spkH7R7for5XDStnAs0wHwYDVR0jBBgwFoAUReuir/SSy4IxLVGLp6chnfNtyA8w
# DQYJKoZIhvcNAQEFBQADggEBAEZQPsm3KCSnOB22WymvUs9S6TFHq1Zce9UNC0Gz
# 7+x1H3Q48rJcYaKclcNQ5IK5I9G6OoZyrTh4rHVdFxc0ckeFlFbR67s2hHfMJKXz
# BBlVqefj56tizfuLLZDCwNK1lL1eT7EF0g49GqkUW6aGMWKoqDPkmzmnxPXOHXh2
# lCVz5Cqrz5x2S+1fwksW5EtwTACJHvzFebxMElf+X+EevAJdqP77BzhPDcZdkbkP
# Z0XN1oPt55INjbFpjE/7WeAjD9KqrgB87pxCDs+R1ye3Fu4Pw718CqDuLAhVhSK4
# 6xgaTfwqIa1JMYNHlXdx3LEbS0scEJx3FMGdTy9alQgpECYxggQ7MIIENwIBATCB
# hjByMQswCQYDVQQGEwJVUzEVMBMGA1UEChMMRGlnaUNlcnQgSW5jMRkwFwYDVQQL
# ExB3d3cuZGlnaWNlcnQuY29tMTEwLwYDVQQDEyhEaWdpQ2VydCBTSEEyIEFzc3Vy
# ZWQgSUQgQ29kZSBTaWduaW5nIENBAhAG8IyaFm1PlWkZ0FW8vvwPMAkGBSsOAwIa
# BQCgeDAYBgorBgEEAYI3AgEMMQowCKACgAChAoAAMBkGCSqGSIb3DQEJAzEMBgor
# BgEEAYI3AgEEMBwGCisGAQQBgjcCAQsxDjAMBgorBgEEAYI3AgEVMCMGCSqGSIb3
# DQEJBDEWBBTV3wX6IWkSeqoN3xAG8l1/Nh5AQDANBgkqhkiG9w0BAQEFAASCAQCO
# BSnZXM7jDRlpwAZywxjqRF/cB2Xf/4i1ju04zP9fc9tdOWEDhAjD52q9kBTVQP/Y
# bwg8RuhVgi4r/wc1VAeHnLj53jW9xIL3Fz6kiJeQ5fYNRSjCx9CPm+ItCi0RXHRj
# sBEzL9DhPk+Q3zdWjfjuKTIcsUehsQmgxYbRQdOytSNTHEUqY5to2FRXQ3hFeqYG
# m3LgODszBB6OLUaAallaC7CMbczNQrKy4l7X41mtQe3kpkso/rT4n5DpuYKKVCvt
# QvtrKZScXK5u1kdTyPFIcYzTIjwaJ9w/xAldh6OuBPReEU092NKQ1T9YSToRpCFv
# 3SDp3BJstS+Dcq34oedQoYICDzCCAgsGCSqGSIb3DQEJBjGCAfwwggH4AgEBMHYw
# YjELMAkGA1UEBhMCVVMxFTATBgNVBAoTDERpZ2lDZXJ0IEluYzEZMBcGA1UECxMQ
# d3d3LmRpZ2ljZXJ0LmNvbTEhMB8GA1UEAxMYRGlnaUNlcnQgQXNzdXJlZCBJRCBD
# QS0xAhADAZoCOv9YsWvW1ermF/BmMAkGBSsOAwIaBQCgXTAYBgkqhkiG9w0BCQMx
# CwYJKoZIhvcNAQcBMBwGCSqGSIb3DQEJBTEPFw0xODA5MTQwMjEzNTdaMCMGCSqG
# SIb3DQEJBDEWBBSBZT6VIIRhmaUppG8YyQ0KWQB50jANBgkqhkiG9w0BAQEFAASC
# AQBWWuKffUcxiXeSzRWCk/kTop/FDz4qBS7lzVM5I5CGbmPi9uMXqwr4xGYuDXub
# UyXbb1mazxOaSoFwoLj7+ds5ExWJ03UhnQdSwHHa9CzcLuXitm6r+kdm66FZQ5gv
# SIxMDJAPQSdGkJb/UlvN9yOJACcyGrHFDOoblwobSlNTNpCOoQsxVtdo/XL2xvvq
# 3hknHqK4Am99noYt2avRm4loIuXPqcQTokz2rhpm4n8jNJ9Ms6fQvXM2NeW4pN65
# 8PJCY9nyS1zP1r4WQF+T1zYsdI03Tb7DgYL4C7UP1xnRlI3CsabNqPFqT1n7RX9d
# OZDPC6jYK8uLRAf8bHgjWm+d
# SIG # End signature block
