# This script looks for memebers of protected groups that dont have admincount=1

Param(
    [Parameter(Mandatory=$True)][String]$ForestName,
    [Parameter(Mandatory=$True)][String[]]$DomainNames
)

Import-Module -Name Semperis-Lib

$outputObjects = @()
try {
    $res = New-Object Semperis.PSSecurityIndicatorResult.SecurityIndicatorResult
    $builtinPrivilegedGroups = @("S-1-5-32-551","S-1-5-32-552","S-1-5-32-548","S-1-5-32-549","S-1-5-32-550","S-1-5-32-544")
    $privilegedGroups = @("512","516","526","521")
    $forestPrivilegedGroups = @("519","527","518")

    $forestDN = Get-DN $ForestName
    $privilegedGroupsDN = [System.Collections.ArrayList]@()
    $forestSID = Get-DomainSID $ForestName

    $failedGroup = @()
    $failedAdmin = @()

    # Get a list of the forest groups DN
    foreach ($groupRID in $forestPrivilegedGroups) {
        $forestGroupObject = Search-AD $ForestName "" $forestDN "subtree" "(&(objectSid=$forestSID-$groupRID)(objectCategory=group))" 1000
        if ($forestGroupObject) {
            [void]$privilegedGroupsDN.add($forestGroupObject.DistinguishedName)
        }
    }

    foreach ($domain in $DomainNames) {
        $DN = Get-DN $domain
        $domainSID = Get-DomainSID $domain

        # Get a list of the groups DN
        foreach ($groupRID in $privilegedGroups) {
            $groupObject = Search-AD $domain "" $DN "subtree" "(&(objectSid=$domainSID-$groupRID)(objectCategory=group))" 1000
            if ($groupObject) {
                [void]$privilegedGroupsDN.add($groupObject.DistinguishedName)
            }
        }

        # Get a list of the groups DN
        foreach ($sid in $builtinPrivilegedGroups) {
            $groupObject = Search-AD $domain "" $DN "subtree" "(&(objectSid=$sid)(objectCategory=group))" 1000
            if ($groupObject) {
                [void]$privilegedGroupsDN.add($groupObject.DistinguishedName)
            }
        }

    }

    # Get all admins
    $admins = @()
    foreach($groupDN in $privilegedGroupsDN) {
        try {
            $groupMembers = Search-AD -dnsDomain $domain -attributes "msds-membertransitive" -baseDN $groupDN -scope "base" `
                -filter "distinguishedname=$groupDN"
            if ($groupMembers.Attributes."msds-membertransitive;range=0-4499") {
                throw "More than 4500 members are in the $groupDN privileged group. This indicator supports a maximum of 4500 members per group. A secure environment should not have such a high number of members in a privileged group, it is recommended to review this group and re-run this indicator"
            }
            if (!($groupMembers.Attributes."msds-membertransitive"[0])) {
                continue
            }
            foreach ($adminDN in $groupMembers.Attributes.'msds-membertransitive'.GetValues("string")) {
                if ($admins.Contains($adminDN)) {
                    continue
                }
                $admins += ($adminDN)
                try {
                    $testAdminCount = Search-AD -dnsDomain $ForestName -attributes "" -baseDN $adminDN -scope "base" -filter "admincount=1"
                    if ($testAdminCount) {
                        continue
                    }
                    $thisOutput = new-object psobject -Property @{
                        DistinguishedName = $adminDN
                    }
                    $outputObjects += $thisOutput
                }
                catch {
                    $failedAdmin += $adminDN
                }
            }
        }
        catch {
            $failedGroup += $groupDN
        }
    }

    # Calculate score
    if ($admins.Count) {
        $res.Score = 100 - (($outputObjects.Count / $admins.Count) * 100)
    }
    else {
        throw "Exception: Could not enumerate admins"
    }

    # Count is the number of domains that failed the test
    if ($res.Score -ne 100) {
        $res.ResultObjects = $outputObjects
        $res.ResultMessage = "Found $($outputObjects.Count) privileged users that do not have adminCount equal to 1."
        $res.Remediation = "Check why those objects do not have admintCount=1 and set the attribute to 1."
        $res.Status = [Semperis.PSSecurityIndicatorResult.ScriptStatus]"Failed"
    }
    else {
        $res.ResultMessage = "No evidence of exposure"
        $res.Remediation = "None"
        $res.Status = [Semperis.PSSecurityIndicatorResult.ScriptStatus]"Pass"
    }
    if($failedAdmin) {
        $res.ResultMessage += " Failed to find: $($failedAdmin -join '; ')."
    }
    if($failedGroup) {
        $res.ResultMessage += " Failed to enumerate: $($failedGroup -join '; ')."
    }
}
catch [System.Exception] {
    $res.Status = [Semperis.PSSecurityIndicatorResult.ScriptStatus]"Error"
    $res.ResultMessage = $_.Exception.Message
    $res.Remediation = "None"
}
return $res
# SIG # Begin signature block
# MIIY1gYJKoZIhvcNAQcCoIIYxzCCGMMCAQExDzANBglghkgBZQMEAgEFADB5Bgor
# BgEEAYI3AgEEoGswaTA0BgorBgEEAYI3AgEeMCYCAwEAAAQQH8w7YFlLCE63JNLG
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCDHdfRxZ5PF78hy
# qYnrQqghdeEV1zmdxlfniJpg0o1/NqCCE+UwggSUMIIDfKADAgECAg5IG2oHJtLo
# PyYC1IJazTANBgkqhkiG9w0BAQsFADBMMSAwHgYDVQQLExdHbG9iYWxTaWduIFJv
# b3QgQ0EgLSBSMzETMBEGA1UEChMKR2xvYmFsU2lnbjETMBEGA1UEAxMKR2xvYmFs
# U2lnbjAeFw0xNjA2MTUwMDAwMDBaFw0yNDA2MTUwMDAwMDBaMFoxCzAJBgNVBAYT
# AkJFMRkwFwYDVQQKExBHbG9iYWxTaWduIG52LXNhMTAwLgYDVQQDEydHbG9iYWxT
# aWduIENvZGVTaWduaW5nIENBIC0gU0hBMjU2IC0gRzMwggEiMA0GCSqGSIb3DQEB
# AQUAA4IBDwAwggEKAoIBAQCNhVUjqR9Tr8ntNsIptW7Y+UL1IYuH8EOhL8A/l+MY
# R9SWToirxmPptkkVhfHZm3sb/dhKzG1OhkAXzXu6Ryi11hRADIbuHksz8yxV7iGM
# 2rbB/rBOOq5Rn6UU4xDmk8r6+V2xkIfv+DUt/KJcJu57FYsf2cOhlzVBszD9chOt
# kZc6znKdBgp1PB+Y48sYL4yfCEqRCtnZNdmDknZiXt+DruTWAU7M8zxwYVg3HxTj
# aqCva/TZ0mwsGTBdoG9S39GcyeAN2XURZZbZQ7SnkDmuRxxUy7GVbiXejvESHPDX
# bucUTbMaZdaESlfuBK9iOMUQm0OOUrg+tq6eLJf/jnTvAgMBAAGjggFkMIIBYDAO
# BgNVHQ8BAf8EBAMCAQYwHQYDVR0lBBYwFAYIKwYBBQUHAwMGCCsGAQUFBwMJMBIG
# A1UdEwEB/wQIMAYBAf8CAQAwHQYDVR0OBBYEFA8656yUkXQtlgJzg62cLkk/GapU
# MB8GA1UdIwQYMBaAFI/wS3+oLkUkrk1Q+mOai97i3Ru8MD4GCCsGAQUFBwEBBDIw
# MDAuBggrBgEFBQcwAYYiaHR0cDovL29jc3AyLmdsb2JhbHNpZ24uY29tL3Jvb3Ry
# MzA2BgNVHR8ELzAtMCugKaAnhiVodHRwOi8vY3JsLmdsb2JhbHNpZ24uY29tL3Jv
# b3QtcjMuY3JsMGMGA1UdIARcMFowCwYJKwYBBAGgMgEyMAgGBmeBDAEEATBBBgkr
# BgEEAaAyAV8wNDAyBggrBgEFBQcCARYmaHR0cHM6Ly93d3cuZ2xvYmFsc2lnbi5j
# b20vcmVwb3NpdG9yeS8wDQYJKoZIhvcNAQELBQADggEBABWEKAztocMZgttjJ0HX
# zGN91rzPNpvP0l1MAotYGhYIerGYmX/YM4pcnmIKmuqQwsVjBAvoh1gGAAeCWcOo
# lDLZ4BRNoNUj4MfduvBp4kpFZS1NSZB4ZjIOsGjAsIiwju1cBvhcEEg/I3O6O1OE
# UoDN8LMVyBEKiwV4RlkI1L63/0v1nGpMnHaiEYVFjNQ37lDd4TM0qaEfOgvxVkSK
# b7Mz0LGO0QxgB+4ywvAkb7+v+4EBdmfEo+jgq9wzVSjjZ0c862qk35Tp9KbAgdFS
# mFGm1gK3POpK79C6ZdI3g1NLfmd8jED2BxywrwQG3PhsRohynOtOncOwuVSjuU6X
# yhQwggT+MIID5qADAgECAhANQkrgvjqI/2BAIc4UAPDdMA0GCSqGSIb3DQEBCwUA
# MHIxCzAJBgNVBAYTAlVTMRUwEwYDVQQKEwxEaWdpQ2VydCBJbmMxGTAXBgNVBAsT
# EHd3dy5kaWdpY2VydC5jb20xMTAvBgNVBAMTKERpZ2lDZXJ0IFNIQTIgQXNzdXJl
# ZCBJRCBUaW1lc3RhbXBpbmcgQ0EwHhcNMjEwMTAxMDAwMDAwWhcNMzEwMTA2MDAw
# MDAwWjBIMQswCQYDVQQGEwJVUzEXMBUGA1UEChMORGlnaUNlcnQsIEluYy4xIDAe
# BgNVBAMTF0RpZ2lDZXJ0IFRpbWVzdGFtcCAyMDIxMIIBIjANBgkqhkiG9w0BAQEF
# AAOCAQ8AMIIBCgKCAQEAwuZhhGfFivUNCKRFymNrUdc6EUK9CnV1TZS0DFC1JhD+
# HchvkWsMlucaXEjvROW/m2HNFZFiWrj/ZwucY/02aoH6KfjdK3CF3gIY83htvH35
# x20JPb5qdofpir34hF0edsnkxnZ2OlPR0dNaNo/Go+EvGzq3YdZz7E5tM4p8XUUt
# S7FQ5kE6N1aG3JMjjfdQJehk5t3Tjy9XtYcg6w6OLNUj2vRNeEbjA4MxKUpcDDGK
# SoyIxfcwWvkUrxVfbENJCf0mI1P2jWPoGqtbsR0wwptpgrTb/FZUvB+hh6u+elsK
# IC9LCcmVp42y+tZji06lchzun3oBc/gZ1v4NSYS9AQIDAQABo4IBuDCCAbQwDgYD
# VR0PAQH/BAQDAgeAMAwGA1UdEwEB/wQCMAAwFgYDVR0lAQH/BAwwCgYIKwYBBQUH
# AwgwQQYDVR0gBDowODA2BglghkgBhv1sBwEwKTAnBggrBgEFBQcCARYbaHR0cDov
# L3d3dy5kaWdpY2VydC5jb20vQ1BTMB8GA1UdIwQYMBaAFPS24SAd/imu0uRhpbKi
# JbLIFzVuMB0GA1UdDgQWBBQ2RIaOpLqwZr68KC0dRDbd42p6vDBxBgNVHR8EajBo
# MDKgMKAuhixodHRwOi8vY3JsMy5kaWdpY2VydC5jb20vc2hhMi1hc3N1cmVkLXRz
# LmNybDAyoDCgLoYsaHR0cDovL2NybDQuZGlnaWNlcnQuY29tL3NoYTItYXNzdXJl
# ZC10cy5jcmwwgYUGCCsGAQUFBwEBBHkwdzAkBggrBgEFBQcwAYYYaHR0cDovL29j
# c3AuZGlnaWNlcnQuY29tME8GCCsGAQUFBzAChkNodHRwOi8vY2FjZXJ0cy5kaWdp
# Y2VydC5jb20vRGlnaUNlcnRTSEEyQXNzdXJlZElEVGltZXN0YW1waW5nQ0EuY3J0
# MA0GCSqGSIb3DQEBCwUAA4IBAQBIHNy16ZojvOca5yAOjmdG/UJyUXQKI0ejq5LS
# JcRwWb4UoOUngaVNFBUZB3nw0QTDhtk7vf5EAmZN7WmkD/a4cM9i6PVRSnh5Nnon
# t/PnUp+Tp+1DnnvntN1BIon7h6JGA0789P63ZHdjXyNSaYOC+hpT7ZDMjaEXcw30
# 82U5cEvznNZ6e9oMvD0y0BvL9WH8dQgAdryBDvjA4VzPxBFy5xtkSdgimnUVQvUt
# MjiB2vRgorq0Uvtc4GEkJU+y38kpqHNDUdq9Y9YfW5v3LhtPEx33Sg1xfpe39D+E
# 68Hjo0mh+s6nv1bPull2YYlffqe0jmd4+TaY4cso2luHpoovMIIFEjCCA/qgAwIB
# AgIMFXW337x5IagTcYjJMA0GCSqGSIb3DQEBCwUAMFoxCzAJBgNVBAYTAkJFMRkw
# FwYDVQQKExBHbG9iYWxTaWduIG52LXNhMTAwLgYDVQQDEydHbG9iYWxTaWduIENv
# ZGVTaWduaW5nIENBIC0gU0hBMjU2IC0gRzMwHhcNMjAwNTE0MTQzMDQ0WhcNMjIw
# NTE1MTQzMDQ0WjCBizELMAkGA1UEBhMCVVMxETAPBgNVBAgTCE5ldyBZb3JrMREw
# DwYDVQQHEwhOZXcgWW9yazEXMBUGA1UEChMOU2VtcGVyaXMsIEluYy4xFzAVBgNV
# BAMTDlNlbXBlcmlzLCBJbmMuMSQwIgYJKoZIhvcNAQkBFhVjb2Rlc2lnbkBzZW1w
# ZXJpcy5jb20wggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQDUMo62coWW
# aPvA5QnJeqQ9R26QLvLQSE+KlquYWFYXsQdsC9lSkV4MdWfWQFAiPf6zNGWi8yhk
# TZkc8TaLZAWE9DYb+lTTV1mSSngsMyw9qact8t0QzS+fGZuJc6cjgHKv1p5D+5lC
# W5C0AXbHM6aBS7HCd38cZGwOGQc6RW+7ux/yAMdgkhDyRjOHoeAEMdzmlOwwswOd
# 2RbgBBgWgGQ2p6sKY80SQFP49TxIndBVBpJnXJ1pUfneXvqphXgnyoB+uOLvqsYi
# oHuHQbQ7LQIDLmYv7ecNX5K8q7Qm59Fh8up/Hxn8BtsN+f9FxyQZx+t64o3FBwh2
# LEuSzAR2qJvpAgMBAAGjggGkMIIBoDAOBgNVHQ8BAf8EBAMCB4AwgZQGCCsGAQUF
# BwEBBIGHMIGEMEgGCCsGAQUFBzAChjxodHRwOi8vc2VjdXJlLmdsb2JhbHNpZ24u
# Y29tL2NhY2VydC9nc2NvZGVzaWduc2hhMmczb2NzcC5jcnQwOAYIKwYBBQUHMAGG
# LGh0dHA6Ly9vY3NwMi5nbG9iYWxzaWduLmNvbS9nc2NvZGVzaWduc2hhMmczMFYG
# A1UdIARPME0wQQYJKwYBBAGgMgEyMDQwMgYIKwYBBQUHAgEWJmh0dHBzOi8vd3d3
# Lmdsb2JhbHNpZ24uY29tL3JlcG9zaXRvcnkvMAgGBmeBDAEEATAJBgNVHRMEAjAA
# MD8GA1UdHwQ4MDYwNKAyoDCGLmh0dHA6Ly9jcmwuZ2xvYmFsc2lnbi5jb20vZ3Nj
# b2Rlc2lnbnNoYTJnMy5jcmwwEwYDVR0lBAwwCgYIKwYBBQUHAwMwHwYDVR0jBBgw
# FoAUDzrnrJSRdC2WAnODrZwuST8ZqlQwHQYDVR0OBBYEFJ0VxlgIguLMjbOv3d6R
# j5Cx6SdVMA0GCSqGSIb3DQEBCwUAA4IBAQA3qhLGQ90wZiaHcJrrWFA3ssT0wb2T
# XQQKpPQO8qm+WXhHGWIAQtUU+4xZcHsKoTxVm4DylzhqCRx72EFwrQ6aXMiM2q8y
# jrvipfJ+41aFmcKSIqh/sHt+0yhwn6zDQHkDQuduzeW6Ad7qDh6xbon56t2TlDtL
# qWD17VuPoBApVO2qw57sbWQLxq9n41EBgqQxIlQT2HXbmdKR/+s7urdnOhKNEL9f
# lJ2EBbuvGWM6EA3m1iOg1YK8uw6JOi0LONBx4BzagawvWOv/73zZUHyNYNQQiBxu
# LmgIsxRCwzkWqYETqIGZvHry3EbhRv+8XDF7Em/BTuNH2+MIyN8n1Eu6MIIFMTCC
# BBmgAwIBAgIQCqEl1tYyG35B5AXaNpfCFTANBgkqhkiG9w0BAQsFADBlMQswCQYD
# VQQGEwJVUzEVMBMGA1UEChMMRGlnaUNlcnQgSW5jMRkwFwYDVQQLExB3d3cuZGln
# aWNlcnQuY29tMSQwIgYDVQQDExtEaWdpQ2VydCBBc3N1cmVkIElEIFJvb3QgQ0Ew
# HhcNMTYwMTA3MTIwMDAwWhcNMzEwMTA3MTIwMDAwWjByMQswCQYDVQQGEwJVUzEV
# MBMGA1UEChMMRGlnaUNlcnQgSW5jMRkwFwYDVQQLExB3d3cuZGlnaWNlcnQuY29t
# MTEwLwYDVQQDEyhEaWdpQ2VydCBTSEEyIEFzc3VyZWQgSUQgVGltZXN0YW1waW5n
# IENBMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAvdAy7kvNj3/dqbqC
# mcU5VChXtiNKxA4HRTNREH3Q+X1NaH7ntqD0jbOI5Je/YyGQmL8TvFfTw+F+CNZq
# FAA49y4eO+7MpvYyWf5fZT/gm+vjRkcGGlV+Cyd+wKL1oODeIj8O/36V+/OjuiI+
# GKwR5PCZA207hXwJ0+5dyJoLVOOoCXFr4M8iEA91z3FyTgqt30A6XLdR4aF5FMZN
# JCMwXbzsPGBqrC8HzP3w6kfZiFBe/WZuVmEnKYmEUeaC50ZQ/ZQqLKfkdT66mA+E
# f58xFNat1fJky3seBdCEGXIX8RcG7z3N1k3vBkL9olMqT4UdxB08r8/arBD13ays
# 6Vb/kwIDAQABo4IBzjCCAcowHQYDVR0OBBYEFPS24SAd/imu0uRhpbKiJbLIFzVu
# MB8GA1UdIwQYMBaAFEXroq/0ksuCMS1Ri6enIZ3zbcgPMBIGA1UdEwEB/wQIMAYB
# Af8CAQAwDgYDVR0PAQH/BAQDAgGGMBMGA1UdJQQMMAoGCCsGAQUFBwMIMHkGCCsG
# AQUFBwEBBG0wazAkBggrBgEFBQcwAYYYaHR0cDovL29jc3AuZGlnaWNlcnQuY29t
# MEMGCCsGAQUFBzAChjdodHRwOi8vY2FjZXJ0cy5kaWdpY2VydC5jb20vRGlnaUNl
# cnRBc3N1cmVkSURSb290Q0EuY3J0MIGBBgNVHR8EejB4MDqgOKA2hjRodHRwOi8v
# Y3JsNC5kaWdpY2VydC5jb20vRGlnaUNlcnRBc3N1cmVkSURSb290Q0EuY3JsMDqg
# OKA2hjRodHRwOi8vY3JsMy5kaWdpY2VydC5jb20vRGlnaUNlcnRBc3N1cmVkSURS
# b290Q0EuY3JsMFAGA1UdIARJMEcwOAYKYIZIAYb9bAACBDAqMCgGCCsGAQUFBwIB
# FhxodHRwczovL3d3dy5kaWdpY2VydC5jb20vQ1BTMAsGCWCGSAGG/WwHATANBgkq
# hkiG9w0BAQsFAAOCAQEAcZUS6VGHVmnN793afKpjerN4zwY3QITvS4S/ys8DAv3F
# p8MOIEIsr3fzKx8MIVoqtwU0HWqumfgnoma/Capg33akOpMP+LLR2HwZYuhegiUe
# xLoceywh4tZbLBQ1QwRostt1AuByx5jWPGTlH0gQGF+JOGFNYkYkh2OMkVIsrymJ
# 5Xgf1gsUpYDXEkdws3XVk4WTfraSZ/tTYYmo9WuWwPRYaQ18yAGxuSh1t5ljhSKM
# Ycp5lH5Z/IwP42+1ASa2bKXuh1Eh5Fhgm7oMLSttosR+u8QlK0cCCHxJrhO24XxC
# QijGGFbPQTS2Zl22dHv1VjMiLyI2skuiSpXY9aaOUjGCBEcwggRDAgEBMGowWjEL
# MAkGA1UEBhMCQkUxGTAXBgNVBAoTEEdsb2JhbFNpZ24gbnYtc2ExMDAuBgNVBAMT
# J0dsb2JhbFNpZ24gQ29kZVNpZ25pbmcgQ0EgLSBTSEEyNTYgLSBHMwIMFXW337x5
# IagTcYjJMA0GCWCGSAFlAwQCAQUAoHwwEAYKKwYBBAGCNwIBDDECMAAwGQYJKoZI
# hvcNAQkDMQwGCisGAQQBgjcCAQQwHAYKKwYBBAGCNwIBCzEOMAwGCisGAQQBgjcC
# ARUwLwYJKoZIhvcNAQkEMSIEIHxTB0QY2s3RLFwy9vZMOR6VZkp9aKA6Q2UZl8Q8
# 74GsMA0GCSqGSIb3DQEBAQUABIIBAI7e3FtPEWWEw6qBFe0bAMPsxLmkqBL+6CAf
# NmKDpUO2M8Xl1b2vU7hm6SVArGvRIlBQdNreWT7221zd8IG0EIttSl5eNxSjNzpw
# WmrtcSS3OOXKqFWW0CtrCxheJH01bWAuFyRR7tyEDJ5v3fq3B8yCSSJfChc/rjRU
# xGRE7agGjfxIJDkp5iEQGv4FV487Ao3jDRFgOybRNsUPwaW/4p8gWKbDt6GYpWVV
# ybQAld8ueNJy0jHATqh2SWifiZ6My5Jxt0VtWJ1hsZZF0oL3JMvpnKuHvyEvZwip
# aLXYiaJ32DyBJrUWZ2A0XfCQFXIKDANY2jENlhPvyLaF4oWpYFyhggIwMIICLAYJ
# KoZIhvcNAQkGMYICHTCCAhkCAQEwgYYwcjELMAkGA1UEBhMCVVMxFTATBgNVBAoT
# DERpZ2lDZXJ0IEluYzEZMBcGA1UECxMQd3d3LmRpZ2ljZXJ0LmNvbTExMC8GA1UE
# AxMoRGlnaUNlcnQgU0hBMiBBc3N1cmVkIElEIFRpbWVzdGFtcGluZyBDQQIQDUJK
# 4L46iP9gQCHOFADw3TANBglghkgBZQMEAgEFAKBpMBgGCSqGSIb3DQEJAzELBgkq
# hkiG9w0BBwEwHAYJKoZIhvcNAQkFMQ8XDTIxMDMxNzE5MzM0NFowLwYJKoZIhvcN
# AQkEMSIEIBi91kIsfoM0006mxh0BEhhgiE0n9OFVEQFPiLnG8E/oMA0GCSqGSIb3
# DQEBAQUABIIBABKcBxv3yVDfJBzN4OciZo1VuxNx7pmd1hkd5YlwenE+A6TZ6wNV
# 4HzE6p32f+9KAgcZQ0atj8pRI69LY9D8xUEaufzqFnSCpJ8+luv8eS42Jl2XH/0K
# dMHIKAG+qlWwvBOomPn+whjry9D0qiNIHdq7Voj3wE4b4pzO0xPPFFcLKdqNA65R
# /7i+EOfZ1ueA3+RyfMbSh6ikk4MkbITbS+D6y0aCwY4V3fzpqccFcnzhmPoV2gyC
# FXqQfTka52QYeMf5/V25fVLNsLVA/jmmlnTs9PchJDw3XFxICxsToPtzAMnFwAbD
# /kuHnR+lesnJ74RaBQwV6YcqCjSJ1FT3wCk=
# SIG # End signature block
