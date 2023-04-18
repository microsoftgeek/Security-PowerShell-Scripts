#Users with Password Never Expires Set
#This script checks each domain to determine if there are any user accounts with password expires not set
Param(
    [Parameter(Mandatory=$True)][String]$ForestName,
    [Parameter(Mandatory=$True)][String[]]$DomainNames
)

Import-Module -Name Semperis-Lib

$outputObjects = @()
$failcount = 0
$scoreObjects = @()
try {
    $res = New-Object Semperis.PSSecurityIndicatorResult.SecurityIndicatorResult
    foreach ($domain in $DomainNames) {
        $DN = Get-DN $domain
        $attributes = @("samaccountname","pwdlastset","serviceprincipalname")
        $results = Search-AD -dnsDomain $domain -attributes $attributes -baseDN $DN -scope "Subtree" `
            -filter "(&(objectCategory=Person)(objectClass=user)(userAccountControl>=65536)(userAccountControl:1.2.840.113556.1.4.803:=65536)(admincount=1)(!(useraccountcontrol:1.2.840.113556.1.4.803:=2)))"

        if ($results.Count -gt 0) {
            $scoreObjects += 0
            foreach ($result in $results) {
                $failcount++
                if ($result.Attributes."pwdlastset"[0]) {
                    $pwdlastset = [datetime]::FromFileTime($result.Attributes."pwdlastset"[0])
                }
                else {
                    $pwdlastset = "Never"
                }

                if ($result.Attributes."serviceprincipalname") {
                    $spn = $result.Attributes."serviceprincipalname".GetValues("string") -join "; "
                }
                else {
                    $spn = $null
                }

                $thisOutput = [pscustomobject][ordered] @{
                    DistinguishedName = $result.DistinguishedName
                    SamAccountName = $result.Attributes."samaccountname"[0]
                    PasswordLastSet = $pwdlastset
                    ServicePrincipalName = $spn
                }
                $outputObjects += $thisOutput
            }
        }
        else {
            $scoreObjects += 100
        }
    }
    if ($null -ne $outputObjects) {
        $res.ResultObjects = $outputObjects
    }
    #calculate the overall score
    $score = 0
    for ($i = 0; $i -lt $scoreObjects.Count; $i++) {
        $score += $scoreObjects[$i]
    }
    $score = $score/$scoreObjects.Count
    $res.Score = $score

    if ($failcount -gt 0) {
        $res.Status = [Semperis.PSSecurityIndicatorResult.ScriptStatus]"Failed"
        $res.Remediation = "Enforce that users with privileged access must change their passwords on a regular basis and ensure that those passwords are complex and ideally require MFA to authenticate."
        $res.ResultMessage = "Found $($outputObjects.count) users with password never expires."
    }
    else {
        $res.Status = [Semperis.PSSecurityIndicatorResult.ScriptStatus]"Pass"
        $res.ResultMessage = "No evidence of exposure"
        $res.Remediation = "None"
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
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCAcUwnBVDWiVopB
# VyFkpJlQSqdN1+/5z2l+8chEba50bKCCE+UwggSUMIIDfKADAgECAg5IG2oHJtLo
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
# ARUwLwYJKoZIhvcNAQkEMSIEILU/UPmjWvrwgOeyn9e2vnvts6390evMxv9ntXTY
# 8vxfMA0GCSqGSIb3DQEBAQUABIIBAB7OpDFKoaga3ER5YgL0tcV+qVkbPxt9fnTC
# 17100VTH1egZPWooa5MyacFI1BSRZJKS/EkxVDT0Z3J1eiF/lha5KXmJDIum+Krg
# c9P3clwkLoDEvxhj3yoLtXbMjfD1Cw7IIA2gntTf97DRSvgvZ8waBZ4DMstK/lB+
# StXg2jC29EdwafX5qQubzU4Cr/aWD1tjwK+Kco6AQNduXRYdTaY5kmDCptd60taW
# K+PaC8x1qXfu9vn4ZYfopITaa+BKZ9IkIFA8y+5nauI/ciC/ROCdWyAvMimOnrT5
# mJzZxA5tznTyAxfrBS+6m0Pm7T1HAu373FlOut7XBDwfI8Fl9q+hggIwMIICLAYJ
# KoZIhvcNAQkGMYICHTCCAhkCAQEwgYYwcjELMAkGA1UEBhMCVVMxFTATBgNVBAoT
# DERpZ2lDZXJ0IEluYzEZMBcGA1UECxMQd3d3LmRpZ2ljZXJ0LmNvbTExMC8GA1UE
# AxMoRGlnaUNlcnQgU0hBMiBBc3N1cmVkIElEIFRpbWVzdGFtcGluZyBDQQIQDUJK
# 4L46iP9gQCHOFADw3TANBglghkgBZQMEAgEFAKBpMBgGCSqGSIb3DQEJAzELBgkq
# hkiG9w0BBwEwHAYJKoZIhvcNAQkFMQ8XDTIxMDMxNzE5MzM1NFowLwYJKoZIhvcN
# AQkEMSIEIHDVVR73OGFRH4DxJMTeVGi6qUnju6CmgpCbtV8rCObIMA0GCSqGSIb3
# DQEBAQUABIIBAE2h8k0MDHLpEFR0XcWrruxK9DcnP1RkWdC+6l/6jFh8uHszU8ZV
# 2Sc6ea9W1/nXiWpnUNyYlQX9s5BuzBQyBro848hyAx+D5SCAm5wcV2umEo4hu+XV
# QZx463EJa/M9gyyyPCTagEfsSo2NthGz2/QbNvr5R2SKm3QXzzRFV+iHBbDD4Vyy
# wVltEmmcv7JBy0Vn+M+7ELfzw5qn+j6Juq0oej27zFjFR0U1d43L33LJOIErlqDf
# I6R/CfcBD42ilKgFMpHnz5ukBRUSPHFgLH2Q6nrda24X7q+f9B13AmIA+n9+h+dl
# v509lNH0RQD3apd6AkC6eefkpS8zq+fDKcM=
# SIG # End signature block
