<#
.SYNOPSIS
Short description

.DESCRIPTION
Long description

.PARAMETER dnsDomain
Domain's dns name

.PARAMETER attributes
Attributes to return from the query

.PARAMETER baseDN
Root distinguished name for the search

.PARAMETER scope
Scope of the search

.PARAMETER filter
Filter to be applied to the query

.PARAMETER pageSize
Page size for the query

.EXAMPLE
An example

.NOTES
General notes
#>
function Search-AD #using System.DS.Protocols to do LDAP searches of GPCs
{
    param(
        [parameter(Mandatory = $true)]
        [string]$dnsDomain,

        [parameter(Mandatory = $false)]
        [string[]]$attributes = "",

        [parameter(Mandatory = $false)]
        [string]$baseDN,

        [parameter(Mandatory = $false)]
        [string]$scope = "subtree",

        [parameter(Mandatory = $true)]
        [string]$filter,

        [parameter(Mandatory = $false)]
        [int]$pageSize = 1000
    )
    add-type -Path "$env:windir\Microsoft.NET\Framework64\v4.0.30319\system.directoryservices.protocols.dll"
    $Timeout = [System.TimeSpan]::FromDays(10000)
    $results = new-object "System.Collections.Generic.List[System.DirectoryServices.Protocols.SearchResultEntry]"
    [System.DirectoryServices.Protocols.LdapConnection] $conn = new-object System.DirectoryServices.Protocols.LdapConnection($dnsDomain)
    [System.DirectoryServices.Protocols.SearchRequest] $search = new-object System.DirectoryServices.Protocols.SearchRequest($baseDN,$filter,$scope,$attributes)
    $search.TimeLimit = $Timeout
    [System.DirectoryServices.Protocols.PageResultRequestControl] $pageRequest = new-object System.DirectoryServices.Protocols.PageResultRequestControl($pageSize)
    [void]$search.Controls.Add($pageRequest)

    [System.DirectoryServices.Protocols.SearchOptionsControl] $searchOptions = new-object System.DirectoryServices.Protocols.SearchOptionsControl([System.DirectoryServices.Protocols.SearchOption]::DomainScope)
    [void]$search.Controls.Add($searchOptions)

    [System.DirectoryServices.Protocols.SecurityDescriptorFlagControl] $searchSecurityFlags = new-object System.DirectoryServices.Protocols.SecurityDescriptorFlagControl(7)
    [void]$search.Controls.Add($searchSecurityFlags)
    [int] $pageCount = 0
    while ($true) {
        $pageCount++
        [System.DirectoryServices.Protocols.SearchResponse] $response = [System.DirectoryServices.Protocols.SearchResponse]$conn.SendRequest($search,$Timeout)
        [System.DirectoryServices.Protocols.PageResultResponseControl] $pageResponse = [System.DirectoryServices.Protocols.PageResultResponseControl]$response.Controls[0]
        if ($response.Entries.Count -gt 0) {
            foreach ($entry in $response.Entries) {
                $results.Add($entry)
            }
        }
        if ($pageResponse.Cookie.Length -eq 0) {
            break
        }
        $pageRequest.Cookie = $pageResponse.Cookie
    }
    if($results -and $attributes) {
        $results = RangeQueryHelper -Attributes $attributes -Entries $results
    }
    return $results
}

<#
.SYNOPSIS
Short description

.DESCRIPTION
Long description

.PARAMETER dnsDomain
Parameter description

.EXAMPLE
An example

.NOTES
General notes
#>
function Get-DN{ #calculates Distinguished Name
    param(
        [parameter(Mandatory = $true)]
        [string]$dnsDomain
    )
    $domContext = New-Object System.DirectoryServices.ActiveDirectory.DirectoryContext([System.DirectoryServices.ActiveDirectory.DirectoryContextType]::Domain, $dnsDomain);
    $selectedDomain = [System.DirectoryServices.ActiveDirectory.Domain]::GetDomain($domContext);
    return $selectedDomain.GetDirectoryEntry().Properties["distinguishedName"][0].ToString();
}

<#
.SYNOPSIS
Short description

.DESCRIPTION
Long description

.PARAMETER dnsDomain
Parameter description

.EXAMPLE
An example

.NOTES
General notes
#>
function Get-DomainSID{ # Gets the domain SID
    param(
        [parameter(Mandatory = $true)]
        [string]$dnsDomain
    )
    $domContext = New-Object System.DirectoryServices.ActiveDirectory.DirectoryContext([System.DirectoryServices.ActiveDirectory.DirectoryContextType]::Domain, $dnsDomain);
    $selectedDomain = [System.DirectoryServices.ActiveDirectory.Domain]::GetDomain($domContext);
    $sid = $selectedDomain.GetDirectoryEntry().Properties["objectSID"][0]
    return (New-Object System.Security.Principal.SecurityIdentifier @($sid,0)).Value
}


<#
.SYNOPSIS
Short description

.DESCRIPTION
Long description

.PARAMETER uac
Parameter description

.EXAMPLE
An example

.NOTES
General notes
#>
Function Get-UACSet{
    param(
        [parameter(Mandatory = $true)]
        [int]$uac
    )

    $uacvalues = @{
        1 = "Script"
        2 = "AccountDisabled"
        8 = "HomeDirectoryRequired"
        16 = "AccountLockedOut"
        32 = "PasswordNotRequired"
        64 = "PasswordCannotChange"
        128 = "EncryptedTextPasswordAllowed"
        256 = "TempDuplicateAccount"
        512 = "NormalAccount"
        2048 = "InterDomainTrustAccount"
        4096 = "WorkstationTrustAccount"
        8192 = "ServerTrustAccount"
        65536 = "PasswordDoesNotExpire"
        131072 = "MnsLogonAccount"
        262144 = "SmartCardRequired"
        524288 = "TrustedForDelegation"
        1048576 = "AccountNotDelegated"
        2097152 = "UseDesKeyOnly"
        4194304 = "DontRequirePreauth"
        8388608 = "PasswordExpired"
        16777216 = "TrustedToAuthenticateForDelegation"
        33554432 = "NoAuthDataRequired"
        67108864 = "PartialSecretsAccount"
    }

    $uaclist = [System.Collections.ArrayList]@()
    foreach($k in $uacvalues.Keys){
        if($uac -band $k){
            $uaclist.Add($uacvalues[$k]) | out-null
        }
    }
    $uaclist
}

function RangeQueryHelper {
    param(
        [parameter(Mandatory = $true)]
        [string[]]$Attributes,

        [parameter(Mandatory = $true)]
        [Object[]]$Entries
    )

    $Entries = Bandage -Attributes $Attributes -Entries $Entries
    # Determine if ranged search might be needed, trying to reduce cost of the check for ranged results
    $rangedSearch = $false
    $rangedAttributes = @("member","memberof","serviceprincipalname", "*", "msds-replattributemetadata", "msds-replvaluemetadata", "serviceprincipalname") # Attributes that are multi valued and might have more then 1500 entries
    foreach ($attribute in $Attributes) {
        if($rangedAttributes -contains $attribute.ToLower()) {
            $rangedSearch = $true
            break
        }
    }
    if(!($rangedSearch)) {
        return $Entries
    }
    foreach ($entry in $Entries){
        $resRangeResults = $entry.Attributes.AttributeNames.Where({$PSItem -match "^\w+;range=0-\d+$"})
        foreach ($attribute in $resRangeResults){
            $attribute -match "^(\w+);range=0-\d+$" | Out-Null
            $attrName = $Matches[1]
            $attrData =  $entry.Attributes[$attribute]
            $inc = $attrData.count # default is 1500
            $start = 0
            $doneSearching = $false
            while (!($doneSearching)) {
                $start += $inc
                $end = ($start + $inc -1)
                $search.Filter = "distinguishedName=$($entry.DistinguishedName)"
                $search.Scope = "base"
                $search.DistinguishedName = $entry.DistinguishedName
                $attr = "$attrName;range=$start-$end"
                $search.Attributes.Clear()
                $search.Attributes.Insert(0,"$attr")
                $response = [System.DirectoryServices.Protocols.SearchResponse]$conn.SendRequest($search)

                # Number of entries should be 1 or something unexpected happened
                foreach ($resEntry in $response.Entries) {
                    if ($resEntry.Attributes[$attr]) {
                        $attrData += $resEntry.Attributes[$attr]
                        continue
                    }

                    # In case we reached the last chunk or we are stuck in the while loop
                    ElseIf ($resEntry.Attributes["$attrName;range=$start-*"]) {
                        $attr = "$attrName;range=$start-*"
                        $attrData += $resEntry.Attributes[$attr]
                    }
                    $doneSearching = $true
                }
            }

            # Done going through the range, now fill the original attribute
            $directoryAttribute = New-Object System.DirectoryServices.Protocols.DirectoryAttribute($attrName,$attrData)
            $entry.Attributes[$attrName] = $directoryAttribute

            # Remove the partial attribute
            $entry.Attributes.Remove($attribute)
        }
    }
    return $Entries
}

# THIS FUNCTION IS TEMPORARY
# we need to decide how to deal with non existing attributes
function Bandage {
    param(
        [parameter(Mandatory = $true)]
        [string[]]$Attributes,

        [parameter(Mandatory = $true)]
        [Object[]]$Entries
    )
    $attributesCount = $Attributes.Count
    foreach ($entry in $Entries) {
        if ($attributesCount -ne $entry.Attributes.Count) {
            foreach ($attribute in $Attributes) {
                if (!($entry.Attributes.contains($attribute))) {
                    $entry.Attributes.Add($attribute,"")
                }
            }
        }
    }
    return $Entries
}

function Search-AD-ADSI #using System.DS.Protocols to do LDAP searches of GPCs and then ADSI to load properties
{
    param(
        [parameter(Mandatory = $true)]
        [string]$dnsDomain,

        [parameter(Mandatory = $false)]
        [string[]]$attributes = "",

        [parameter(Mandatory = $true)]
        [string]$baseDN,

        [parameter(Mandatory = $false)]
        [string]$scope = "subtree",

        [parameter(Mandatory = $true)]
        [string]$filter,

        [parameter(Mandatory = $false)]
        [int]$pageSize = 1000
    )
    add-type -Path "$env:windir\Microsoft.NET\Framework64\v4.0.30319\system.directoryservices.protocols.dll"
    $results = new-object "System.Collections.Generic.List[System.DirectoryServices.DirectoryEntry]"
    [System.DirectoryServices.Protocols.LdapConnection] $conn = new-object System.DirectoryServices.Protocols.LdapConnection($dnsDomain)
    [System.DirectoryServices.Protocols.SearchRequest] $search = new-object System.DirectoryServices.Protocols.SearchRequest($baseDN,$filter,$scope,$attributes)
    [System.DirectoryServices.Protocols.PageResultRequestControl] $pageRequest = new-object System.DirectoryServices.Protocols.PageResultRequestControl($pageSize)
    [void]$search.Controls.Add($pageRequest)

    [System.DirectoryServices.Protocols.SearchOptionsControl] $searchOptions = new-object System.DirectoryServices.Protocols.SearchOptionsControl([System.DirectoryServices.Protocols.SearchOption]::DomainScope)
    [void]$search.Controls.Add($searchOptions)

    [System.DirectoryServices.Protocols.SecurityDescriptorFlagControl] $searchSecurityFlags = new-object System.DirectoryServices.Protocols.SecurityDescriptorFlagControl(7)
    [void]$search.Controls.Add($searchSecurityFlags)
    [int] $pageCount = 0
    while ($true) {
        $pageCount++
        [System.DirectoryServices.Protocols.SearchResponse] $response = [System.DirectoryServices.Protocols.SearchResponse]$conn.SendRequest($search)
        [System.DirectoryServices.Protocols.PageResultResponseControl] $pageResponse = [System.DirectoryServices.Protocols.PageResultResponseControl]$response.Controls[0]
        if ($response.Entries.Count -gt 0) {
            foreach ($entry in $response.Entries) {
                $adsiResult = [adsi]("LDAP://" + $entry.DistinguishedName)
                if ($adsiResult) {
                    $results += $adsiResult
                }
            }
        }
        if ($pageResponse.Cookie.Length -eq 0) {
            break
        }
        $pageRequest.Cookie = $pageResponse.Cookie
    }
    return $results
}

Function Get-ADSearchFlag {
    param(
        [parameter(Mandatory = $true)]
        [int]$searchflags
    )

    $searchflagvalues = @{
        1 = "Index"
        2 = "ContainerIndex"
        4 = "ANR"
        8 = "PreserveOnDelete"
        16 = "Copy"
        32 = "TupleIndex"
        64 = "SubtreeIndex"
        128 = "Confidential"
        256 = "NeverValueAudit"
        512 = "RODCFiltered"
        1024 = "ExtendedLinkTracking"
        2048 ="BaseOnly"
        4096 ="PartitionSecret"

    }

    $searchflagslist = [System.Collections.ArrayList]@()
    foreach($k in $searchflagvalues.Keys){
        if($searchflags -band $k){
            $searchflagslist.Add($searchflagvalues[$k]) | out-null
        }
    }
    $searchflagslist
}

Export-ModuleMember -Function Search-AD
Export-ModuleMember -Function Get-DN
Export-ModuleMember -Function Get-DomainSID
Export-ModuleMember -Function Get-UACSet
Export-ModuleMember -Function Get-ADSearchFlags
# SIG # Begin signature block
# MIIY1gYJKoZIhvcNAQcCoIIYxzCCGMMCAQExDzANBglghkgBZQMEAgEFADB5Bgor
# BgEEAYI3AgEEoGswaTA0BgorBgEEAYI3AgEeMCYCAwEAAAQQH8w7YFlLCE63JNLG
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCBPSYgACuOxM9eG
# ivcloYKFHDLnSjchOegXgkuENSk6haCCE+UwggSUMIIDfKADAgECAg5IG2oHJtLo
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
# ARUwLwYJKoZIhvcNAQkEMSIEIEPB1AJEBOx/k8xRBXKiEww1K735KU+KFnp+SJPz
# qmH1MA0GCSqGSIb3DQEBAQUABIIBABiiw6bcBJtCncWvTT9y5bFnYm2lei+f+EKL
# TOVb8Flg0U5uC6JcKYTynjZOkTPlUfivzIEjGzsuNmWsEdRXeibs8UPS6Jhr4IEu
# lAOqX+l6qP3mclAAFly3+LdvnlXbN/xXzMfqAlX4qG7lDSWrzNxBbl4yhdd9LvUY
# FGYd40O0wvHQ0mmryijAJpYmp0GyjmisYSYBBtxGWARY4VgRGV570uHSMbXMyl8c
# Dk3Vavl5ZIV8sHK5+s0ncjM11q2iMBPumw/oS955nngLbP6btoZ7/TwQWK1Ti0Wa
# MWMgAPnC416cl32X7jQsQdIUDNbUJ06+YxeDHM+gTGrxXDtE81WhggIwMIICLAYJ
# KoZIhvcNAQkGMYICHTCCAhkCAQEwgYYwcjELMAkGA1UEBhMCVVMxFTATBgNVBAoT
# DERpZ2lDZXJ0IEluYzEZMBcGA1UECxMQd3d3LmRpZ2ljZXJ0LmNvbTExMC8GA1UE
# AxMoRGlnaUNlcnQgU0hBMiBBc3N1cmVkIElEIFRpbWVzdGFtcGluZyBDQQIQDUJK
# 4L46iP9gQCHOFADw3TANBglghkgBZQMEAgEFAKBpMBgGCSqGSIb3DQEJAzELBgkq
# hkiG9w0BBwEwHAYJKoZIhvcNAQkFMQ8XDTIxMDMxNzE5MzM1MVowLwYJKoZIhvcN
# AQkEMSIEIHRaGsfBFIPqKmm9MrFxOtNUrfXXNz3JDEFnfy16tDVRMA0GCSqGSIb3
# DQEBAQUABIIBALpkhvmGzeUk9q1fBuXxuNhr0B4TrxkVcJkcfS5rDgLdUkaRrtKP
# lxzmlW9dS6xXas+Ld2kyL5EelxhmLdt/s+vyQwOqrFKvgtt0L64r5uEkQ6JEuLEm
# MvOG/37OXm9wGx93+NwlJiz0GXKuVUtNlpn4kRLxmn/RCMrVqmxGS1oOSo9l3zao
# pohcZ8gPIsJ75JhIVeLMc/I+r9a321ApHyjvTQDUpV0aYKd/CxPAnOsDXQlwuROA
# TRtXfMxIdjFccfpOKwOupQ1oqpqxbQguxTMjzSWirkV5yOk+75BfQfy4iqwMo60Y
# lMfL20lk67zI0XGe+r2fmLUCoEAV+6ZywNE=
# SIG # End signature block
