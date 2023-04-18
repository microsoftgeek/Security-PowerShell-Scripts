# Set a datestamp for the files per run
$datestamp = $(Get-Date -f yyyy-MM-dd-HH-mm)
$lastyear = (Get-Date).AddDays(-365)

# Get a list of computers to query, pick the fqdn
# Filter the list of computers by 'windows', enabled and logged in within the last year
get-adcomputer -filter {Enabled -eq 'True' -and OperatingSystem -like "*Windows*" -and LastLogonDate -gt $lastyear} | select DNSHostName | %{
    $targethost = $_.DNSHostName 
    # ping it first
    if (Test-Connection -Quiet $targethost) {
        # ping success
        Write-Host "Checking $targethost"
        # Use schtasks.exe to get list of scheduled tasks, output csv, filter
        # looks like schtasks likes to re-insert the header every few lines, so filter that out
        $tasks = schtasks.exe /query /s $targethost /V /FO CSV | ConvertFrom-CSV |
          Where-Object {$_.Status -ne "Disabled" -and
            $_.HostName -ne "Hostname" -and
            $_."Logon Mode" -ne "Interactive only" -and
            $_."Run As User" -NotMatch "^(SYSTEM|INTERACTIVE|LOCAL SERVICE|Users|Administrators)$"} |
          select HostName,TaskName,"Run As User"
        # use wmi to get list of services, filter out network/local/system/service account
        $services = get-wmiobject -class win32_service -computer $targethost |
          Where-Object -FilterScript { $_.StartName -NotMatch '^((.*\\)?(Network|Local)?(System|Service))$|^$|^StartName$' } |
          Select SystemName,Name,StartName
        # if we got data, write it to a file
        # skip the first line - it's the header, and we don't need 100's of those
        if ($tasks) { $tasks | ConvertTo-CSV | select-object -Skip 1 >> $datestamp-tasks.csv }
        if ($services) { $services | ConvertTo-CSV | select-object -Skip 1 >> $datestamp-services.csv }
    } else {
        # ping failure
        "$targethost" | Out-File -FilePath $datestamp-unreachablehosts.txt
    }
}

