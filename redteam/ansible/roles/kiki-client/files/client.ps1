# === Configuration ===
$SoftwareTimestamps = @{
    "software1"="C:\Path\To\software1_timestamp.txt"
    "software2"="C:\Path\To\software2_timestamp.txt"
    "software3"="C:\Path\To\software3_timestamp.txt"
}

$CheckIntervalMinutes=5  # If timestamp older than this, reinstall
$ServerUrl="http://server.local:8080/get-command/"
$AuthToken="my_secure_token"
$LogToCon=$true         # Set to $false to suppress console output
$LogToFile=$true
$DryRun=$false    
$LogFilePath="C:\agent_debug.log"

# === Logging Function ===
function Log-Debug {
    param(
        [string]$Message
    )
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $logEntry = "[$timestamp] $Message"

    if ($LogToCon) {
        Write-Output $logEntry
    }
    if ($LogToFile) {
        try {
            Add-Content -Path $LogFilePath -Value $logEntry
        } catch {
            # Fail silently if logging fails
        }
    }
}

# === Function to Query Server and Execute Install Command ===
function Request-Reinstall {
    param(
        [string]$SoftwareName
    )

    $hostname = $env:COMPUTERNAME
    $ip = (Get-NetIPAddress -AddressFamily IPv4 | Where-Object {
        $_.IPAddress -notlike '169.*' -and
        $_.IPAddress -ne '127.0.0.1' -and
        $_.PrefixOrigin -ne 'WellKnown' -and
        $_.ValidLifetime -gt 0
    } | Sort-Object InterfaceIndex | Select-Object -First 1).IPAddres
    if (-not $ip) {
        $ip = "0.0.0.0"
    }
    $os_type = "ps1"

    $uri = "$ServerUrl?auth=$AuthToken&ip=$ip&hostname=$hostname&os=$os_type&software=$SoftwareName"
    Log-Debug "Requesting install command for $SoftwareName from server..."

    try {
        $response = Invoke-RestMethod -Uri $uri -Method Get -ErrorAction Stop
        if ($response.status -eq "ok" -and $response.command) {
            Log-Debug "Received install command from server: $($response.command)"
            # Execute install command silently
            if (! $DryRun) {
                Invoke-Expression $response.command
            }
            Log-Debug "Executed install command for $SoftwareName"
        } else {
            Log-Debug "Server response error or missing command: $($response | ConvertTo-Json -Depth 3)"
        }
    } catch {
        Log-Debug "Error contacting server or executing command for $SoftwareName : $_"
    }
}

# === Main Logic ===
foreach ($software in $SoftwareTimestamps.Keys) {
    $filePath = $SoftwareTimestamps[$software]

    if (-Not (Test-Path $filePath)) {
        Log-Debug "Timestamp file missing for $software : $filePath"
        Request-Reinstall -SoftwareName $software
        continue
    }

    try {
        $content = Get-Content -Path $filePath -ErrorAction Stop | Select-Object -First 1
        $lastRunTime = [datetime]::ParseExact($content, 'yyyy-MM-dd HH:mm:ss', $null)
    } catch {
        Log-Debug "Failed to parse timestamp file for $software at $filePath. Contents: '$content'"
        Request-Reinstall -SoftwareName $software
        continue
    }

    $timeDiff = (Get-Date) - $lastRunTime
    if ($timeDiff.TotalMinutes -gt $CheckIntervalMinutes) {
        Log-Debug "$software timestamp is older than $CheckIntervalMinutes minutes. Triggering reinstall."
        Request-Reinstall -SoftwareName $software
    } else {
        Log-Debug "$software is running fine. Last reported time: $lastRunTime"
    }
}
