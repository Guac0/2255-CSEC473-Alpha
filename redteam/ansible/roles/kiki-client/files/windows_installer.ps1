# Installs the client agent on the local machine. Assumes the script file is present in same directory and named as client.ps1
# Does NOT pull variables from ansible
# Not really intended to be used by anything at the moment - just maintained as a backup in case you need to install the client without using ansible

# Define parameters
$ServiceName = "WinSvcUpdate"
$DisplayName = "Windows Service Update"
$ScriptPath = "C:\ProgramData\WinUpdate\client.ps1"
$ScriptDir = [System.IO.Path]::GetDirectoryName($ScriptPath)

# Ensure the script directory exists
if (-not (Test-Path $ScriptDir)) {
    New-Item -Path $ScriptDir -ItemType Directory -Force | Out-Null
}

# (Optional) Hide the directory
attrib +h $ScriptDir

# (Optional) Place the client.ps1 script
Copy-Item ".\client.ps1" -Destination $ScriptPath -Force

# Define the powershell command that will run as the service
$ServiceCommand = "powershell.exe -ExecutionPolicy Bypass -WindowStyle Hidden -File `"$ScriptPath`""

# Check if service already exists
if (Get-Service -Name $ServiceName -ErrorAction SilentlyContinue) {
    Write-Output "Service '$ServiceName' already exists. Stopping and removing it..."
    Stop-Service -Name $ServiceName -Force -ErrorAction SilentlyContinue
    sc.exe delete $ServiceName | Out-Null
    Start-Sleep -Seconds 2
}

# Create the service
New-Service -Name $ServiceName `
            -BinaryPathName $ServiceCommand `
            -DisplayName $DisplayName `
            -StartupType Automatic

# Start the service
Start-Service -Name $ServiceName
Write-Output "Service '$ServiceName' installed and started."
