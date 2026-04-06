$fuse_date = "2025-11-31"  # YYYY-MM-DD format in America/New_York timezone
$fuse_time = "16:00:00"    # HH:MM:SS, 24-hour format in America/New_York timezone
$fuse_armed = $false  # DO NOT SET TO TRUE UNLESS YOU WANT TO ACTIVATE IT
$log_location = "./dt.txt"  # Set to $null for no output
$users = "user1 user2 user3"
$users_pwd = "temppassword"

#########################
##### EXTRA SETUP #######
#########################

# If logging is enabled, create/overwrite log location
if ($log_location) {
    New-Item -ItemType File -Path $log_location -Force | Out-Null
}

function Log($message) {
    #$timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    #$entry = "[$timestamp] $message"
    #timestamp is basically useless, ignore it
    $entry = "$message"
    # Write output to console and, if a log file location is set, append the log entry to the file
    if ($log_location) { 
        $entry | Out-File -Append -FilePath $log_location 
    }
    Write-Output $entry
    if ($log_location) { $entry | Out-File -Append -FilePath $log_location }
}

# Start

#########################
###### TIME CHECK #######
#########################

#$current_date = Get-Date -Format "yyyy-MM-dd"
#$current_time = Get-Date -Format "HH:mm:ss"
$estTimeZone = [System.TimeZoneInfo]::FindSystemTimeZoneById("Eastern Standard Time")
$estDateTime = [System.TimeZoneInfo]::ConvertTimeFromUtc((Get-Date).ToUniversalTime(), $estTimeZone)
$current_date = $estDateTime.ToString("yyyy-MM-dd")
$current_time = $estDateTime.ToString("HH:mm:ss")

Log "---------------------------------------------"
Log "  Doubletap - $current_date $current_time) EST"

if ($current_date -eq $fuse_date) {
    if ($current_time -ge $fuse_time) {
        Log "+++++++++++++++++++++++++++++++++++"
        Log "  DETONATION CRITERIA MET"
        Log "Found date $current_date and expected $fuse_date"
        Log "Found time $current_time and expected $fuse_time"

        if ($fuse_armed) {
            Log "  PROCEEDING WITH KABOOM"
            
            # Block all traffic except for SSH (22) and RDP (3389)
            Log "Configuring Windows Firewall Rules..."

            # Reset Windows Firewall to default
            netsh advfirewall reset
            
            # Block all inbound traffic by default
            netsh advfirewall set allprofiles firewallpolicy blockinbound,allowoutbound
            
            # Allow SSH (22)
            netsh advfirewall firewall add rule name="Allow SSH" dir=in action=allow protocol=TCP localport=22
            
            # Allow RDP (3389)
            netsh advfirewall firewall add rule name="Allow RDP" dir=in action=allow protocol=TCP localport=3389
            
            # Block all ICMP (ping)
            netsh advfirewall firewall add rule name="Block ICMP" dir=in action=block protocol=ICMPv4
            
            Log "Firewall rules applied successfully."

            $userList = $users -split ' '
            $securePwd = ConvertTo-SecureString $users_pwd -AsPlainText -Force

            foreach ($user in $userList) {
                if (Get-LocalUser -Name $user -ErrorAction SilentlyContinue) {
                    # Local user
                    Set-LocalUser -Name $user -Password $securePwd
                    Log "Local user $user password changed successfully."
                }
                elseif (Get-ADUser -Identity $user -ErrorAction SilentlyContinue) {
                    # AD user
                    Set-ADAccountPassword -Identity $user -NewPassword $securePwd -Reset
                    Log "AD user $user password changed successfully."
                }
                else {
                    Log "User $user not found (neither local nor AD). Skipping..."
                }
            }
            
            # Terminate all active RDP and SSH sessions
            Log "Terminating all active RDP and SSH sessions..."
            Get-WmiObject Win32_Process | Where-Object { $_.Name -eq "mstsc.exe" -or $_.Name -eq "ssh.exe" } | ForEach-Object { Stop-Process -Id $_.ProcessId -Force }
            
            Log "Execution complete."
        } else {
            Log "  ... where's the kaboom? FUSE NOT ARMED"
        }
        # Cleanup after explosion

        Log " My work here is done"
    } else {
        Log "Wrong hour - found $current_date but expected $current_time"
    }
} else {
    Log "Wrong date - found $current_date but expected $fuse_date"
}

# End
