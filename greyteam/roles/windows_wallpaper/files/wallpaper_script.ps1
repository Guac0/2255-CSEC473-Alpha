# Wait until Explorer is actually running
while (-not (Get-Process explorer -ErrorAction SilentlyContinue)) {
    Start-Sleep -Milliseconds 500
}

# Small additional delay to let profile finish loading
Start-Sleep -Seconds 10

# 2. CRITICAL: Clear the wallpaper cache before setting the new one
# This prevents Windows from reverting to the 'cached' teal screen.
$themePath = "$env:APPDATA\Microsoft\Windows\Themes"
if (Test-Path "$themePath\TranscodedWallpaper") {
    Remove-Item "$themePath\TranscodedWallpaper" -Force -ErrorAction SilentlyContinue
}

# Tell windows to enable rdp wallpaper
#$rdpPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services"
#if (-not (Test-Path $rdpPath)) {
#    New-Item $rdpPath -Force | Out-Null
#}
#Set-ItemProperty -Path $rdpPath -Name "fNoRemoteDesktopWallpaper" -Value 0

$wallpaper = "C:\ProgramData\Inscope\Branding\wallpaper.jpg"

# Apply wallpaper registry settings
Set-ItemProperty "HKCU:\Control Panel\Desktop" -Name Wallpaper -Value $wallpaper
Set-ItemProperty "HKCU:\Control Panel\Desktop" -Name WallpaperStyle -Value "10"
Set-ItemProperty "HKCU:\Control Panel\Desktop" -Name TileWallpaper -Value "0"

New-Item "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Wallpapers" -Force | Out-Null
Set-ItemProperty "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Wallpapers" -Name BackgroundType -Value 0

# Force Windows API refresh
Add-Type @"
using System;
using System.Runtime.InteropServices;
public class Wallpaper {
    [DllImport("user32.dll", SetLastError = true)]
    public static extern bool SystemParametersInfo(int uAction, int uParam, string lpvParam, int fuWinIni);
}
"@

[Wallpaper]::SystemParametersInfo(20, 0, $wallpaper, 3)
Start-Sleep -Seconds 1
[Wallpaper]::SystemParametersInfo(20, 0, $wallpaper, 3)
# Delete the scheduled task 
#schtasks /delete /tn "WallpaperInit" /f