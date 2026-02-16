$wallpaper = "C:\ProgramData\Inscope\Branding\wallpaper.jpg"

# Set registry values for current user
Set-ItemProperty "HKCU:\Control Panel\Desktop" -Name Wallpaper -Value $wallpaper
Set-ItemProperty "HKCU:\Control Panel\Desktop" -Name WallpaperStyle -Value "10"
Set-ItemProperty "HKCU:\Control Panel\Desktop" -Name TileWallpaper -Value "0"

New-Item "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Wallpapers" -Force | Out-Null
Set-ItemProperty "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Wallpapers" -Name BackgroundType -Value 0

# Refresh
RUNDLL32.EXE user32.dll,UpdatePerUserSystemParameters