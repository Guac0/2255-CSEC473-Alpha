#ps1
net user greyteam ponyuploc0! /logonpasswordchg:no /active:yes /add /y
wmic UserAccount where Name="greyteam" set PasswordExpires=False
net localgroup administrators greyteam /add
net user Administrator ponyuploc0! /logonpasswordchg:no /y
net localgroup "Remote Desktop Users" greyteam /add
Set-ExecutionPolicy Bypass -Scope Process -Force; [System.Net.ServicePointManager]::SecurityProtocol = [System.Net.ServicePointManager]::SecurityProtocol -bor 3072; iex ((New-Object System.Net.WebClient).DownloadString('https://chocolatey.org/install.ps1'))
