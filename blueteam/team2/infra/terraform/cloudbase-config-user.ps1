#ps1
net user grayteam ponyuploc0! /logonpasswordchg:no /active:yes /add /y
wmic UserAccount where Name="grayteam" set PasswordExpires=False
net localgroup administrators grayteam /add
net user Administrator ponyuploc0! /logonpasswordchg:no /y
net localgroup "Remote Desktop Users" grayteam /add
Set-ExecutionPolicy Bypass -Scope Process -Force; [System.Net.ServicePointManager]::SecurityProtocol = [System.Net.ServicePointManager]::SecurityProtocol -bor 3072; iex ((New-Object System.Net.WebClient).DownloadString('https://chocolatey.org/install.ps1'))
