# windows_utilities

Installs various system utilities and/or creates desktop shortcuts for existing system utilities.
Note: LibreOffice install will force a system restart, so it is installed last. The Ansible will wait for the host to come back online.
If LibreOffice does not force a reboot, then you should reboot using the windows_reboot role to allow for the new programs to initiate correctly.

Installs:
- LibreOffice v26.2.0 (Last Updated February 4th 2026) [must be downloaded manually due to file size]
- Notepad++ v8.9.1 (Last Updated February 4th 2026)
- Chrome v??? (Last Updated February 4th 2026) [chrome doesn't say what version it is]
- Thunderbird v147.0.1 (Last Updated February 4th 2026)
- Hexchat v2.16.2 (Last Updated February 4th 2026)
- FileZilla v3.69.5 (Last Updated February 4th 2026)

Creates Desktop Shortcuts:
- For all of the installed apps above
- Windows Run
- cmd.exe
- Powershell

Downloads:
- Sysinternals (This is currently commented out and untested as it is an unfair advantage to the blue team)