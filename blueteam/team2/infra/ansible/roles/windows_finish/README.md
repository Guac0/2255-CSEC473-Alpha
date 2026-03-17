windows_finish
=========
Runs various finishing tasks. Currently:
- Re-enables UAC for admins (it is disabled in windows_deploy_standards)
- Deletes the working directory

You should run a final reboot after this using the windows_reboot role.