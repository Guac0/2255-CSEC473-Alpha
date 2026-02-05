windows_deploy_standards
=========
Applies base things that all Windows computers should have done. 

Currently:
- Ensures DNS client is configured
- Expands disk to use all availalbe space
- Enables/disables Windows Updates depending on role variables
- Sets firewall to allow ICMP, ensures that all profiles are enabled (or disabled depending on role variables)
- Removes auto-login, default username, and first login screen
- Ensures RDP is configured including firewall
- Enables HTTP mode for WinRM and configures firewall
- Removes unattend.xml file that may still exist from image building
- Sets hostname based on what Ansible believes the hostname should be
- Sets timezone to EST
- Creates an Ansible working directory via the working_dir variable
- Deploys HKLM:\Software\lvapi and HKLM:\Software\Wow6432Node\lvapi reg key with value 1337 for payload keying

