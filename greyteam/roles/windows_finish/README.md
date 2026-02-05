windows_post_deploy
=========
Runs various finishing tasks. Currently:
- Disables some Windows update functions
- Disables the first time log in animation
- Re-enables UAC for admins (it is disabled in windows_deploy_standards)
- Deletes the working directory
- Reboots

Requires Reboot
------------
Yes

Requirements
------------
It only makes sense to run this if you ran other tasks first.

Role Variables
--------------
Variables used:
- working_dir

Dependencies
------------
None

Example Playbook
----------------
```yaml
- name: Post Deploy Cleanup
  hosts: windows:&team_hosts
  roles:
    - windows_post_deploy
  tags:
    - windows 
    - team 
    - cleanup 
    - post_deploy_cleanup
    - post_deploy
    - wrap_it_up
```