windows_deploy_local_users
=========
Add local admins and users to a system. Creates the default admins Administrator and Admin, plus any other custom users that are defined. Note that all users belong to the "Remote Desktop Users" group.

Requires Reboot
------------
No

Requirements
------------
None

Role Variables
--------------
Variables used:
- team_password
- local_admins
- local_users

Dependencies
------------
None

Example Playbook
----------------
```yaml
- name: Create Local Users
  hosts: windows:&team_hosts:!win_dc
  roles:
    - windows_create_local_users
  tags: 
  - never
  - team
  - windows
  - team_local_users
```