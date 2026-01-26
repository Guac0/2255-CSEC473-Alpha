windows_deploy_wallpaper
=========
TODO: the majority of documentation here is the original from Connor for ISTS 2020. It requires refactoring to the latest standards.

Sets the wallpaper for users.

Requires Reboot
------------
Yes

Requirements
------------
None

Role Variables
--------------
See THIS SHOULD BE A LINK BY THE TIME YOU ARE READING THIS.... for an overview of RITSECs 
standard Ansible format.

Defaults are located in vars/main
```yaml
working_dir: "{{ win_setwallpaper_working_dir }}"
file_name: "{{ win_setwallpaper_file_name }}"
team_password: "{{ win_setwallpaper_team_password|default('StayHappy') }}" # This default exists to handle when the users var handles passwords
users: "{{ win_setwallpaper_users }}" 
```
Of special note, the users var can include item.user and item.password however this is not a requirment.

Dependencies
------------
None.

Example Playbook
----------------
A proper example playbook with proper var structure is located at A LINK SHOULD BE HERE

```yaml
- hosts: windows
  vars:
    win_setwallpaper_working_dir: 'C:\Temp\Working\Ansible'
    win_setwallpaper_file_name: "fox.jpg"
    win_setwallpaper_team_password: password
    win_setwallpaper_users: username

  roles:
    - windows_deploy_wallpaper
```
OR
```yaml
- name: Set Wallpaper
  hosts: windows:&team_hosts
  roles:
    - windows_deploy_wallpaper
  tags:
    - windows
    - team
    - wallpaper
```
License
-------
Apache-2.0

Author Information
------------------
This role was created by [Connor Leavesley](https://github.com/clev98) in 2020 for ISTS 2021.