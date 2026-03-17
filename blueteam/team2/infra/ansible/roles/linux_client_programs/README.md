Author: Darius Flontas (daf2478)
linux_client_programs

Installs and exposes basic workstation client software on Linux employee workstations for the CDT comp environment

What this role does
    -Installs common workstation apps:
      -Thunderbird
      -LibreOffice
      -FileZilla
      -HexChat
    -Verifies connectivity from the workstation to:
      -FTP service (host/port from group_vars)
      -IRC service (host/port from group_vars)
    -Creates simple desktop launcher files and copies them to each user listed in "linux_desktop_users"

Where it lives
    "greyteam/roles/linux_client_programs/"

Variables to customize
    Set these in "greyteam/group_vars/linux.yaml":
        -"ftp_host": crystal-empire
        -"ftp_port": 21
        -"irc_host": everfree-forest
        -"irc_port": 6667
        -"linux_desktop_users": list of existing local usernames that should get Desktop icons

Package list lives in:
    "greyteam/roles/linux_client_programs/defaults/main.yaml" as "linux_client_programs_packages"

How to run
    From the greyteam directory:

    bash:
        ansible-playbook -i inventory.yaml playbook.yaml --tags utilities_linux