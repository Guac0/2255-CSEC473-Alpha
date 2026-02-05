# NGIRCD IRC Server Role

This Ansible role installs and configures the NGIRCD IRC server on a Linux Host.

## Features

1. Installs the NGIRCD package using apt.
2. Starts and enables the NGIRCD service automatically.
3. Deploys a custom configuration with IRC admin user cadence using our team password.

## Usage

- Add role to `playbook.yaml` under the Linux services section:
```yaml
- name: Deploy NGIRCD IRC Server
  hosts: everfree-forest
  roles:
    - linux_ngircd
  tags:
    - ngircd
    - linux
    - inscope

