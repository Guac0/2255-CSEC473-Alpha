# tasks

This folder contains files with the actual tasks that Ansible will execute on the destination machine.
By default, Ansible will only execute the contents of "main.yaml". This file must source any other task files that you may want.
For ease of use, we will standardize on main.yaml not containing any other tasks. Instead, tasks will be split up into other files that are then sourced by main.yaml.
This allows use to easily read and modify (without merge conflicts) our tasks.

old shit:

# 3 Desktop shortcuts for installed applications

# Create /etc/skel/Desktop so any future users created on the box inherit these shortcuts (might delete once all users are finalized)
#- name: Fix desktop skeleton path
#  ansible.builtin.file:
#    path: /etc/skel/Desktop
#    state: directory
#    mode: "0755"
#  become: true

# Pulls /etc/passwd into ansible_facts.getent_passwd so we can verify usernames exist
# also prevents errors when looping over non-existent users
#- name: Load passwd entries (so we can check users exist)
#  ansible.builtin.getent:
#    database: passwd
#  become: true
#
# Creates /usr/skel/Desktop (default on path on ubuntu)
#- name: Ensure desktop exsists for all users
#  ansible.builtin.file:
#    path: /usr/skel/Desktop
#    state: directory
#    mode: '0755'
#  become: true

# Make sure each target user has a Desktop folder so we can drop shortcuts there
#- name: Ensure desktop exisits for existing users
#  ansible.builtin.file:
#    path: "/home/{{ item }}/Desktop"
#    state: directory
#    owner: "{{ item }}"
#    group: "{{ item }}"
#    mode: '0755'
#  loop: "{{ linux_desktop_users }}"
#  when: item in ansible_facts.getent_passwd
#  become: true


# Create simple .desktop launchers that run each program by name
#- name: Create app launchers in /etc/skel/Desktop
#  ansible.builtin.copy:
#    dest: "/etc/skel/Desktop/{{ item.filename }}"
#    mode: "0755"
#    content: |
#      [Desktop Entry]
#      Type=Application
#      Name={{ item.name }}
#      Exec={{ item.exec }}
#      Terminal=false
#  loop:
#    - { name: "Thunderbird", filename: "Thunderbird.desktop", exec: "thunderbird" }
#    - { name: "LibreOffice", filename: "LibreOffice.desktop", exec: "libreoffice" }
#    - { name: "FileZilla", filename: "FileZilla.desktop", exec: "filezilla" }
#    - { name: "HexChat", filename: "HexChat.desktop", exec: "hexchat" }
#  become: true

# Copies the launcher templates from /etc/skel/Desktop into every existing user’s Desktop folder
# Uses product() so we do each user times each launcher without writing 4 separate tasks
#- name: Copy launchers to each user Desktop
#  ansible.builtin.copy:
#    remote_src: true
#    src: "/etc/skel/Desktop/{{ item.1 }}"
#    dest: "/home/{{ item.0 }}/Desktop/{{ item.1 }}"
#    owner: "{{ item.0 }}"
#    group: "{{ item.0 }}"
#    mode: "0755"
#  loop: "{{ linux_desktop_users | product(['Thunderbird.desktop','LibreOffice.desktop','FileZilla.desktop','HexChat.desktop']) | list }}"
#  when: item.0 in ansible_facts.getent_passwd
#  become: true