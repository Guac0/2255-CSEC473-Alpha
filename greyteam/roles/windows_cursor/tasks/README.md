# tasks

This folder contains files with the actual tasks that Ansible will execute on the destination machine.
By default, Ansible will only execute the contents of "main.yaml". This file must source any other task files that you may want.
For ease of use, we will standardize on main.yaml not containing any other tasks. Instead, tasks will be split up into other files that are then sourced by main.yaml.
This allows use to easily read and modify (without merge conflicts) our tasks.