# 2255.CSEC473.01 Alpha Greyteam
## Setup
apt update
apt install -y python3 python3-pip sshpass pwgen openjdk-8-jdk
git clone <repo>
cd <repo>
python -m venv venv
source venv/bin/activate
pip3 install ansible argcomplete pywinrm passlib
activate-global-python-argcomplete
ansible-galaxy install -r requirements.yml

## Useful Commands
ansible -c to check - https://docs.ansible.com/ansible/latest/community/other_tools_and_programs.html#validate-playbook-tools
ansible-lint verify-apache.yml

ansible-playbook -i inventory/inventory-rcr.yaml -t flags -l unix -vvvv playbook_rcr.yaml
ansible-playbook -i inventory.yaml playbook.yaml -t tag -vv -c
ansible-playbook -i inventory/ -f 200 -l {team_numbers} -t {role_tag} -vv windows.yaml
ansible-playbook -i inventory.yaml -t {role_tag} playbook.yaml -vv