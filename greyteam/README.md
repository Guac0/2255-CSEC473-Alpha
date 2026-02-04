# 2255.CSEC473.01 Alpha Greyteam
## Setup
curl https://raw.githubusercontent.com/Guac0/2255-CSEC473-Alpha/refs/heads/main/greyteam/setup.sh | bash
or:

apt update
apt install -y nano git python-is-python3 python3 python3-venv python3-pip sshpass pwgen openjdk-8-jdk
git clone https://github.com/Guac0/2255-CSEC473-Alpha/
cd ./2255-CSEC473-Alpha/greyteam
python -m venv venv
source venv/bin/activate
pip3 install -r requirements.txt
activate-global-python-argcomplete
ansible-galaxy install -r requirements.yml

## Useful Commands
ansible -c to check - https://docs.ansible.com/ansible/latest/community/other_tools_and_programs.html#validate-playbook-tools
ansible-lint verify-apache.yml

ansible-playbook -i inventory.yaml playbook.yaml -t ping
ansible-playbook -i inventory/inventory.yaml playbook.yaml -t flags -l unix -vvvv 
ansible-playbook -i inventory.yaml playbook.yaml -t tag -vv -c