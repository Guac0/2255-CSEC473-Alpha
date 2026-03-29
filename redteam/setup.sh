echo "This script assumes that you are running on a Debian-based OS, have a redteam user, and are currently running as root."
apt update
apt install -y nano git curl python-is-python3 python3 python3-venv python3-pip sshpass pwgen ansible
git clone https://github.com/Guac0/2255-CSEC473-Alpha/
chown redteam:redteam -R 2255-CSEC473-Alpha
cd ./2255-CSEC473-Alpha/redteam/ansible
python -m venv venv
source venv/bin/activate
pip3 install -r requirements.txt
activate-global-python-argcomplete
ansible-galaxy install -r requirements.yml
chown redteam:redteam -R .
echo "Finished. Ansible and venv set up at ./2255-CSEC473-Alpha/redteam/ansible. Make sure to source venv/bin/activate before running Ansible tasks."