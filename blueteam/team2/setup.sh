echo "This script assumes that you are running on a Debian-based OS, have a blueteam user, and are currently running as root."
apt update
apt install -y nano git curl python-is-python3 python3 python3-venv python3-pip sshpass pwgen ansible
git clone https://github.com/Guac0/2255-CSEC473-Alpha/
chown blueteam:blueteam -R 2255-CSEC473-Alpha
cd ./2255-CSEC473-Alpha/blueteam/team2/ansible
python -m venv venv
source venv/bin/activate
pip3 install -r requirements.txt
activate-global-python-argcomplete
ansible-galaxy install -r requirements.yml
echo "Finished. Ansible set up at ./2255-CSEC473-Alpha/blueteam/team2/ansible"