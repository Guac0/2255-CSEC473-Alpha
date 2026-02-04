apt update
apt install -y nano git python-is-python3 python3 python3-venv python3-pip sshpass pwgen openjdk-8-jdk
git clone https://github.com/Guac0/2255-CSEC473-Alpha/
cd ./2255-CSEC473-Alpha/greyteam
python -m venv venv
source venv/bin/activate
pip3 install -r requirements.txt
activate-global-python-argcomplete
ansible-galaxy install -r requirements.yml