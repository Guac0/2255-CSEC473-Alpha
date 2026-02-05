apt update
apt install -y nano git python-is-python3 python3 python3-venv python3-pip sshpass pwgen
git clone https://github.com/Guac0/2255-CSEC473-Alpha/
curl -L https://download.documentfoundation.org/libreoffice/stable/26.2.0/win/x86_64/LibreOffice_26.2.0_Win_x86-64.msi > 2255-CSEC473-Alpha/greyteam/roles/windows_utilities/files/LibreOffice_Win_x86-64.msi
chown greyteam:greyteam -R 2255-CSEC473-Alpha
cd ./2255-CSEC473-Alpha/greyteam
python -m venv venv
source venv/bin/activate
pip3 install -r requirements.txt
activate-global-python-argcomplete
ansible-galaxy install -r requirements.yml