# 2255.CSEC473.01 Alpha Greyteam

Contains the full implementation for the Rochester Institute of Technology Spring 2026's CSEC 473 Cyber Defense Techiques Section 01 Group Alpha's competition (our 'greyteam' rotation). This repository contains the full infrastructure as code implementation of our competition, which was themed after the My Little Pony franchise.

## Competition Information

This competition took the format of a semi-asymmetrical Service Uptime competition. Services started in a "good" state serving legitimate content, with the Blue Team scoring 1 point per scoring round (every minute) per good service. The Red Team was tasked with gaining and maintaining access to each system, and was scored by adding thematic malicious content to scored services. If a scored service contains malicious content (with the Red Team uploading criteria of what counts as malicious to the scoring engine), the Red Team receives 1 point per scoring round per infected service. Offline services (whether unreachable or just containing no content for either team) do not score any points for either team, although the total count of offline "points" is tracked for referential usage.

Please reference the information packets provided to the Blue (defensive) and Red (offensive) teams for full details on the competition environment, rules, access, and other information (`2255.CSEC473.01 Alpha Competition - Blue/Red Team Packet.pdf`). They are largely identical except for the Users and Remote Access sections (and minor theming differences at various points).

This README file aims to document this repo at a high level. It assumes you are already familiar with Ansible and Terraform, as explaining them is out of scope. READMEs and comments are provided where possible, but not every folder/file is fully documented due to the scope of this competition and tight deadlines (this was the first competition of the Spring semester with ~4.5 weeks of development time for a 3 credit class).

Topology:
![Image failed to load - please directly load image instead, which can be hopefully found at "./2255.CSEC473.01 Alpha Competition - Packet Excerpt - Network Topology.png"]("./2255.CSEC473.01 Alpha Competition - Packet Excerpt - Network Topology.png")

## Terraform

Terraform is used to implement each host using Infrastructure as Code principles for automation at scale. Note that the official implementation uses the Rochester Institute of Technology Cyber Range Openstack in its state as of Spring 2026, and major modifications may have to be taken if you plan on using a different cloud provider.

The Red Team was provided with a shared Openstack network instance that was manually created and joined to the competition router, and as such is not present in the Terraform.

### Setup

- Navigate to the terraform/ folder.
- Update config.tf with information for your cloud provider. You will likely need to provide an appcred file or clouds.yaml file (appcred source script seems to work best for the Cyber Range Openstack).
- If you are not using Openstack, you will likely need to update almost every Terraform file to use the equivalent for your provider. If you are using Openstack, carry on with the following steps.
- Upload an ssh key with the identifer "cdt" to your environment.
- If you are using a different Openstack instance than the RIT cyber range, you will likely need to update the volume identifers for each provisioned OS in the hosts files. Additionally, each host has been provisioned with a large amount of resources due to the abundance of RAM/CPU/storage available; you may wish to decrease this to suit your provider.
- You can change generic information about the inscope hosts by modifying the terraform.tfvars file. Other changes will have to be made in each individual resource file.
- Once your changes have been made, run `terraform init` and `terraform apply` to deploy the infrastructure.

## Ansible

After each system is initiated with Terraform, Ansible is used to deploy the actual competition implementation on each host. Note that this README file sits in the root of the ansible directory as it does not have a separate folder.

### Setup
Automated setup:
curl https://raw.githubusercontent.com/Guac0/2255-CSEC473-Alpha/refs/heads/main/greyteam/setup.sh | bash

Manual setup:
apt update
apt install -y nano git python-is-python3 python3 python3-venv python3-pip sshpass pwgen #openjdk-8-jdk
git clone https://github.com/Guac0/2255-CSEC473-Alpha/
cd ./2255-CSEC473-Alpha/greyteam
python -m venv venv
source venv/bin/activate
pip3 install -r requirements.txt
activate-global-python-argcomplete
ansible-galaxy install -r requirements.yml

### Usage

To install the whole infrastructure:
ansible-playbook -i inventory.yaml playbook.yaml

For finer grained control, please review the Ansible roles available in playbook.yaml. If you wish to make changes to the Ansible implementation, first review if your intended changes can be implemented via changing the Ansible variables in group_vars/ or in the variables folder (defaults/main.yaml) in each role. If you make changes to host quantities/locations using Terraform, make sure to update the inventory.yaml file accordingly.

### Useful Command Reference
ansible -c to check - https://docs.ansible.com/ansible/latest/community/other_tools_and_programs.html#validate-playbook-tools
ansible-lint verify-apache.yml

ansible-playbook -i inventory.yaml playbook.yaml -t ping
ansible-playbook -i inventory/inventory.yaml playbook.yaml -t flags -l unix -vvvv 
ansible-playbook -i inventory.yaml playbook.yaml -t tag -vv -c