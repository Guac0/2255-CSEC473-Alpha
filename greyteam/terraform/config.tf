# Define required providers
terraform {
required_version = ">= 0.14.0"
  required_providers {
    openstack = {
      source  = "terraform-provider-openstack/openstack"
      version = "~> 1.53.0"
    }
  }
}

# Configure the OpenStack Provider
#provider "openstack" {
#  cloud = "openstack"
  #tenant_name = "aan8745"
#}
provider "openstack" {
  tenant_name = "cdtalpha"
  auth_url    = "https://openstack.cyberrange.rit.edu:5000/v3/"
}