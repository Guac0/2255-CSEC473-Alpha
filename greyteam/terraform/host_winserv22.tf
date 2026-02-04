resource "openstack_compute_instance_v2" "winserv22" {
  depends_on = [openstack_networking_secgroup_v2.secgroup_inscope]

  for_each = {
    canterlot   = "10.0.10.1"
    appleloosa  = "10.0.10.2"
    cloudsdale  = "10.0.20.1"
    manehatten  = "10.0.20.2"
  }

  name        = each.key
  flavor_name = "large"
  key_pair    = "cdt"

  block_device {
    uuid                  = "d05fa605-c188-45b8-a3d4-5bb0fe4560fa" #winserver22
    source_type           = "image"
    destination_type      = "volume"
    volume_size           = 60
    boot_index            = 0
    delete_on_termination = true
  }


  network {
    uuid        = openstack_networking_network_v2.network_blue.id
    fixed_ip_v4 = each.value
  }

  security_groups = ["secgroup_inscope"]

  user_data = file("cloudbase-config.ps1")
}
