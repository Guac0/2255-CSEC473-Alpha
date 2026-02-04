resource "openstack_compute_instance_v2" "win10" {
  depends_on = [openstack_networking_secgroup_v2.secgroup_inscope]
  
  for_each = {
    baltimare       = "10.0.30.1"
    neighara-falls  = "10.0.30.2"
  }

  name        = each.key
  flavor_name = "medium"
  key_pair    = "cdt"

  block_device {
    uuid                  = "f848941a-64d7-41b4-9c3d-bbddf657ef51" #windows 10
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
