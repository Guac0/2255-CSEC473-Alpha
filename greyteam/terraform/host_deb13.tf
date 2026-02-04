resource "openstack_compute_instance_v2" "deb13" {
  depends_on = [openstack_networking_secgroup_v2.secgroup_blue]
  
  for_each = {
    ponyville       = "10.0.10.3"
    seaddle         = "10.0.10.4"
    everfree-forest = "10.0.20.3"
    griffonstone    = "10.0.20.4"
  }

  name        = each.key
  flavor_name     = "medium"
  key_pair        = "cdt"

  block_device {
    uuid                  = "865d8624-6139-4447-bc34-312399c9d929" #debian-trixie-13
    source_type           = "image"
    destination_type      = "volume"
    volume_size           = 40
    boot_index            = 0
    delete_on_termination = true
  }

  network {
    uuid        = openstack_networking_network_v2.network_blue.id
    fixed_ip_v4 = each.value
  }

  security_groups = ["secgroup_blue"]

  # Cloud-init user setup
  user_data = file("cloud-init-debian.yaml")
}
