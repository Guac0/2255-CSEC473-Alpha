resource "openstack_compute_instance_v2" "jumpgrey" {
  depends_on = [openstack_networking_secgroup_v2.secgroup_grey]
  for_each = var.jumpgrey

  name            = each.value.hostname
  flavor_name     = "medium"
  key_pair        = "cdt"

  block_device {
    uuid                  = "1cde3ec3-03d3-4c17-a512-d3799ae92dad" #ubuntu2404desktop
    source_type           = "image"
    destination_type      = "volume"
    volume_size           = 25
    boot_index            = 0
    delete_on_termination = true
  }

  network {
    name        = "MAIN-NAT"
  }
  network {
    uuid        = openstack_networking_network_v2.network_grey.id
    fixed_ip_v4 = each.value.ip
  }

  security_groups = ["secgroup_grey"]

  # Cloud-init user setup
  user_data = file("cloud-init-ubuntu.yaml")
}
