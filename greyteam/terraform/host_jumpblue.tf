resource "openstack_compute_instance_v2" "jumpblue" {
  depends_on = [openstack_networking_secgroup_v2.secgroup_blue]
  for_each = var.jumpblue

  name            = each.value.hostname
  flavor_name     = "medium"
  key_pair        = "cdt"

  block_device {
    uuid                  = "1cde3ec3-03d3-4c17-a512-d3799ae92dad" #ubuntu2404desktop
    #uuid                  = "6cccb629-50af-4068-81ff-2e41c109f095" #ubuntu2204desktop
    source_type           = "image"
    destination_type      = "volume"
    volume_size           = 30
    boot_index            = 0
    delete_on_termination = true
  }

  network {
    name        = "MAIN-NAT"
  }
  network {
    uuid        = openstack_networking_network_v2.network_blue.id
    fixed_ip_v4 = each.value.ip
  }

  security_groups = ["secgroup_blue"]

  # Cloud-init user setup
  user_data = file("cloud-init-ubuntu.yaml")
}
