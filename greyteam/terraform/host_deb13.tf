resource "openstack_compute_instance_v2" "deb13" {
  depends_on = [openstack_networking_secgroup_v2.secgroup_blue]
  for_each = var.deb13

  name        = each.value.hostname
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
    uuid        = each.value.network
    fixed_ip_v4 = each.value.ip
  }

  security_groups = ["secgroup_blue"]

  # Cloud-init user setup
  user_data = file("cloud-init-debian.yaml")
}
