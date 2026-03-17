resource "openstack_compute_instance_v2" "deb12_2" {
  depends_on = [openstack_networking_secgroup_v2.secgroup_blue2]
  for_each = var.deb12_2

  name        = each.value.hostname
  flavor_name     = "large"
  key_pair        = "cdt"

  block_device {
    uuid                  = "31bb9997-5486-48f3-acf6-b5d0e4f472e0" #debian-bookworm-server
    #uuid                  = "865d8624-6139-4447-bc34-312399c9d929" #debian-trixie-13
    source_type           = "image"
    destination_type      = "volume"
    volume_size           = 40
    boot_index            = 0
    delete_on_termination = true
  }

  network {
    uuid        = local.network_mapping[each.value.network]
    fixed_ip_v4 = each.value.ip
  }

  security_groups = ["secgroup_blue2"]

  # Cloud-init user setup
  user_data = file("cloud-init-debian.yaml")
}
