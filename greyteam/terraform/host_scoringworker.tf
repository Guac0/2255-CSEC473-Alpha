resource "openstack_compute_instance_v2" "scoringworker" {
  depends_on = [openstack_networking_secgroup_v2.secgroup_grey]
  for_each = var.scoringworker

  name            = each.value.hostname
  flavor_name     = "medium"
  key_pair        = "cdt"

  block_device {
    uuid                  = "612bfbe6-7404-4e77-9d2a-0c7705e6b539" #debian-trixie-server
    source_type           = "image"
    destination_type      = "volume"
    volume_size           = 30
    boot_index            = 0
    delete_on_termination = true
  }

  network {
    uuid        = openstack_networking_network_v2.network_grey.id
    fixed_ip_v4 = each.value.ip
  }

  security_groups = ["secgroup_grey"]

  # Cloud-init user setup
  user_data = file("cloud-init-debian.yaml")
}
