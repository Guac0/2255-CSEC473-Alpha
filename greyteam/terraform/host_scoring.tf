resource "openstack_compute_instance_v2" "scoring" {
  depends_on = [openstack_networking_secgroup_v2.secgroup_grey]

  name            = "scoring"
  flavor_name     = "large"
  key_pair        = "cdt"

  block_device {
    uuid                  = "612bfbe6-7404-4e77-9d2a-0c7705e6b539" #debian-trixie-server
    source_type           = "image"
    destination_type      = "volume"
    volume_size           = 75
    boot_index            = 0
    delete_on_termination = true
  }

  network {
    uuid        = openstack_networking_network_v2.network_grey.id
    fixed_ip_v4 = "172.20.0.100"
  }

  security_groups = ["secgroup_grey"]

  # Cloud-init user setup
  user_data = file("cloud-init-ubuntu.yaml")
}
