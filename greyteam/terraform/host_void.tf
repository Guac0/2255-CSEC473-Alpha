resource "openstack_compute_instance_v2" "whinnyapolis" {
  depends_on = [openstack_networking_secgroup_v2.secgroup_blue]

  name            = "whinnyapolis"
  flavor_name     = "medium"
  key_pair        = "cdt"

  block_device {
    uuid                  = "1cde3ec3-03d3-4c17-a512-d3799ae92dad" #ubuntu2404desktop need to change to void
    source_type           = "image"
    destination_type      = "volume"
    volume_size           = 40
    boot_index            = 0
    delete_on_termination = true
  }


  network {
    uuid        = openstack_networking_network_v2.network_internal.id
    fixed_ip_v4 = "10.0.30.5"
  }

  security_groups = ["secgroup_blue"]

  # Cloud-init user setup
  user_data = file("cloud-init-ubuntu.yaml")
}
