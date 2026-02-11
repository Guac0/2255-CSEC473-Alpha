resource "openstack_compute_instance_v2" "crystalempire" {
  depends_on = [openstack_networking_secgroup_v2.secgroup_blue]

  name            = "crystalempire"
  flavor_name     = "medium"
  key_pair        = "cdt"

  block_device {
    uuid                  = "1cde3ec3-03d3-4c17-a512-d3799ae92dad" #ubuntu2404desktop need to change to chachyos
    source_type           = "image"
    destination_type      = "volume"
    volume_size           = 40
    boot_index            = 0
    delete_on_termination = true
  }


  network {
    uuid        = openstack_networking_network_v2.network_blue.id
    fixed_ip_v4 = "10.0.10.6"
  }

  security_groups = ["secgroup_blue"]

  # Cloud-init user setup
  user_data = file("cloud-init-ubuntu.yaml")
}
