resource "openstack_compute_instance_v2" "fillydelphia" {
  depends_on = [openstack_networking_secgroup_v2.secgroup_blue]

  name            = "fillydelphia"
  flavor_name     = "large"
  key_pair        = "cdt"

  block_device {
    uuid                  = "f848941a-64d7-41b4-9c3d-bbddf657ef51" #windows 10, need to change to cement
    source_type           = "image"
    destination_type      = "volume"
    volume_size           = 60
    boot_index            = 0
    delete_on_termination = true
  }


  network {
    uuid        = openstack_networking_network_v2.network_internal.id
    fixed_ip_v4 = "10.0.30.6"
  }

  security_groups = ["secgroup_blue"]

  # Cloud-init user setup
  user_data = file("cloudbase-config.ps1")
}
