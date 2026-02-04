resource "openstack_compute_instance_v2" "canterlot" {
  depends_on = [openstack_networking_secgroup_v2.secgroup_inscope]

  name        = "canterlot"
  flavor_name = "large"
  key_pair    = "cdt"

  block_device {
    uuid                  = "d05fa605-c188-45b8-a3d4-5bb0fe4560fa"
    source_type           = "image"
    destination_type      = "volume"
    volume_size           = 100
    boot_index            = 0
    delete_on_termination = true
  }

  network {
    name = "MAIN-NAT"
  }

  network {
    uuid        = openstack_networking_network_v2.network_blue.id
    fixed_ip_v4 = "10.0.10.1"
  }

  security_groups = ["secgroup_inscope"]

  user_data = file("cloudbased-config.ps1")
}
