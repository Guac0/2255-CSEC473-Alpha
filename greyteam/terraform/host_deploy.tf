resource "openstack_compute_instance_v2" "deploy" {
  depends_on = [openstack_networking_secgroup_v2.secgroup_grey]

  name            = "deploy"
  flavor_name     = "xlarge"
  key_pair        = "cdt"

  block_device {
    uuid                  = "70de79be-69be-45dc-b956-f15dbe194ccd" #debian-trixie-server
    #uuid                  = "865d8624-6139-4447-bc34-312399c9d929" #debian-trixie-13
    source_type           = "image"
    destination_type      = "volume"
    volume_size           = 75
    boot_index            = 0
    delete_on_termination = true
  }

  network {
    name        = "MAIN-NAT"
  }
  network {
    uuid        = openstack_networking_network_v2.network_grey.id
    fixed_ip_v4 = "172.20.0.80"
  }

  security_groups = ["secgroup_grey"]

  # Cloud-init user setup
  user_data = file("cloud-init-debian.yaml")
}
