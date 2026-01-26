resource "openstack_compute_instance_v2" "deploy" {
  name            = "deploy"
  flavor_name     = "small.2gb"
  #key_pair        = "guac_irsec_2025"

  block_device {
    #uuid                  = "a96980db-1cda-40d6-bb2e-ac26d445e6bd" #UbuntuJammy2204-Desktop
    uuid                  = "1cde3ec3-03d3-4c17-a512-d3799ae92dad" #UbuntuNobleDesktop
    source_type           = "image"
    destination_type      = "volume"
    volume_size           = 65
    boot_index            = 0
    delete_on_termination = true
  }

  network {
    name = "MAIN-NAT"
    #name = "deploy"
    #fixed_ip_v4 = "10.1.100.1"
  }

  security_groups = ["default"]

  # Cloud-init user setup
  user_data = file("cloud-init-ubuntu.yaml")
}
