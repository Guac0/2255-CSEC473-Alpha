

resource "openstack_compute_instance_v2" "debian1" {
  name            = "debian1"
  #image_name      = "debian-bookworm-server"
  flavor_name     = "small.2gb"
  key_pair        = "cdt"

  block_device {
    #uuid                  = "680017c0-3c2b-4605-94d8-b5625fb3c159" #UbuntuJammy2204_new
    #uuid                  = "f6906907-6a2a-4d43-b13e-261a7697ed5c" #UbuntuNoble2404
    uuid                  = "31bb9997-5486-48f3-acf6-b5d0e4f472e0" #debian-bookworm-server
    source_type           = "image"
    destination_type      = "volume"
    volume_size           = 40
    boot_index            = 0
    delete_on_termination = true
  }

  network {
    name = "aan8745"
    #name = "team1"
    #fixed_ip_v4 = "10.1.1.11"
  }

  security_groups = ["default"]

  # Cloud-init user setup
  user_data = file("cloud-init-ubuntu.yaml")
}
