

resource "openstack_compute_instance_v2" "windows_server1" {
  name            = "windows_server1"
  flavor_name     = "medium"
  key_pair        = "cdt"

  block_device {
    uuid                  = "d05fa605-c188-45b8-a3d4-5bb0fe4560fa"
    source_type           = "image"
    destination_type      = "volume"
    volume_size           = 60
    boot_index            = 0
    delete_on_termination = true
  }

  network {
    name = "aan8745"
    #name = "team1"
    #fixed_ip_v4 = "10.1.1.12"
  }

  security_groups = ["default"]

  user_data = file("cloudbase-config.ps1")
}
