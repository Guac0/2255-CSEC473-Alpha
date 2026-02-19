resource "openstack_compute_instance_v2" "winserv22" {
  depends_on = [openstack_networking_secgroup_v2.secgroup_inscope]
  for_each = var.winserv22

  name        = each.value.hostname
  flavor_name = "xlarge" #"large"
  key_pair    = "cdt"

  block_device {
    uuid                  = "d05fa605-c188-45b8-a3d4-5bb0fe4560fa" #winserver22
    source_type           = "image"
    destination_type      = "volume"
    volume_size           = 60
    boot_index            = 0
    delete_on_termination = true
  }


  network {
    uuid        = local.network_mapping[each.value.network]
    fixed_ip_v4 = each.value.ip
  }

  security_groups = ["secgroup_inscope"]

  user_data = file("cloudbase-config.ps1")
}
