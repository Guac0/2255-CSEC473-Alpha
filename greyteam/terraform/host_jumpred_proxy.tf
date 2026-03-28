resource "openstack_compute_instance_v2" "jumpred_proxy" {
  depends_on = [openstack_networking_secgroup_v2.secgroup_red_proxy]
  for_each = var.jumpred_proxy

  name            = each.value.hostname
  flavor_name     = "large"
  key_pair        = "cdt"

  block_device {
    uuid                  = "70de79be-69be-45dc-b956-f15dbe194ccd" #debian-trixie-server
    #uuid                  = "6cccb629-50af-4068-81ff-2e41c109f095" #ubuntu2204desktop
    source_type           = "image"
    destination_type      = "volume"
    volume_size           = 40
    boot_index            = 0
    delete_on_termination = true
  }

  network {
    uuid        = local.network_mapping[each.value.network]
    fixed_ip_v4 = each.value.ip
  }

  security_groups = ["secgroup_red_proxy"]

  # Cloud-init user setup
  user_data = file("cloud-init-ubuntu-red.yaml")
}
