resource "openstack_compute_instance_v2" "jumpbox" {
  name            = "jumpbox"
  flavor_name     = "small.2gb"
  #key_pair        = "guac_irsec_2025"

  block_device {
    #uuid                  = "680017c0-3c2b-4605-94d8-b5625fb3c159" #UbuntuJammy2204_new
    #uuid                  = "f6906907-6a2a-4d43-b13e-261a7697ed5c" #UbuntuNoble2404
    uuid                  = "839999cb-769c-4b7c-a7d1-07139ccb98f6" #UbuntuNobleServer
    source_type           = "image"
    destination_type      = "volume"
    volume_size           = 20
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


#resource "openstack_compute_floatingip_associate_v2" "fip_associate" {
#  floating_ip = "129.21.21.115"
#  instance_id = openstack_compute_instance_v2.jumpbox.id
#}