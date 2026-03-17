locals {
  network_mapping = {
    "blue" = openstack_networking_network_v2.network_blue2.id
    "core" = openstack_networking_network_v2.network_core2.id
    #"dmz"  = openstack_networking_network_v2.network_dmz.id
    #"internal" = openstack_networking_network_v2.network_internal.id
  }
}