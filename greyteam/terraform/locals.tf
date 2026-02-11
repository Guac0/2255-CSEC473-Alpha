locals {
  network_mapping = {
    "core" = openstack_networking_network_v2.network_core.id
    "dmz"  = openstack_networking_network_v2.network_dmz.id
    "internal" = openstack_networking_network_v2.network_internal.id
  }
}