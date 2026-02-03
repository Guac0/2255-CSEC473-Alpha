resource "openstack_networking_network_v2" "network_dmz" {
    name = "network_dmz"
    admin_state_up = "true"
}

resource "openstack_networking_subnet_v2" "subnet_dmz" {
    name = "subnet_dmz"
    network_id = "${openstack_networking_network_v2.network_dmz.id}"
    cidr = "10.0.30.0/24"
    ip_version = 4
    enable_dhcp = "false"
    dns_nameservers = [var.dns1, var.dns2]
}

resource "openstack_networking_router_interface_v2" "router_int_dmz" {
  depends_on = [openstack_networking_router_v2.router_main]
  router_id = "${openstack_networking_router_v2.router_main.id}"
  subnet_id = "${openstack_networking_subnet_v2.subnet_dmz.id}"
}