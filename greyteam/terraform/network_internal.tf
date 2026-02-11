resource "openstack_networking_network_v2" "network_internal" {
    name = "network_internal"
    admin_state_up = "true"
}

resource "openstack_networking_subnet_v2" "subnet_internal" {
    name = "subnet_internal"
    network_id = "${openstack_networking_network_v2.network_internal.id}"
    cidr = "10.0.20.0/24"
    ip_version = 4
    enable_dhcp = "false"
    dns_nameservers = [var.dns1, var.dns2]
}

resource "openstack_networking_router_interface_v2" "router_int_internal" {
  depends_on = [openstack_networking_router_v2.router_main]
  router_id = "${openstack_networking_router_v2.router_main.id}"
  subnet_id = "${openstack_networking_subnet_v2.subnet_internal.id}"
}