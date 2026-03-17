resource "openstack_networking_network_v2" "network_core2" {
    name = "network_core2"
    admin_state_up = "true"
}

resource "openstack_networking_subnet_v2" "subnet_core2" {
    name = "subnet_core2"
    network_id = "${openstack_networking_network_v2.network_core2.id}"
    cidr = "10.2.1.0/24"
    gateway_ip = "10.2.1.254"
    ip_version = 4
    enable_dhcp = "false"
    dns_nameservers = [var.dns1, var.dns2]
}

resource "openstack_networking_router_interface_v2" "router_int_core2" {
  depends_on = [openstack_networking_router_v2.router_main2]
  router_id = "${openstack_networking_router_v2.router_main2.id}"
  subnet_id = "${openstack_networking_subnet_v2.subnet_core2.id}"
}