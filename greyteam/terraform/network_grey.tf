resource "openstack_networking_network_v2" "network_grey" {
    name = "network_grey"
    admin_state_up = "true"
}

resource "openstack_networking_subnet_v2" "subnet_grey" {
    name = "subnet_grey"
    network_id = "${openstack_networking_network_v2.network_grey.id}"
    cidr = "172.20.0.64/26"
    gateway_ip = "172.20.0.126"
    ip_version = 4
    enable_dhcp = "false"
    dns_nameservers = [var.dns1, var.dns2]
}

resource "openstack_networking_router_interface_v2" "router_int_grey" {
  depends_on = [openstack_networking_router_v2.router_main]
  router_id = "${openstack_networking_router_v2.router_main.id}"
  subnet_id = "${openstack_networking_subnet_v2.subnet_grey.id}"
}