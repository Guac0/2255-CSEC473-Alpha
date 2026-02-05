resource "openstack_networking_network_v2" "network_blue" {
    name = "network_blue"
    admin_state_up = "true"
}

resource "openstack_networking_subnet_v2" "subnet_blue" {
    name = "subnet_blue"
    network_id = "${openstack_networking_network_v2.network_blue.id}"
    cidr = "172.20.0.32/27"
    gateway_ip = "172.20.0.62"
    ip_version = 4
    enable_dhcp = "false"
    dns_nameservers = [var.dns1, var.dns2]
}

resource "openstack_networking_router_interface_v2" "router_int_blue" {
  depends_on = [openstack_networking_router_v2.router_main]
  router_id = "${openstack_networking_router_v2.router_main.id}"
  subnet_id = "${openstack_networking_subnet_v2.subnet_blue.id}"
}