resource "openstack_networking_network_v2" "network_red" {
    name = "network_red"
    admin_state_up = "true"
}

resource "openstack_networking_subnet_v2" "subnet_red" {
    name = "subnet_red"
    network_id = "${openstack_networking_network_v2.network_red.id}"
    cidr = "192.168.10.0/24"
    gateway_ip = "192.168.10.254"
    ip_version = 4
    enable_dhcp = "false"
    dns_nameservers = [var.dns1, var.dns2]
}

resource "openstack_networking_router_interface_v2" "router_int_red" {
  depends_on = [openstack_networking_router_v2.router_main]
  router_id = "${openstack_networking_router_v2.router_main.id}"
  subnet_id = "${openstack_networking_subnet_v2.subnet_red.id}"
}