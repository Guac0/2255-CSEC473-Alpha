resource "openstack_networking_network_v2" "network_red_proxy" {
    name = "network_red_proxy"
    admin_state_up = "true"
}

resource "openstack_networking_subnet_v2" "subnet_red_proxy" {
    name = "subnet_red_proxy"
    network_id = "${openstack_networking_network_v2.network_red_proxy.id}"
    cidr = "192.168.50.0/24"
    gateway_ip = "192.168.50.254"
    ip_version = 4
    enable_dhcp = "false"
    dns_nameservers = [var.dns1, var.dns2]
}

resource "openstack_networking_router_interface_v2" "router_int_red_proxy" {
  depends_on = [openstack_networking_router_v2.router_main]
  router_id = "${openstack_networking_router_v2.router_main.id}"
  subnet_id = "${openstack_networking_subnet_v2.subnet_red_proxy.id}"
}