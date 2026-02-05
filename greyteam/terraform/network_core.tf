resource "openstack_networking_network_v2" "network_core" {
    name = "network_core"
    admin_state_up = "true"
}

resource "openstack_networking_subnet_v2" "subnet_core" {
    name = "subnet_core"
    network_id = "${openstack_networking_network_v2.network_core.id}"
    cidr = "10.0.10.0/24"
    gateway_ip = "10.0.10.254"
    ip_version = 4
    enable_dhcp = "false"
    dns_nameservers = [var.dns1, var.dns2]
}

resource "openstack_networking_router_interface_v2" "router_int_core" {
  depends_on = [openstack_networking_router_v2.router_main]
  router_id = "${openstack_networking_router_v2.router_main.id}"
  subnet_id = "${openstack_networking_subnet_v2.subnet_core.id}"
}