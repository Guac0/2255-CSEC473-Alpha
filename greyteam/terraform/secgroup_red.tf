resource "openstack_networking_secgroup_v2" "secgroup_red" {
  name        = "secgroup_red"
}

resource "openstack_networking_secgroup_rule_v2" "secgroup_red_rule_1" {
  direction         = "ingress"
  ethertype         = "IPv4"
  #protocol          = ""
  #port_range_min    = 0
  #port_range_max    = 0
  #remote_ip_prefix  = "0.0.0.0/0"
  #remote_group_id   = ""
  security_group_id = openstack_networking_secgroup_v2.secgroup_red.id
}

resource "openstack_networking_secgroup_rule_v2" "secgroup_red_rule_2" {
  direction         = "ingress"
  ethertype         = "IPv6"
  #protocol          = ""
  #port_range_min    = 0
  #port_range_max    = 0
  #remote_ip_prefix  = "0.0.0.0/0"
  #remote_group_id   = ""
  security_group_id = openstack_networking_secgroup_v2.secgroup_red.id
}

/*
resource "openstack_networking_secgroup_rule_v2" "secgroup_red_rule_3" {
  direction         = "egress"
  ethertype         = "IPv4"
  #protocol          = ""
  #port_range_min    = 0
  #port_range_max    = 0
  #remote_ip_prefix  = "0.0.0.0/0"
  #remote_group_id   = ""
  security_group_id = openstack_networking_secgroup_v2.secgroup_red.id
}

resource "openstack_networking_secgroup_rule_v2" "secgroup_red_rule_4" {
  direction         = "egress"
  ethertype         = "IPv6"
  #protocol          = ""
  #port_range_min    = 0
  #port_range_max    = 0
  #remote_ip_prefix  = "0.0.0.0/0"
  #remote_group_id   = ""
  security_group_id = openstack_networking_secgroup_v2.secgroup_red.id
}
*/