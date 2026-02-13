resource "openstack_networking_secgroup_v2" "secgroup_blue" {
  name        = "secgroup_blue"
}

# resource "openstack_networking_secgroup_rule_v2" "secgroup_blue_rule_1" {
#   direction         = "ingress"
#   ethertype         = "IPv4"
#   #protocol          = ""
#   #port_range_min    = 0
#   #port_range_max    = 0
#   #remote_ip_prefix  = "0.0.0.0/0"
#   #remote_group_id   = ""
#   security_group_id = openstack_networking_secgroup_v2.secgroup_blue.id
# }

# resource "openstack_networking_secgroup_rule_v2" "secgroup_blue_rule_2" {
#   direction         = "ingress"
#   ethertype         = "IPv6"
#   #protocol          = ""
#   #port_range_min    = 0
#   #port_range_max    = 0
#   #remote_ip_prefix  = "0.0.0.0/0"
#   #remote_group_id   = ""
#   security_group_id = openstack_networking_secgroup_v2.secgroup_blue.id
# }

resource "openstack_networking_secgroup_rule_v2" "secgroup_blue_rule_0" {
  direction         = "ingress"
  ethertype         = "IPv4"
  remote_ip_prefix  = "172.20.0.32/27"
  security_group_id = openstack_networking_secgroup_v2.secgroup_blue.id
}
#innbound from inscope
resource "openstack_networking_secgroup_rule_v2" "secgroup_blue_rule_1" {
  direction         = "ingress"
  ethertype         = "IPv4"
  #protocol          = ""
  #port_range_min    = 0
  #port_range_max    = 0
  remote_ip_prefix  = "10.0.10.0/24"
  #remote_group_id   = ""
  security_group_id = openstack_networking_secgroup_v2.secgroup_blue.id
}

resource "openstack_networking_secgroup_rule_v2" "secgroup_blue_rule_2" {
  direction         = "ingress"
  ethertype         = "IPv4"
  #protocol          = ""
  #port_range_min    = 0
  #port_range_max    = 0
  remote_ip_prefix  = "10.0.20.0/24"
  #remote_group_id   = ""
  security_group_id = openstack_networking_secgroup_v2.secgroup_blue.id
}
resource "openstack_networking_secgroup_rule_v2" "secgroup_blue_rule_3" {
  direction         = "ingress"
  ethertype         = "IPv4"
  remote_ip_prefix  = "10.0.30.0/24"
  security_group_id = openstack_networking_secgroup_v2.secgroup_blue.id
}
#SSH from WAN/NAT
resource "openstack_networking_secgroup_rule_v2" "secgroup_blue_rule_4" {
  direction         = "ingress"
  ethertype         = "IPv4"
  protocol          = "tcp"
  port_range_min    = 22
  port_range_max    = 22
  remote_ip_prefix  = "100.65.0.0/16"
  security_group_id = openstack_networking_secgroup_v2.secgroup_blue.id
}



#outbund from inscope
resource "openstack_networking_secgroup_rule_v2" "secgroup_blue_rule_5" {
  direction         = "egress"
  ethertype         = "IPv4"
  #protocol          = ""
  #port_range_min    = 0
  #port_range_max    = 0
  remote_ip_prefix  = "10.0.10.0/24"
  #remote_group_id   = ""
  security_group_id = openstack_networking_secgroup_v2.secgroup_blue.id
}

resource "openstack_networking_secgroup_rule_v2" "secgroup_blue_rule_6" {
  direction         = "egress"
  ethertype         = "IPv4"
  #protocol          = ""
  #port_range_min    = 0
  #port_range_max    = 0
  remote_ip_prefix  = "10.0.20.0/24"
  #remote_group_id   = ""
  security_group_id = openstack_networking_secgroup_v2.secgroup_blue.id
}
resource "openstack_networking_secgroup_rule_v2" "secgroup_blue_rule_7" {
  direction         = "egress"
  ethertype         = "IPv4"
  #protocol          = ""
  #port_range_min    = 0
  #port_range_max    = 0
  remote_ip_prefix  = "10.0.30.0/24"
  #remote_group_id   = ""
  security_group_id = openstack_networking_secgroup_v2.secgroup_blue.id
}

resource "openstack_networking_secgroup_rule_v2" "secgroup_blue_rule_8" {
  direction         = "egress"
  ethertype         = "IPv4"
  protocol          = "tcp"
  port_range_min    = 443
  port_range_max    = 443
  remote_ip_prefix  = "172.20.0.100/32"
  security_group_id = openstack_networking_secgroup_v2.secgroup_blue.id
}

resource "openstack_networking_secgroup_rule_v2" "secgroup_blue_rule_9" {
  direction         = "egress"
  ethertype         = "IPv4"
  remote_ip_prefix  = "172.20.0.64/26"
  security_group_id = openstack_networking_secgroup_v2.secgroup_blue.id
}

resource "openstack_networking_secgroup_rule_v2" "secgroup_blue_rule_10" {
  direction         = "egress"
  ethertype         = "IPv4"
  remote_ip_prefix  = "100.65.0.0/16"
  security_group_id = openstack_networking_secgroup_v2.secgroup_blue.id
}

resource "openstack_networking_secgroup_rule_v2" "secgroup_blue_rule_11" {
  direction         = "egress"
  ethertype         = "IPv4"
  protocol          = "tcp"
  port_range_min    = 444
  port_range_max    = 444
  remote_ip_prefix  = "172.20.0.100/32"
  security_group_id = openstack_networking_secgroup_v2.secgroup_blue.id
}
/*
resource "openstack_networking_secgroup_rule_v2" "secgroup_blue_rule_3" {
  direction         = "egress"
  ethertype         = "IPv4"
  #protocol          = ""
  #port_range_min    = 0
  #port_range_max    = 0
  #remote_ip_prefix  = "0.0.0.0/0"
  #remote_group_id   = ""
  security_group_id = openstack_networking_secgroup_v2.secgroup_blue.id
}

resource "openstack_networking_secgroup_rule_v2" "secgroup_blue_rule_4" {
  direction         = "egress"
  ethertype         = "IPv6"
  #protocol          = ""
  #port_range_min    = 0
  #port_range_max    = 0
  #remote_ip_prefix  = "0.0.0.0/0"
  #remote_group_id   = ""
  security_group_id = openstack_networking_secgroup_v2.secgroup_blue.id
}
*/