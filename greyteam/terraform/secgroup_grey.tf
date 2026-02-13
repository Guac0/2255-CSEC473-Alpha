resource "openstack_networking_secgroup_v2" "secgroup_grey" {
  name        = "secgroup_grey"
}

############
# all outbound
############
resource "openstack_networking_secgroup_rule_v2" "grey_egress_all" {
  direction         = "egress"
  ethertype         = "IPv4"
  remote_ip_prefix  = "0.0.0.0/0"
  security_group_id = openstack_networking_secgroup_v2.secgroup_grey.id
}
############
# inbound 443
############
resource "openstack_networking_secgroup_rule_v2" "grey_ingress_443" {
  direction         = "ingress"
  ethertype         = "IPv4"
  protocol          = "tcp"
  port_range_min    = 443
  port_range_max    = 443
  remote_ip_prefix  = "172.20.0.0/24"
  security_group_id = openstack_networking_secgroup_v2.secgroup_grey.id
}
############
# inbound 444
############
resource "openstack_networking_secgroup_rule_v2" "grey_ingress_444" {
  direction         = "ingress"
  ethertype         = "IPv4"
  protocol          = "tcp"
  port_range_min    = 444
  port_range_max    = 444
  remote_ip_prefix  = "172.20.0.0/24"
  security_group_id = openstack_networking_secgroup_v2.secgroup_grey.id
}

# resource "openstack_networking_secgroup_rule_v2" "secgroup_grey_rule_1" {
#   direction         = "ingress"
#   ethertype         = "IPv4"
#   #protocol          = ""
#   #port_range_min    = 0
#   #port_range_max    = 0
#   #remote_ip_prefix  = "0.0.0.0/0"
#   #remote_group_id   = ""
#   security_group_id = openstack_networking_secgroup_v2.secgroup_grey.id
# }

# resource "openstack_networking_secgroup_rule_v2" "secgroup_grey_rule_2" {
#   direction         = "ingress"
#   ethertype         = "IPv6"
#   #protocol          = ""
#   #port_range_min    = 0
#   #port_range_max    = 0
#   #remote_ip_prefix  = "0.0.0.0/0"
#   #remote_group_id   = ""
#   security_group_id = openstack_networking_secgroup_v2.secgroup_grey.id
# }


resource "openstack_networking_secgroup_rule_v2" "secgroup_grey_rule_3" {
  direction         = "egress"
  ethertype         = "IPv4"
  #protocol          = ""
  #port_range_min    = 0
  #port_range_max    = 0
  #remote_ip_prefix  = "0.0.0.0/0"
  #remote_group_id   = ""
  security_group_id = openstack_networking_secgroup_v2.secgroup_grey.id
}

# resource "openstack_networking_secgroup_rule_v2" "secgroup_grey_rule_4" {
#   direction         = "egress"
#   ethertype         = "IPv6"
#   #protocol          = ""
#   #port_range_min    = 0
#   #port_range_max    = 0
#   #remote_ip_prefix  = "0.0.0.0/0"
#   #remote_group_id   = ""
#   security_group_id = openstack_networking_secgroup_v2.secgroup_grey.id
# }
