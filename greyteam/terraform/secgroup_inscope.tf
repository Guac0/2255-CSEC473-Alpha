resource "openstack_networking_secgroup_v2" "secgroup_inscope" {
  name        = "secgroup_inscope"
}

resource "openstack_networking_secgroup_rule_v2" "secgroup_inscope_rule_1" {
  direction         = "ingress"
  ethertype         = "IPv4"
  #protocol          = ""
  #port_range_min    = 0
  #port_range_max    = 0
  #remote_ip_prefix  = "0.0.0.0/0"
  #remote_group_id   = ""
  security_group_id = openstack_networking_secgroup_v2.secgroup_inscope.id
}

resource "openstack_networking_secgroup_rule_v2" "secgroup_inscope_rule_2" {
  direction         = "ingress"
  ethertype         = "IPv6"
  #protocol          = ""
  #port_range_min    = 0
  #port_range_max    = 0
  #remote_ip_prefix  = "0.0.0.0/0"
  #remote_group_id   = ""
  security_group_id = openstack_networking_secgroup_v2.secgroup_inscope.id
}

/*
resource "openstack_networking_secgroup_rule_v2" "secgroup_inscope_rule_3" {
  direction         = "egress"
  ethertype         = "IPv4"
  #protocol          = ""
  #port_range_min    = 0
  #port_range_max    = 0
  #remote_ip_prefix  = "0.0.0.0/0"
  #remote_group_id   = ""
  security_group_id = openstack_networking_secgroup_v2.secgroup_inscope.id
}

resource "openstack_networking_secgroup_rule_v2" "secgroup_inscope_rule_4" {
  direction         = "egress"
  ethertype         = "IPv6"
  #protocol          = ""
  #port_range_min    = 0
  #port_range_max    = 0
  #remote_ip_prefix  = "0.0.0.0/0"
  #remote_group_id   = ""
  security_group_id = openstack_networking_secgroup_v2.secgroup_inscope.id
}
*/


# resource "openstack_networking_secgroup_v2" "secgroup_inscope" {
#   name = "secgroup_inscope"
# }

# ###########
# # Allow ALL inbound
# ###########

# resource "openstack_networking_secgroup_rule_v2" "inscope_ingress_all" {
#   direction         = "ingress"
#   ethertype         = "IPv4"
#   remote_ip_prefix  = "0.0.0.0/0"
#   security_group_id = openstack_networking_secgroup_v2.secgroup_inscope.id
# }

# ###########
# # Outbound to scoring server (443)
# ###########


# resource "openstack_networking_secgroup_rule_v2" "inscope_scoring_443" {
#   direction         = "egress"
#   ethertype         = "IPv4"
#   protocol          = "tcp"
#   port_range_min    = 443
#   port_range_max    = 443
#   remote_ip_prefix  = "172.20.0.100/32"
#   security_group_id = openstack_networking_secgroup_v2.secgroup_inscope.id
# }

# ###########
# # Outbound to Blue except 22
# ###########


# resource "openstack_networking_secgroup_rule_v2" "inscope_blue_tcp_low" {
#   direction         = "egress"
#   ethertype         = "IPv4"
#   protocol          = "tcp"
#   port_range_min    = 1
#   port_range_max    = 21
#   remote_ip_prefix  = "172.20.0.32/27"
#   security_group_id = openstack_networking_secgroup_v2.secgroup_inscope.id
# }

# resource "openstack_networking_secgroup_rule_v2" "inscope_blue_tcp_high" {
#   direction         = "egress"
#   ethertype         = "IPv4"
#   protocol          = "tcp"
#   port_range_min    = 23
#   port_range_max    = 65535
#   remote_ip_prefix  = "172.20.0.32/27"
#   security_group_id = openstack_networking_secgroup_v2.secgroup_inscope.id
# }

# ###########
# # All outbound to Grey
# ################################

# resource "openstack_networking_secgroup_rule_v2" "inscope_grey_all" {
#   direction         = "egress"
#   ethertype         = "IPv4"
#   remote_ip_prefix  = "172.20.0.64/26"
#   security_group_id = openstack_networking_secgroup_v2.secgroup_inscope.id
# }

# ###########
# # All outbound to NAT/WAN
# ###########

# resource "openstack_networking_secgroup_rule_v2" "inscope_nat_all" {
#   direction         = "egress"
#   ethertype         = "IPv4"
#   remote_ip_prefix  = "100.65.0.0/16"
#   security_group_id = openstack_networking_secgroup_v2.secgroup_inscope.id
# }

# ###########
# # Allow all traffic in inscope
# ###########


# resource "openstack_networking_secgroup_rule_v2" "inscope_internal_core_in" {
#   direction         = "ingress"
#   ethertype         = "IPv4"
#   remote_ip_prefix  = "10.0.10.0/24"
#   security_group_id = openstack_networking_secgroup_v2.secgroup_inscope.id
# }

# resource "openstack_networking_secgroup_rule_v2" "inscope_internal_dmz_in" {
#   direction         = "ingress"
#   ethertype         = "IPv4"
#   remote_ip_prefix  = "10.0.20.0/24"
#   security_group_id = openstack_networking_secgroup_v2.secgroup_inscope.id
# }

# resource "openstack_networking_secgroup_rule_v2" "inscope_internal_internal_in" {
#   direction         = "ingress"
#   ethertype         = "IPv4"
#   remote_ip_prefix  = "10.0.30.0/24"
#   security_group_id = openstack_networking_secgroup_v2.secgroup_inscope.id
# }

# resource "openstack_networking_secgroup_rule_v2" "inscope_internal_core_out" {
#   direction         = "egress"
#   ethertype         = "IPv4"
#   remote_ip_prefix  = "10.0.10.0/24"
#   security_group_id = openstack_networking_secgroup_v2.secgroup_inscope.id
# }

# resource "openstack_networking_secgroup_rule_v2" "inscope_internal_dmz_out" {
#   direction         = "egress"
#   ethertype         = "IPv4"
#   remote_ip_prefix  = "10.0.20.0/24"
#   security_group_id = openstack_networking_secgroup_v2.secgroup_inscope.id
# }

# resource "openstack_networking_secgroup_rule_v2" "inscope_internal_internal_out" {
#   direction         = "egress"
#   ethertype         = "IPv4"
#   remote_ip_prefix  = "10.0.30.0/24"
#   security_group_id = openstack_networking_secgroup_v2.secgroup_inscope.id
# }