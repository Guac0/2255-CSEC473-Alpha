resource "openstack_networking_secgroup_v2" "secgroup_blue" {
  name = "secgroup_blue"
}

##########
# Internal Blue Communication
##########

resource "openstack_networking_secgroup_rule_v2" "blue_internal_ingress" {
  direction         = "ingress"
  ethertype         = "IPv4"
  remote_ip_prefix  = "172.20.0.32/27"
  security_group_id = openstack_networking_secgroup_v2.secgroup_blue.id
}

############################################
# Inbound from Inscope (Core/Internal/DMZ)
############################################

resource "openstack_networking_secgroup_rule_v2" "blue_ingress_core" {
  direction         = "ingress"
  ethertype         = "IPv4"
  remote_ip_prefix  = "10.0.10.0/24"
  security_group_id = openstack_networking_secgroup_v2.secgroup_blue.id
}

resource "openstack_networking_secgroup_rule_v2" "blue_ingress_internal" {
  direction         = "ingress"
  ethertype         = "IPv4"
  remote_ip_prefix  = "10.0.20.0/24"
  security_group_id = openstack_networking_secgroup_v2.secgroup_blue.id
}

resource "openstack_networking_secgroup_rule_v2" "blue_ingress_dmz" {
  direction         = "ingress"
  ethertype         = "IPv4"
  remote_ip_prefix  = "10.0.30.0/24"
  security_group_id = openstack_networking_secgroup_v2.secgroup_blue.id
}

############################################
# SSH from NAT/WAN ONLY
############################################

resource "openstack_networking_secgroup_rule_v2" "blue_ingress_ssh_nat" {
  direction         = "ingress"
  ethertype         = "IPv4"
  protocol          = "tcp"
  port_range_min    = 22
  port_range_max    = 22
  remote_ip_prefix  = "100.65.0.0/16"
  security_group_id = openstack_networking_secgroup_v2.secgroup_blue.id
}

############################################
# Outbound to Inscope
############################################

resource "openstack_networking_secgroup_rule_v2" "blue_egress_core" {
  direction         = "egress"
  ethertype         = "IPv4"
  remote_ip_prefix  = "10.0.10.0/24"
  security_group_id = openstack_networking_secgroup_v2.secgroup_blue.id
}

resource "openstack_networking_secgroup_rule_v2" "blue_egress_internal" {
  direction         = "egress"
  ethertype         = "IPv4"
  remote_ip_prefix  = "10.0.20.0/24"
  security_group_id = openstack_networking_secgroup_v2.secgroup_blue.id
}

resource "openstack_networking_secgroup_rule_v2" "blue_egress_dmz" {
  direction         = "egress"
  ethertype         = "IPv4"
  remote_ip_prefix  = "10.0.30.0/24"
  security_group_id = openstack_networking_secgroup_v2.secgroup_blue.id
}

############################################
# Outbound to Grey (General)
############################################

resource "openstack_networking_secgroup_rule_v2" "blue_egress_grey" {
  direction         = "egress"
  ethertype         = "IPv4"
  remote_ip_prefix  = "172.20.0.64/26"
  security_group_id = openstack_networking_secgroup_v2.secgroup_blue.id
}

############################################
# Scoring Server Access (443 & 444)
############################################

resource "openstack_networking_secgroup_rule_v2" "blue_scoring_443" {
  direction         = "egress"
  ethertype         = "IPv4"
  protocol          = "tcp"
  port_range_min    = 443
  port_range_max    = 443
  remote_ip_prefix  = "172.20.0.100/32"
  security_group_id = openstack_networking_secgroup_v2.secgroup_blue.id
}

resource "openstack_networking_secgroup_rule_v2" "blue_scoring_444" {
  direction         = "egress"
  ethertype         = "IPv4"
  protocol          = "tcp"
  port_range_min    = 444
  port_range_max    = 444
  remote_ip_prefix  = "172.20.0.100/32"
  security_group_id = openstack_networking_secgroup_v2.secgroup_blue.id
}

############################################
# Outbound to NAT/WAN
############################################

resource "openstack_networking_secgroup_rule_v2" "blue_egress_nat" {
  direction         = "egress"
  ethertype         = "IPv4"
  remote_ip_prefix  = "100.65.0.0/16"
  security_group_id = openstack_networking_secgroup_v2.secgroup_blue.id
}

#############
# SSH 22 rules
#############

# TCP 1-21
resource "openstack_networking_secgroup_rule_v2" "blue_core_tcp_low" {
  direction         = "ingress"
  ethertype         = "IPv4"
  protocol          = "tcp"
  port_range_min    = 1
  port_range_max    = 21
  remote_ip_prefix  = "10.0.10.0/24"
  security_group_id = openstack_networking_secgroup_v2.secgroup_blue.id
}

# TCP 23-65535
resource "openstack_networking_secgroup_rule_v2" "blue_core_tcp_high" {
  direction         = "ingress"
  ethertype         = "IPv4"
  protocol          = "tcp"
  port_range_min    = 23
  port_range_max    = 65535
  remote_ip_prefix  = "10.0.10.0/24"
  security_group_id = openstack_networking_secgroup_v2.secgroup_blue.id
}
resource "openstack_networking_secgroup_rule_v2" "blue_internal_tcp_low" {
  direction         = "ingress"
  ethertype         = "IPv4"
  protocol          = "tcp"
  port_range_min    = 1
  port_range_max    = 21
  remote_ip_prefix  = "10.0.20.0/24"
  security_group_id = openstack_networking_secgroup_v2.secgroup_blue.id
}

resource "openstack_networking_secgroup_rule_v2" "blue_internal_tcp_high" {
  direction         = "ingress"
  ethertype         = "IPv4"
  protocol          = "tcp"
  port_range_min    = 23
  port_range_max    = 65535
  remote_ip_prefix  = "10.0.20.0/24"
  security_group_id = openstack_networking_secgroup_v2.secgroup_blue.id
}
resource "openstack_networking_secgroup_rule_v2" "blue_dmz_tcp_low" {
  direction         = "ingress"
  ethertype         = "IPv4"
  protocol          = "tcp"
  port_range_min    = 1
  port_range_max    = 21
  remote_ip_prefix  = "10.0.30.0/24"
  security_group_id = openstack_networking_secgroup_v2.secgroup_blue.id
}

resource "openstack_networking_secgroup_rule_v2" "blue_dmz_tcp_high" {
  direction         = "ingress"
  ethertype         = "IPv4"
  protocol          = "tcp"
  port_range_min    = 23
  port_range_max    = 65535
  remote_ip_prefix  = "10.0.30.0/24"
  security_group_id = openstack_networking_secgroup_v2.secgroup_blue.id
}
resource "openstack_networking_secgroup_rule_v2" "blue_inscope_udp" {
  direction         = "ingress"
  ethertype         = "IPv4"
  protocol          = "udp"
  port_range_min    = 1
  port_range_max    = 65535
  remote_ip_prefix  = "10.0.0.0/16"
  security_group_id = openstack_networking_secgroup_v2.secgroup_blue.id
}

resource "openstack_networking_secgroup_rule_v2" "blue_inscope_icmp" {
  direction         = "ingress"
  ethertype         = "IPv4"
  protocol          = "icmp"
  remote_ip_prefix  = "10.0.0.0/16"
  security_group_id = openstack_networking_secgroup_v2.secgroup_blue.id
}