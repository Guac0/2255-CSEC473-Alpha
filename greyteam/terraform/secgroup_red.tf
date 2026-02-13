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
# resource "openstack_networking_secgroup_v2" "secgroup_red" {
#   name        = "secgroup_red"
# }

# ############
# # allow traffic inside
# ############

# resource "openstack_networking_secgroup_rule_v2" "red_internal_in" {
#   direction         = "ingress"
#   ethertype         = "IPv4"
#   remote_ip_prefix  = "172.20.0.32/27"
#   security_group_id = openstack_networking_secgroup_v2.secgroup_red.id
# }
# resource "openstack_networking_secgroup_rule_v2" "red_internal_out" {
#   direction         = "egress"
#   ethertype         = "IPv4"
#   remote_ip_prefix  = "172.20.0.32/27"
#   security_group_id = openstack_networking_secgroup_v2.secgroup_red.id
# }

# ############
# # allow outbound inscope
# ############

# resource "openstack_networking_secgroup_rule_v2" "red_out_core" {
#   direction         = "egress"
#   ethertype         = "IPv4"
#   remote_ip_prefix  = "10.0.10.0/24"
#   security_group_id = openstack_networking_secgroup_v2.secgroup_red.id
# }

# resource "openstack_networking_secgroup_rule_v2" "red_out_dmz" {
#   direction         = "egress"
#   ethertype         = "IPv4"
#   remote_ip_prefix  = "10.0.20.0/24"
#   security_group_id = openstack_networking_secgroup_v2.secgroup_red.id
# }
# resource "openstack_networking_secgroup_rule_v2" "red_out_internal" {
#   direction         = "egress"
#   ethertype         = "IPv4"
#   remote_ip_prefix  = "10.0.30.0/24"
#   security_group_id = openstack_networking_secgroup_v2.secgroup_red.id
# }

# ############
# # allow in inscope except 22
# ############

# # TCP 1-21
# resource "openstack_networking_secgroup_rule_v2" "red_core_tcp_low" {
#   direction         = "ingress"
#   ethertype         = "IPv4"
#   protocol          = "tcp"
#   port_range_min    = 1
#   port_range_max    = 21
#   remote_ip_prefix  = "10.0.10.0/24"
#   security_group_id = openstack_networking_secgroup_v2.secgroup_red.id
# }
# resource "openstack_networking_secgroup_rule_v2" "red_dmz_tcp_low" {
#   direction         = "ingress"
#   ethertype         = "IPv4"
#   protocol          = "tcp"
#   port_range_min    = 1
#   port_range_max    = 21
#   remote_ip_prefix  = "10.0.20.0/24"
#   security_group_id = openstack_networking_secgroup_v2.secgroup_red.id
# }
# resource "openstack_networking_secgroup_rule_v2" "red_internal_tcp_low" {
#   direction         = "ingress"
#   ethertype         = "IPv4"
#   protocol          = "tcp"
#   port_range_min    = 1
#   port_range_max    = 21
#   remote_ip_prefix  = "10.0.30.0/24"
#   security_group_id = openstack_networking_secgroup_v2.secgroup_red.id
# }

# # TCP 23-65535
# resource "openstack_networking_secgroup_rule_v2" "red_core_tcp_high" {
#   direction         = "ingress"
#   ethertype         = "IPv4"
#   protocol          = "tcp"
#   port_range_min    = 23
#   port_range_max    = 65535
#   remote_ip_prefix  = "10.0.10.0/24"
#   security_group_id = openstack_networking_secgroup_v2.secgroup_red.id
# }
# resource "openstack_networking_secgroup_rule_v2" "red_dmz_tcp_high" {
#   direction         = "ingress"
#   ethertype         = "IPv4"
#   protocol          = "tcp"
#   port_range_min    = 23
#   port_range_max    = 65535
#   remote_ip_prefix  = "10.0.20.0/24"
#   security_group_id = openstack_networking_secgroup_v2.secgroup_red.id
# }
# resource "openstack_networking_secgroup_rule_v2" "red_internal_tcp_high" {
#   direction         = "ingress"
#   ethertype         = "IPv4"
#   protocol          = "tcp"
#   port_range_min    = 23
#   port_range_max    = 65535
#   remote_ip_prefix  = "10.0.30.0/24"
#   security_group_id = openstack_networking_secgroup_v2.secgroup_red.id
# }

# # UDP all
# resource "openstack_networking_secgroup_rule_v2" "red_inscope_udp" {
#   direction         = "ingress"
#   ethertype         = "IPv4"
#   protocol          = "udp"
#   port_range_min    = 1
#   port_range_max    = 65535
#   remote_ip_prefix  = "10.0.0.0/16"
#   security_group_id = openstack_networking_secgroup_v2.secgroup_red.id
# }

# # ICMP
# resource "openstack_networking_secgroup_rule_v2" "red_inscope_icmp" {
#   direction         = "ingress"
#   ethertype         = "IPv4"
#   protocol          = "icmp"
#   remote_ip_prefix  = "10.0.0.0/16"
#   security_group_id = openstack_networking_secgroup_v2.secgroup_red.id
# }


# ############
# # 443 and 444 for greyteam scoring
# ############

# resource "openstack_networking_secgroup_rule_v2" "red_scoring_443" {
#   direction         = "egress"
#   ethertype         = "IPv4"
#   protocol          = "tcp"
#   port_range_min    = 443
#   port_range_max    = 443
#   remote_ip_prefix  = "172.20.0.100/32"
#   security_group_id = openstack_networking_secgroup_v2.secgroup_red.id
# }

# resource "openstack_networking_secgroup_rule_v2" "red_scoring_444" {
#   direction         = "egress"
#   ethertype         = "IPv4"
#   protocol          = "tcp"
#   port_range_min    = 444
#   port_range_max    = 444
#   remote_ip_prefix  = "172.20.0.100/32"
#   security_group_id = openstack_networking_secgroup_v2.secgroup_red.id
# }

# ######
# # all in/out on NAT/WAN
# ######

# resource "openstack_networking_secgroup_rule_v2" "red_nat_in" {
#   direction         = "ingress"
#   ethertype         = "IPv4"
#   remote_ip_prefix  = "100.65.0.0/16"
#   security_group_id = openstack_networking_secgroup_v2.secgroup_red.id
# }

# resource "openstack_networking_secgroup_rule_v2" "red_nat_out" {
#   direction         = "egress"
#   ethertype         = "IPv4"
#   remote_ip_prefix  = "100.65.0.0/16"
#   security_group_id = openstack_networking_secgroup_v2.secgroup_red.id
# }
# # resource "openstack_networking_secgroup_rule_v2" "secgroup_red_rule_1" {
# #   direction         = "ingress"
# #   ethertype         = "IPv4"
# #   #protocol          = ""
# #   #port_range_min    = 0
# #   #port_range_max    = 0
# #   #remote_ip_prefix  = "0.0.0.0/0"
# #   #remote_group_id   = ""
# #   security_group_id = openstack_networking_secgroup_v2.secgroup_red.id
# # }

# # resource "openstack_networking_secgroup_rule_v2" "secgroup_red_rule_2" {
# #   direction         = "ingress"
# #   ethertype         = "IPv6"
# #   #protocol          = ""
# #   #port_range_min    = 0
# #   #port_range_max    = 0
# #   #remote_ip_prefix  = "0.0.0.0/0"
# #   #remote_group_id   = ""
# #   security_group_id = openstack_networking_secgroup_v2.secgroup_red.id
# # }

# # /*
# # resource "openstack_networking_secgroup_rule_v2" "secgroup_red_rule_3" {
# #   direction         = "egress"
# #   ethertype         = "IPv4"
# #   #protocol          = ""
# #   #port_range_min    = 0
# #   #port_range_max    = 0
# #   #remote_ip_prefix  = "0.0.0.0/0"
# #   #remote_group_id   = ""
# #   security_group_id = openstack_networking_secgroup_v2.secgroup_red.id
# # }

# # resource "openstack_networking_secgroup_rule_v2" "secgroup_red_rule_4" {
# #   direction         = "egress"
# #   ethertype         = "IPv6"
# #   #protocol          = ""
# #   #port_range_min    = 0
# #   #port_range_max    = 0
# #   #remote_ip_prefix  = "0.0.0.0/0"
# #   #remote_group_id   = ""
# #   security_group_id = openstack_networking_secgroup_v2.secgroup_red.id
# # }
# # */