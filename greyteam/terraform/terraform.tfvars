dns1 = "129.21.3.17"
dns2 = "8.8.8.8"
jumpgrey = {
  "jumpgrey1" = { hostname = "jumpgrey1", ip = "172.20.0.71" }
  "jumpgrey2" = { hostname = "jumpgrey2", ip = "172.20.0.72" }
  "jumpgrey3" = { hostname = "jumpgrey3", ip = "172.20.0.73" }
  "jumpgrey4" = { hostname = "jumpgrey4", ip = "172.20.0.74" }
  "jumpgrey5" = { hostname = "jumpgrey5", ip = "172.20.0.75" }
  "jumpgrey6" = { hostname = "jumpgrey6", ip = "172.20.0.76" }
  "jumpgrey7" = { hostname = "jumpgrey7", ip = "172.20.0.77" }
  "jumpgrey8" = { hostname = "jumpgrey8", ip = "172.20.0.78" }
  "jumpgrey9" = { hostname = "jumpgrey9", ip = "172.20.0.79" }
  "jumpgrey10" = { hostname = "jumpgrey10", ip = "172.20.0.70" }
}
jumpblue = {
  "jumpblue1" = { hostname = "jumpblue1", ip = "172.20.0.41" }
  "jumpblue2" = { hostname = "jumpblue2", ip = "172.20.0.42" }
  "jumpblue3" = { hostname = "jumpblue3", ip = "172.20.0.43" }
  "jumpblue4" = { hostname = "jumpblue4", ip = "172.20.0.44" }
  "jumpblue5" = { hostname = "jumpblue5", ip = "172.20.0.45" }
  "jumpblue6" = { hostname = "jumpblue6", ip = "172.20.0.46" }
  "jumpblue7" = { hostname = "jumpblue7", ip = "172.20.0.47" }
  "jumpblue8" = { hostname = "jumpblue8", ip = "172.20.0.48" }
  "jumpblue9" = { hostname = "jumpblue9", ip = "172.20.0.49" }
  "jumpblue10" = { hostname = "jumpblue10", ip = "172.20.0.40" }
}
scoringworker = {
  "scoring1" = { hostname = "scoring1", ip = "172.20.0.67" }
  "scoring2" = { hostname = "scoring2", ip = "172.20.0.82" }
  "scoring3" = { hostname = "scoring3", ip = "172.20.0.90" }
  "scoring4" = { hostname = "scoring4", ip = "172.20.0.106" }
  "scoring5" = { hostname = "scoring5", ip = "172.20.0.115" }
}

deb13 = {
  "apache2" = { hostname = "ponyvile", ip = "10.1.10.3", network = openstack_networking_network_v2.network_core.id}
  "mariadb" = { hostname = "seaddle", ip = "10.1.10.4", network = openstack_networking_network_v2.network_core.id}
  "cups" = { hostname = "todo", ip = "10.1.10.5", network = openstack_networking_network_v2.network_core.id}
  "vsftpd" = { hostname = "crystal-empire", ip = "10.1.10.6", network = openstack_networking_network_v2.network_core.id}
  "irc" = { hostname = "everfree-forest", ip = "10.1.20.3", network = openstack_networking_network_v2.network_dmz.id}
  "nginx" = { hostname = "griffonstone", ip = "10.1.20.4", network = openstack_networking_network_v2.network_dmz.id}
}
ubun24 = {
  "linux_wkst1" = { hostname = "cloudsdale", ip = "10.1.30.3", network = openstack_networking_network_v2.network_internal.id}
  "linux_wkst2" = { hostname = "vanhoover", ip = "10.1.30.4", network = openstack_networking_network_v2.network_internal.id}
}
win10 = {
  "windows_wkst1" = { hostname = "baltamare", ip = "10.1.30.1", network = openstack_networking_network_v2.network_internal.id}
  "windows_wkst2" = { hostname = "neighara-falls", ip = "10.1.30.2", network = openstack_networking_network_v2.network_internal.id}
}
winserv22 = {
  "dc" = { hostname = "canterlot", ip = "10.1.10.1", network = openstack_networking_network_v2.network_core.id }
  "mssql" = { hostname = "manehatten", ip = "10.1.10.2", network = openstack_networking_network_v2.network_core.id}
  "iis" = { hostname = "las-pegasus", ip = "10.1.20.1", network = openstack_networking_network_v2.network_dmz.id}
  "smb" = { hostname = "appleloosa", ip = "10.1.20.2", network = openstack_networking_network_v2.network_dmz.id}
}