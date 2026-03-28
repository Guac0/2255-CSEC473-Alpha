dns1 = "129.21.3.17"
dns2 = "8.8.8.8"
jumpred = {
  "jumpred1" = { hostname = "jumpred1", ip = "192.168.10.11", network = "red" }
  "jumpred2" = { hostname = "jumpred2", ip = "192.168.10.12", network = "red" }
  "jumpred3" = { hostname = "jumpred3", ip = "192.168.10.13", network = "red" }
  "jumpred4" = { hostname = "jumpred4", ip = "192.168.10.14", network = "red" }
  "jumpred5" = { hostname = "jumpred5", ip = "192.168.10.15", network = "red" }
  "jumpred6" = { hostname = "jumpred6", ip = "192.168.10.16", network = "red" }
  "jumpred7" = { hostname = "jumpred7", ip = "192.168.10.17", network = "red" }
  "jumpred8" = { hostname = "jumpred8", ip = "192.168.10.18", network = "red" }
  "jumpred9" = { hostname = "jumpred9", ip = "192.168.10.19", network = "red" }
  "jumpred10" = { hostname = "jumpred10", ip = "192.168.10.20", network = "red" }
}
jumpred_proxy = {
  "jumpred_proxy_central1" = { hostname = "jumpred_proxy_central1", ip = "192.168.10.100", network = "red" }
  "jumpred_proxy1" = { hostname = "jumpred_proxy1", ip = "192.168.50.11", network = "proxy" }
  "jumpred_proxy2" = { hostname = "jumpred_proxy2", ip = "192.168.50.12", network = "proxy" }
  "jumpred_proxy3" = { hostname = "jumpred_proxy3", ip = "192.168.50.13", network = "proxy" }
  "jumpred_proxy4" = { hostname = "jumpred_proxy4", ip = "192.168.50.14", network = "proxy" }
  "jumpred_proxy5" = { hostname = "jumpred_proxy5", ip = "192.168.50.15", network = "proxy" }
  "jumpred_proxy6" = { hostname = "jumpred_proxy6", ip = "192.168.50.16", network = "proxy" }
  "jumpred_proxy7" = { hostname = "jumpred_proxy7", ip = "192.168.50.17", network = "proxy" }
  "jumpred_proxy8" = { hostname = "jumpred_proxy8", ip = "192.168.50.18", network = "proxy" }
}
jumpgrey = {
  "jumpgrey1" = { hostname = "jumpgrey1", ip = "172.20.0.71" }
  #"jumpgrey2" = { hostname = "jumpgrey2", ip = "172.20.0.72" }
  #"jumpgrey3" = { hostname = "jumpgrey3", ip = "172.20.0.73" }
  #"jumpgrey4" = { hostname = "jumpgrey4", ip = "172.20.0.74" }
  #"jumpgrey5" = { hostname = "jumpgrey5", ip = "172.20.0.75" }
  #"jumpgrey6" = { hostname = "jumpgrey6", ip = "172.20.0.76" }
  #"jumpgrey7" = { hostname = "jumpgrey7", ip = "172.20.0.77" }
  #"jumpgrey8" = { hostname = "jumpgrey8", ip = "172.20.0.78" }
  #"jumpgrey9" = { hostname = "jumpgrey9", ip = "172.20.0.79" }
  #"jumpgrey10" = { hostname = "jumpgrey10", ip = "172.20.0.70" }
}
jumpblue = {
  #"jumpblue1" = { hostname = "jumpblue1", ip = "172.20.0.41" }
  #"jumpblue2" = { hostname = "jumpblue2", ip = "172.20.0.42" }
  #"jumpblue3" = { hostname = "jumpblue3", ip = "172.20.0.43" }
  #"jumpblue4" = { hostname = "jumpblue4", ip = "172.20.0.44" }
  #"jumpblue5" = { hostname = "jumpblue5", ip = "172.20.0.45" }
  #"jumpblue6" = { hostname = "jumpblue6", ip = "172.20.0.46" }
  #"jumpblue7" = { hostname = "jumpblue7", ip = "172.20.0.47" }
  #"jumpblue8" = { hostname = "jumpblue8", ip = "172.20.0.48" }
  #"jumpblue9" = { hostname = "jumpblue9", ip = "172.20.0.49" }
  #"jumpblue10" = { hostname = "jumpblue10", ip = "172.20.0.40" }
}
scoringworker = {
#  "scoring1" = { hostname = "scoring1", ip = "172.20.0.67" }
#  "scoring2" = { hostname = "scoring2", ip = "172.20.0.82" }
#  "scoring3" = { hostname = "scoring3", ip = "172.20.0.90" }
#  "scoring4" = { hostname = "scoring4", ip = "172.20.0.106" }
#  "scoring5" = { hostname = "scoring5", ip = "172.20.0.115" }
}

deb13 = {
  "apache2" = { hostname = "ponyville", ip = "10.0.10.3", network = "core"}
  "mariadb" = { hostname = "seaddle", ip = "10.0.10.4", network = "core"}
  "cups" = { hostname = "trotsylvania", ip = "10.0.10.5", network = "core"}
  "vsftpd" = { hostname = "crystal-empire", ip = "10.0.10.6", network = "core"}
  "irc" = { hostname = "everfree-forest", ip = "10.0.20.3", network = "dmz"}
  "nginx" = { hostname = "griffonstone", ip = "10.0.20.4", network = "dmz"}
  #"test1" = { hostname = "test1", ip = "10.0.10.11", network = "core"}
  #"test2" = { hostname = "test2", ip = "10.0.10.12", network = "core"}
  #"test3" = { hostname = "test3", ip = "10.0.10.13", network = "core"}
}
ubun24 = {
  "linux_wkst1" = { hostname = "cloudsdale", ip = "10.0.30.4", network = "internal"}
  "linux_wkst2" = { hostname = "vanhoover", ip = "10.0.30.5", network = "internal"}
  "linux_wkst3" = { hostname = "whinnyapolis", ip = "10.0.30.6", network = "internal"}
}
win10 = {
  "windows_wkst1" = { hostname = "baltamare", ip = "10.0.30.1", network = "internal"}
  "windows_wkst2" = { hostname = "neighara-falls", ip = "10.0.30.2", network = "internal"}
  "windows_wkst3" = { hostname = "fillydelphia", ip = "10.0.30.3", network = "internal"}
}
winserv22 = {
  "dc" = { hostname = "canterlot", ip = "10.0.10.1", network = "core" }
  "mssql" = { hostname = "manehatten", ip = "10.0.10.2", network = "core" }
  "iis" = { hostname = "las-pegasus", ip = "10.0.20.1", network = "dmz" }
  "smb" = { hostname = "appleloosa", ip = "10.0.20.2", network = "dmz" }
}