dns1 = "129.21.3.17"
dns2 = "8.8.8.8"
jumpblue2 = {
  #"jumpblue1" = { hostname = "jumpblue1", ip = "10.20.1.73" }
  #"jumpblue2" = { hostname = "jumpblue2", ip = "10.20.1.132" }
  #"jumpblue3" = { hostname = "jumpblue3", ip = "10.20.1.71" }
  #"jumpblue4" = { hostname = "jumpblue4", ip = "10.20.1.111" }
  #"jumpblue5" = { hostname = "jumpblue5", ip = "10.20.1.57" }
  "jumpblue6" = { hostname = "jumpblue6", ip = "10.20.1.20" }
  #"jumpblue7" = { hostname = "jumpblue7", ip = "10.20.1.46" }
  #"jumpblue8" = { hostname = "jumpblue8", ip = "10.20.1.37" }
  #"jumpblue9" = { hostname = "jumpblue9", ip = "10.20.1.16" }
  #"jumpblue10" = { hostname = "jumpblue10", ip = "10.20.1.29" }
}

deb13_2 = {
  "gitlab" = { hostname = "dungeon", ip = "10.2.1.4", network = "core" }
  "irc"    = { hostname = "cathedral", ip = "10.2.1.5", network = "core" }
  "nginx"  = { hostname = "gallows", ip = "10.2.1.6", network = "core" }
}

ubun24_2 = {
  "docker" = { hostname = "market", ip = "10.2.1.7", network = "core" }
  "mysql"  = { hostname = "stables", ip = "10.2.1.8", network = "core" }
  "apache" = { hostname = "pigeontower", ip = "10.2.1.9", network = "core" }
}

winserv22_2 = {
  "iis" = { hostname = "armory", ip = "10.2.1.1", network = "core" }
  "smb" = { hostname = "sewers", ip = "10.2.1.2", network = "core" }
  "dns" = { hostname = "fortress", ip = "10.2.1.3", network = "core" }
}