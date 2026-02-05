variable "dns1" {
    description = "Primary DNS IP"
    default = "8.8.8.8"
}

variable "dns2" {
    description = "Secondary DNS IP"
    default = "1.1.1.1"
}

variable "jumpgrey" {
  type = map(object({
    hostname = string
    ip       = string
  }))
}

variable "jumpblue" {
  type = map(object({
    hostname = string
    ip       = string
  }))
}

variable "scoringworker" {
  type = map(object({
    hostname = string
    ip       = string
  }))
}

variable "deb13" {
  type = map(object({
    hostname = string
    ip       = string
    network  = string
  }))
}
variable "ubun24" {
  type = map(object({
    hostname = string
    ip       = string
    network  = string
  }))
}
variable "win10" {
  type = map(object({
    hostname = string
    ip       = string
    network  = string
  }))
}
variable "winserv22" {
  type = map(object({
    hostname = string
    ip       = string
    network  = string
  }))
}