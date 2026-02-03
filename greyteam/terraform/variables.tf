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