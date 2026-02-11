output "instance_fixed_ip_deploy_external" {
    value = openstack_compute_instance_v2.deploy.network.0.fixed_ip_v4
}
output "instance_fixed_ip_deploy_internal" {
    value = openstack_compute_instance_v2.deploy.network.1.fixed_ip_v4
}

output "instance_ips_jumpblue" {
  value = {
    for name, instance in openstack_compute_instance_v2.jumpblue : name => {
      external_ip = instance.network[0].fixed_ip_v4
      internal_ip = instance.network[1].fixed_ip_v4
    }
  }
}

output "instance_ips_jumpgrey" {
  value = {
    for name, instance in openstack_compute_instance_v2.jumpgrey : name => {
      external_ip = instance.network[0].fixed_ip_v4
      internal_ip = instance.network[1].fixed_ip_v4
    }
  }
}