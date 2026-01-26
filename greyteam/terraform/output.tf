output "instance_fixed_ip_deploy" {
    value = openstack_compute_instance_v2.deploy.network.0.fixed_ip_v4
}

output "instance_fixed_ip_jumpbox" {
    value = openstack_compute_instance_v2.jumpbox.network.0.fixed_ip_v4
}