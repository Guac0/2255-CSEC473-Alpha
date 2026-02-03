output "instance_fixed_ip_deploy_external" {
    value = openstack_compute_instance_v2.deploy.network.0.fixed_ip_v4
}

output "instance_fixed_ip_deploy_internal" {
    value = openstack_compute_instance_v2.deploy.network.1.fixed_ip_v4
}