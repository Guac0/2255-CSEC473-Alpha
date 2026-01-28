output "instance_fixed_ip_jumpbox_external" {
    value = openstack_compute_instance_v2.jumpbox.network.0.fixed_ip_v4
}

output "instance_fixed_ip_jumpbox_internal" {
    value = openstack_compute_instance_v2.jumpbox.network.1.fixed_ip_v4
}

output "instance_fixed_ip_deploy" {
    value = openstack_compute_instance_v2.deploy.network.0.fixed_ip_v4
}

output "instance_fixed_ip_debian1" {
    value = openstack_compute_instance_v2.debian1.network.0.fixed_ip_v4
}

output "instance_fixed_ip_windows_server1" {
    value = openstack_compute_instance_v2.windows_server1.network.0.fixed_ip_v4
}