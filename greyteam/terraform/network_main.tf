resource "openstack_networking_router_v2" "router_main" {
    name = "router_main"
    admin_state_up = "true"
    external_network_id = "2f96295c-34f6-49a2-b5cf-7f5b407be0c8" #main-nat
}