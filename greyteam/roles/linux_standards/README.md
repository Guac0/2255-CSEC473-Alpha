linux_standards
=========

Deploys various standard settings
Currently:
- hostname and fqdn
- timezone
- packages
- dns
- payload key

Requires Reboot
------------
Yes (for hostname)

Requirements
------------
Designed for Ubuntu; untested on other flavors.

Role Variables
--------------
Variables used:
- domain
- dns_primary
- dns_secondary
- payload_key_location
- payload_key_content

Dependencies
------------
None
