# kiki-server

Provides the server-side infrastructure for Kiki's Delivery Service. This should be hosted on a unique server not used for other purposes for redundancy/blocking reasons.

1. Provisions an endpoint for clients to reach out to
    * Clients must provide valid authorization code, rotates every engagement
    * Clients can optionally request a certain software to install. Otherwise, a random/rotating selection is provided.
2. Upon client's request, sends a single message containing all install material for the program
    * Applicable variables are randomized to hinder detection, such as install path
    
Notes
* this is intended to be used in conjunction with kiki-client, which provides an automatic agent on client systems to check if the local programs are healthy and re-install them if not. However, in the event that the client agent is uninstalled, the kiki-server endpoint can be manually queried to provide identical functionality to the client.
* This is designed so that client-server comms only occur if absolutely needed (if client determines that installs are required). This is to minimize detection - THIS IS NOT A C2. Instead, it deploys C2s.

Hardware
* Assume 200 clients, 30 clients connecting a minute max: 2 cpu cores (5 workers), 1gib ram, 1mbps, 10gb ssd
TODO
* Encryption
* Logging
* Dashboard / connect logging to central log server
* Serve Downloads via Nginx Directly (with auth via flask)
* Add specific programs, installers, variables