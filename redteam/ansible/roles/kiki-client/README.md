# kiki-client

Provides the client agent for Kiki's Delivery Service.

1. Periodically executes and checks the local system for healthy programs
    * To avoid detection and be compatible with various install locations, the checked-for programs should write the current time to a pre-determined file and then timestomp it. The client agent will query these files and, if it has been X minutes since the last update, continue with the below process
2. If protected programs are uninstalled, the client agent queries the server and requests a randomized install package for that program
3. The server sends the install package (a powershell command) and the client installs it

TODO
* Encryption
* Obfuscation
* Run agent periodically