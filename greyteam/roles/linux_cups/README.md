# Creates CUPS service on Linux

Creates CUPS service with publically available web GUI.
- The cupsd.conf file is required to open up the GUI.
- The printer admin user is used as a login for administrative responsibilities via the GUI

Creates a "printer" also on the localhost using ippeveprinter
- The printer supposedly outputs to the admin user's "print" directory
- ippeveprinter is run as a service so that it keeps running after ansible finishes. The service name is ippprinter (ipp printer)

Note that nothing prints to the directory, and there is an error displayed in the GUI, but the jobs are marked as "succeeded". Checks could be done by trying to access the web GUI or by trying to print via commandline.
