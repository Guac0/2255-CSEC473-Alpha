# templates

This folder holds files that will be deployed on the target machine as a Jinja2 template.
Basically, take your file, move items you want to be Ansible variables to the "defaults" folder, and replace them in the file with "{{ variable_name }}". Finally, rename the file to add ".j2" to the end of the filename.
Then, when you execute the template copy task (see the tasks folder), the file will be copied onto the target machine but with any variables replaced by their values.