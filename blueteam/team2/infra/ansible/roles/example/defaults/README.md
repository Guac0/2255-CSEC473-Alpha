# defaults

This folder contains files that hold variables that can be used in this role.
These variables can be accessed using {{ example_var1 }} in your code.
Place all your variables in main.yaml. Using multiple files is a more advanced technique.
Use variables early and often! They make it easy to change things if you need to change deployment details or re-use your code for a new competition.
You can also set variables for groups of destination machines in the group_vars folder in the root of the Ansible project. Use this if you need to re-use variables between multiple roles.



For people with prior experience with Ansible, "defaults" and "vars" are both valid folders to declare variables in. "defaults" has a lower precedence than "vars". For standardization, we will use "defaults" unless absolutely needed.