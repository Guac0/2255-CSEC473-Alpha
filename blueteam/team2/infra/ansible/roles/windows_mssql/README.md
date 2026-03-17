# windows_mssql

Deploys a no-frills MSSQL Express server on the destination endpoint with remote access enabled and sample data deployed.
To customize common configuration values, see defaults/main.yaml.
To customize the initial data deployed into the DB, see the last item in tasks/data.yaml.

Thanks for Han for his work on SSMS and SQLCMD!

## Useful Development Links
https://docs.ansible.com/projects/ansible/latest/collections/community/general/mssql_db_module.html#ansible-collections-community-general-mssql-db-module
https://docs.ansible.com/projects/ansible/latest/collections/community/general/mssql_script_module.html#ansible-collections-community-general-mssql-script-module
https://galaxy.ansible.com/ui/repo/published/microsoft/sql/content/role/server/
https://github.com/linux-system-roles/mssql/tree/main
https://github.com/automatesql/Ansible-for-SQL-Server-DBAs/blob/main/Simple-SQL-Server-Install/config2022.j2
