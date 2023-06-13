# Testing This Collection
Available targets in this repository -

```
~/ansible/bin/ansible-test integration --list-targets

* module_cm_cluster
* module_domain_save
* module_group_save
* module_interface_actions
* module_license_create
* module_license_trial_action
* module_usermgmt_users_save
* module_vault_keys2_op
```

To test individual module, first update the vars/sample.yml file, for example integration/targets/module_group_save -

| parameter | description |
| --- | --- |
| this_node_connection_string.server_ip | IP or FQDN of CipherTrust Manager (CM) |
| this_node_connection_string.server_private_ip | Private IP of CM Instance |
| this_node_connection_string.server_port | Port of CM |
| this_node_connection_string.user | Admin username of CM |
| this_node_connection_string.password | Admin password of CM |
| this_node_connection_string.verify | If client has to verify CM connection |
| group_name | Name of the User Group to be created on CM |
| new_group_name | Update User Group Name |
| user_id | User ID of the user to be added/removed to/from a Group |
| client_id | Client ID of the client to be added/removed to/from a Group |

Once updated, rename the sample.yml file to main.yml

You may now execute the test by running below command -

```
~/ansible/bin/ansible-test integration module_group_save
```