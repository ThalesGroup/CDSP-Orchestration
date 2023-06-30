#!/usr/bin/python
# -*- coding: utf-8 -*-
#
# (c) 2023 Thales Group. All rights reserved.
# Author: Anurag Jain, Developer Advocate, Thales
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#  http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#

from __future__ import absolute_import, division, print_function
__metaclass__ = type

from ansible_collections.thalesgroup.ciphertrust.plugins.module_utils.modules import ThalesCipherTrustModule
from ansible_collections.thalesgroup.ciphertrust.plugins.module_utils.connection_management import createConnection, patchConnection
from ansible_collections.thalesgroup.ciphertrust.plugins.module_utils.exceptions import CMApiException, AnsibleCMException

DOCUMENTATION = '''
---
module: connection_manager_ldap
short_description: Manage connections to an Identity Provider(IdP) which support LDAP specifications
description:
    - This is a Thales CipherTrust Manager module for working with the CipherTrust Manager APIs, more specifically with Connection Manager API for LDAP
version_added: "1.0.0"
author: Anurag Jain, Developer Advocate Thales Group
options:
    localNode:
        description:
            - this holds the connection parameters required to communicate with an instance of CipherTrust Manager (CM)
            - holds IP/FQDN of the server, username, password, and port 
        required: true
        type: dict
        suboptions:
          server_ip:
            description: CM Server IP or FQDN
            type: str
            required: true
          server_private_ip:
            description: internal or private IP of the CM Server, if different from the server_ip
            type: str
            required: true
          server_port:
            description: Port on which CM server is listening
            type: int
            required: true
            default: 5432
          user:
            description: admin username of CM
            type: str
            required: true
          password:
            description: admin password of CM
            type: str
            required: true
          verify:
            description: if SSL verification is required
            type: bool
            required: true
            default: false     
    op_type:
        description: Operation to be performed
        choices: [create, patch]
        required: true
        type: str
    connection_id:
        description: Unique ID of the connection to be updated
        default: none
        type: str
    name:
        description: Unique connection name
        required: true
        default: none
        type: str
    description:
        description: Description about the connection
        required: false
        default: none
        type: str
    meta:
        description: Optional end-user or service data stored with the connection
        required: false
        type: dict
    products:
        description: Array of the CipherTrust products associated with the connection.
        required: false
        default: none
        type: list
        element: str
    base_dn:
        description: Starting point to use when searching for users
        default: none
        type: str
    server_url:
        description: LDAP URL for your server. (e.g. ldap://172.16.2.2:3268)
        default: none
        type: str
    user_login_attribute:
        description: Attribute inside the user object which contains the username used to login with
        default: none
        type: str
    bind_dn:
        description: Object which has permission to search under the root DN for users
        default: none
        type: str
    bind_password:
        description: Password for the Bind DN object of the LDAP connection
        default: none
        type: str
    group_base_dn:
        description: Starting point to use when searching for groups. This value can be left empty to disable group support for this connection
        default: none
        type: str
    group_filter:
        description: Search filter for listing groups. Searching with this filter should only return groups. This value can be left empty to disable group support for this connection
        default: none
        type: str
    group_id_attribute:
        description: Attribute inside the group object which contains the group identifier (name). This value should be unique and can be left empty to disable group support for this connection. If group_id_attribute is not provided, it will default to 'group_name_attribute'
        default: none
        type: str
    group_member_field:
        description: Attribute inside the group object which contains group membership information, basically which users are members of the group. This value can be left empty to disable group support for this connection
        default: none
        type: str
    group_name_attribute:
        description: Attribute inside the group object which contains the friendly name of the group
        default: none
        type: str
    insecure_skip_verify:
        description: Optional flag to disable verifying the server's certificate. It ignores both the operating system's CAs and root_cas if provided. Only applies if the server_url scheme is ldaps. Default value is false.
        default: none
        type: str
    root_cas:
        description:
          - Optional list of certificates that are used to determine if the server is trusted. Only applies if the server_url scheme is ldaps.
          - If not provided, then the server's certificate is verified using the operating system's CAs.
        default: none
        type: str
    search_filter:
        description: LDAP search filter which can further restrict the set of users who will be allowed to log in.
        default: none
        type: str
    search_filter:
        description: Attribute inside the user object which contains the user distinguished name. If user_dn_attribute is not provided, it will default to 'dn'
        default: none
        type: str
'''

EXAMPLES = '''
- name: "Create LDAP Connection"
  thalesgroup.ciphertrust.connection_manager_ldap:
    localNode:
        server_ip: "IP/FQDN of CipherTrust Manager"
        server_private_ip: "Private IP in case that is different from above"
        server_port: 5432
        user: "CipherTrust Manager Username"
        password: "CipherTrust Manager Password"
        verify: false
    op_type: create
    name: ldap_conn
    products:
      - cte
    server_url: "ldap://172.27.0.6:389"
    user_login_attribute: uid
    bind_dn: "cn=admin,dc=planetexpress,dc=com"
    bind_password: GoodNewsEveryone
    base_dn: "dc=planetexpress,dc=com"
    search_filter: "(objectclass=User)"

- name: "Update LDAP Connection"
  thalesgroup.ciphertrust.connection_manager_ldap:
    localNode:
        server_ip: "IP/FQDN of CipherTrust Manager"
        server_private_ip: "Private IP in case that is different from above"
        server_port: 5432
        user: "CipherTrust Manager Username"
        password: "CipherTrust Manager Password"
        verify: false
    op_type: patch
'''

RETURN = '''

'''
_schema_less = dict()

argument_spec = dict(
    op_type=dict(type='str', options=['create', 'patch'], required=True),
    connection_id=dict(type='str', required=False),    
    base_dn=dict(type='str'),
    name=dict(type='str'),
    server_url=dict(type='str'),
    user_login_attribute=dict(type='str'),
    bind_dn=dict(type='str'),
    bind_password=dict(type='str'),
    description=dict(type='str'),
    group_base_dn=dict(type='str'),
    group_filter=dict(type='str'),
    group_id_attribute=dict(type='str'),
    group_member_field=dict(type='str'),
    group_name_attribute=dict(type='str'),
    insecure_skip_verify=dict(type='bool'),
    root_cas=dict(type='list', element='str'),
    search_filter=dict(type='str'),
    user_dn_attribute=dict(type='str'),
    meta=dict(type='dict', options=_schema_less, required=False),
    products=dict(type='list', element='str', required=False),
)

def validate_parameters(domain_module):
    return True

def setup_module_object():
    module = ThalesCipherTrustModule(
        argument_spec=argument_spec,
        required_if=(
            ['op_type', 'patch', ['connection_id']],
            ['op_type', 'create', ['name', 'base_dn', 'server_url', 'user_login_attribute']],
        ),
        mutually_exclusive=[],
        supports_check_mode=True,
    )
    return module

def main():

    global module
    
    module = setup_module_object()
    validate_parameters(
        domain_module=module,
    )

    result = dict(
        changed=False,
    )

    if module.params.get('op_type') == 'create':
      try:
        response = createConnection(
          node=module.params.get('localNode'),
          connection_type='ldap',
          base_dn=module.params.get('base_dn'),
          name=module.params.get('name'),
          server_url=module.params.get('server_url'),
          user_login_attribute=module.params.get('user_login_attribute'),
          bind_dn=module.params.get('bind_dn'),
          bind_password=module.params.get('bind_password'),
          description=module.params.get('description'),
          group_base_dn=module.params.get('group_base_dn'),
          group_filter=module.params.get('group_filter'),
          group_id_attribute=module.params.get('group_id_attribute'),
          group_member_field=module.params.get('group_member_field'),
          group_name_attribute=module.params.get('group_name_attribute'),
          insecure_skip_verify=module.params.get('insecure_skip_verify'),
          meta=module.params.get('meta'),
          products=module.params.get('products'),
          root_cas=module.params.get('root_cas'),
          search_filter=module.params.get('search_filter'),
          user_dn_attribute=module.params.get('user_dn_attribute'),
        )
        result['response'] = response
      except CMApiException as api_e:
        if api_e.api_error_code:
          module.fail_json(msg="status code: " + str(api_e.api_error_code) + " message: " + api_e.message)
      except AnsibleCMException as custom_e:
        module.fail_json(msg=custom_e.message)

    elif module.params.get('op_type') == 'patch':
      try:
        response = patchConnection(
          node=module.params.get('localNode'),
          connection_type='ldap',
          connection_id=module.params.get('connection_id'),
          base_dn=module.params.get('base_dn'),
          server_url=module.params.get('server_url'),
          user_login_attribute=module.params.get('user_login_attribute'),
          bind_dn=module.params.get('bind_dn'),
          bind_password=module.params.get('bind_password'),
          description=module.params.get('description'),
          group_base_dn=module.params.get('group_base_dn'),
          group_filter=module.params.get('group_filter'),
          group_id_attribute=module.params.get('group_id_attribute'),
          group_member_field=module.params.get('group_member_field'),
          group_name_attribute=module.params.get('group_name_attribute'),
          insecure_skip_verify=module.params.get('insecure_skip_verify'),
          meta=module.params.get('meta'),
          products=module.params.get('products'),
          root_cas=module.params.get('root_cas'),
          search_filter=module.params.get('search_filter'),
          user_dn_attribute=module.params.get('user_dn_attribute'),
        )
        result['response'] = response
      except CMApiException as api_e:
        if api_e.api_error_code:
          module.fail_json(msg="status code: " + str(api_e.api_error_code) + " message: " + api_e.message)
      except AnsibleCMException as custom_e:
        module.fail_json(msg=custom_e.message)

    else:
        module.fail_json(msg="invalid op_type")
        
    module.exit_json(**result)

if __name__ == '__main__':
    main()