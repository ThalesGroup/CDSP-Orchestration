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

import os
import requests
import urllib3
import json

from ansible_collections.thales.ciphertrust.plugins.module_utils.modules import ThalesCipherTrustModule
from ansible_collections.thales.ciphertrust.plugins.module_utils.connection_management import createConnection, patchConnection
from ansible_collections.thales.ciphertrust.plugins.module_utils.exceptions import CMApiException, AnsibleCMException

DOCUMENTATION = '''
---
module: connection_manager_smb
short_description: This is a Thales CipherTrust Manager module for working with the CipherTrust Manager APIs.
description:
    - This is a Thales CipherTrust Manager module for working with the CipherTrust Manager APIs, more specifically with Connection Manager API for AWS
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
        default: none
        type: dict
    products:
        description: Array of the CipherTrust products associated with the connection.
        required: false
        default: none
        type: list
        element: str
    password:
        description: Password for SMB share
        default: none
        type: str
    username:
        description: Username for accessing SMB share
        default: none
        type: str
    domain:
        description: Domain for SMB share
        default: none
        type: str
    host:
        description: Hostname or FQDN of SMB share
        default: none
        type: str
    port:
        description: Port where SMB service runs on host (usually 445)
        default: none
        type: str
'''

EXAMPLES = '''
- name: "Create SMB Connection"
  thales.ciphertrust.connection_manager_smb:
    localNode:
        server_ip: "IP/FQDN of CipherTrust Manager"
        server_private_ip: "Private IP in case that is different from above"
        server_port: 5432
        user: "CipherTrust Manager Username"
        password: "CipherTrust Manager Password"
        verify: false
    op_type: create
    name: smbConnection
    products:
      - cte
    username: user
    password: pwd
    domain: domainName
    host: 1.2.3.4
    port: 445

- name: "Update SMB Connection"
  thales.ciphertrust.connection_manager_smb:
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
    username=dict(type='str'),
    password=dict(type='str'),
    domain=dict(type='str', options=['key', 'password']),
    host=dict(type='str'),
    port=dict(type='str'),
    name=dict(type='str'),
    description=dict(type='str'),
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
            ['op_type', 'create', ['name', 'username', 'password']],
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
          connection_type='smb',          
          domain=module.params.get('domain'),
          host=module.params.get('host'),
          username=module.params.get('username'),
          port=module.params.get('port'),
          password=module.params.get('password'),
          name=module.params.get('name'),
          description=module.params.get('description'),
          meta=module.params.get('meta'),
          products=module.params.get('products'),
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
          connection_type='smb',
          connection_id=module.params.get('connection_id'),
          domain=module.params.get('domain'),
          host=module.params.get('host'),
          username=module.params.get('username'),
          port=module.params.get('port'),
          password=module.params.get('password'),
          description=module.params.get('description'),
          meta=module.params.get('meta'),
          products=module.params.get('products'),
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