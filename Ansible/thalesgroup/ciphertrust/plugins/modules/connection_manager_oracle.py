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
module: connection_manager_oracle
short_description: Manage Oracle Cloud Infrastructure connections
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
        type: dict
    products:
        description: Array of the CipherTrust products associated with the connection.
        required: false
        default: none
        type: list
        element: str
    credentials:
        description: Credentials of the OCI connection
        type: dict
        suboptions:
          key_file:
            description: Private key file for OCI connection (PEM format)
            type: str
          pass_phrase:
            description: Passphrase of the encrypted key file
            type: str
    fingerprint:
        description: Fingerprint of the public key added to this user
        default: none
        type: str
    region:
        description: An Oracle Cloud Infrastructure region
        default: none
        type: str
    tenancy_ocid:
        description: OCID of the tenancy
        default: none
        type: str
    user_ocid:
        description: OCID of the user
        default: none
        type: str
'''

EXAMPLES = '''
- name: "Create Oracle Connection"
  thalesgroup.ciphertrust.connection_manager_oracle:
    localNode:
        server_ip: "IP/FQDN of CipherTrust Manager"
        server_private_ip: "Private IP in case that is different from above"
        server_port: 5432
        user: "CipherTrust Manager Username"
        password: "CipherTrust Manager Password"
        verify: false
    op_type: create
    name: "OCI Connection"
    products: 
      - cckm
    user_ocid: "ocid1.user.oc1..asdaaaaat2x4wy2jz4iat56kk7kqbzcevwyrasdty2bquujjhwcstmcfvbfq"
    tenancy_ocid: "ocid1.tenancy.oc1..7777aaaadixb52q2mvlsn634ql577776hb2vg7audpd4d4mcf5zluymff644"
    fingerprint: "c4:a9:89:47:21:11:11:ac:c4:a9:89:47:21:31:9e"
    region: ap-sydney-1
    credentials: "private key"
    pass_phrase: password

- name: "Update Oracle Connection"
  thalesgroup.ciphertrust.connection_manager_oracle:
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

_credential = dict(
    key_file=dict(type='str'),
    pass_phrase=dict(type='str'),
)

argument_spec = dict(
    op_type=dict(type='str', options=['create', 'patch'], required=True),
    connection_id=dict(type='str', required=False),  
    credentials=dict(type='str'),
    fingerprint=dict(type='str'),
    name=dict(type='str'),
    region=dict(type='str'),
    tenancy_ocid=dict(type='str'),
    user_ocid=dict(type='str'),
    description=dict(type='str', required=False),
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
            ['op_type', 'create', ['name', 'credentials', 'fingerprint', 'region', 'tenancy_ocid', 'user_ocid']],
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
          connection_type='oracle',
          credentials=module.params.get('credentials'),
          fingerprint=module.params.get('fingerprint'),
          region=module.params.get('region'),
          tenancy_ocid=module.params.get('tenancy_ocid'),
          user_ocid=module.params.get('user_ocid'),
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
          connection_type='oracle',
          connection_id=module.params.get('connection_id'),
          credentials=module.params.get('credentials'),
          fingerprint=module.params.get('fingerprint'),
          region=module.params.get('region'),
          tenancy_ocid=module.params.get('tenancy_ocid'),
          user_ocid=module.params.get('user_ocid'),
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