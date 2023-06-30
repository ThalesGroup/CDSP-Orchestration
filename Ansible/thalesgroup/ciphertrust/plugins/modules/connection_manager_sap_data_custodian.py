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
module: connection_manager_sap_data_custodian
short_description: Manage SAP Data Custodian connections
description:
    - This is a Thales CipherTrust Manager module for working with the CipherTrust Manager APIs, more specifically with Connection Manager API for SAP Data Custodian
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
    api_endpoint:
        description: KMS API endpoint of the SAP Data Custodian. Provide HTTP URL with the API version in it. Only v2 version of KMS API is supported.
        default: none
        type: str
    technical_user_credentials:
        description: Technical User Credentials for SAP Data Custodian connection 
        type: dict
        suboptions:
          api_key:
            description: API key of the technical user
            type: str
          secret:
            description: Secret/Password of the technical user
            type: str
    user_credentials:
        description: Standard User Credentials for SAP Data Custodian connection
        type: dict
        suboptions:
          secret:
            description: Secret/Password of the user
            type: str
          tenant:
            description: Tenant of the user
            type: str
          user:
            description: Username
            type: str
'''

EXAMPLES = '''
- name: "Create SAP Data Custodian Connection"
  thalesgroup.ciphertrust.connection_manager_sap_data_custodian:
    localNode:
        server_ip: "IP/FQDN of CipherTrust Manager"
        server_private_ip: "Private IP in case that is different from above"
        server_port: 5432
        user: "CipherTrust Manager Username"
        password: "CipherTrust Manager Password"
        verify: false
    op_type: create
    api_endpoint: "https://demo-kms-endpoint/kms/v2"
    name: "SAP Data Custodian"
    products:
      - cckm
    user_credentials:
      secret: secret
      tenant: tenant
      username: username

- name: "Update SAP Data Custodian Connection"
  thalesgroup.ciphertrust.connection_manager_sap_data_custodian:
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

_technical_user_credential = dict(
    api_key=dict(type='str'),
    secret=dict(type='str'),
)

_user_credential = dict(
    secret=dict(type='str'),
    tenant=dict(type='str'),
    user=dict(type='str'),
)

argument_spec = dict(
    op_type=dict(type='str', options=['create', 'patch'], required=True),
    connection_id=dict(type='str', required=False),
    api_endpoint=dict(type='str'),
    name=dict(type='str'),
    description=dict(type='str'),
    meta=dict(type='dict', options=_schema_less),
    products=dict(type='list', element='str'),
    technical_user_credentials=dict(type='dict', options=_technical_user_credential),
    user_credentials=dict(type='dict', options=_user_credential),
)

def validate_parameters(domain_module):
    return True

def setup_module_object():
    module = ThalesCipherTrustModule(
        argument_spec=argument_spec,
        required_if=(
            ['op_type', 'patch', ['connection_id']],
            ['op_type', 'create', ['name', 'api_endpoint']],
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
          connection_type='sap',
          api_endpoint=module.params.get('credentials'),
          technical_user_credentials=module.params.get('technical_user_credentials'),
          user_credentials=module.params.get('user_credentials'),
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
          connection_type='sap',
          connection_id=module.params.get('connection_id'),
          api_endpoint=module.params.get('credentials'),
          technical_user_credentials=module.params.get('technical_user_credentials'),
          user_credentials=module.params.get('user_credentials'),
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