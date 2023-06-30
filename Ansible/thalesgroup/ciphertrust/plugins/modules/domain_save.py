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
from ansible_collections.thalesgroup.ciphertrust.plugins.module_utils.domains import create, patch
from ansible_collections.thalesgroup.ciphertrust.plugins.module_utils.exceptions import CMApiException, AnsibleCMException

DOCUMENTATION = '''
---
module: domain_save
short_description: Create or manage domains
description:
    - This is a Thales CipherTrust Manager module for working with the CipherTrust Manager APIs, more specifically with domains management API
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
    interface_id:
        description:
            - Identifier of the domain to be patched
        type: str
    name:
        description: The name of the domain
        required: true
        default: none
        type: str
    admins:
        description: List of administrators for the domain
        required: true
        default: none
        type: list
        element: str
    allow_user_management:
        description: To allow user creation and management in the domain, set it to true
        required: false
        default: false
        type: bool
    hsm_connection_id:
        description: The ID of the HSM connection. Required for HSM-anchored domains.
        required: false
        default: none
        type: str
    hsm_kek_label:
        description: Optional name field for the domain KEK for an HSM-anchored domain. If not provided, a random UUID is assigned for KEK label.
        required: false
        default: none
        type: str
    meta:
        description: Optional end-user or service data stored with the domain.
        required: false
        default: null
        type: dict
    parent_ca_id:
        description: This optional parameter is the ID or URI of the parent domain's CA. This CA is used for signing the default CA of a newly created sub-domain. The oldest CA in the parent domain is used if this value is not supplied.
        required: false
        default: none
        type: str
    connection_id:
        description: HSM connection ID pertaining to the domain KEK
        required: false
        default: none
        type: str
    domain_kek_label:
        description: Label of the target domain KEK
        required: false
        default: none
        type: str
'''

EXAMPLES = '''
- name: "Create Domain"
  thalesgroup.ciphertrust.domain_save:
    localNode:
        server_ip: "IP/FQDN of CipherTrust Manager"
        server_private_ip: "Private IP in case that is different from above"
        server_port: 5432
        user: "CipherTrust Manager Username"
        password: "CipherTrust Manager Password"
        verify: false
    op_type: create
    admins:
      - local|4d1c26ab-8730-4d44-af5c-9a8641d0266d
      - local|c7cf4efc-df81-4446-a30e-2dd5badf44b4
    name: AnsibleDomain
    parent_ca_id: a5e0fa8a-a7f7-434c-ade8-f84de040269a

- name: "Patch Domain"
  thalesgroup.ciphertrust.domain_save:
    localNode:
        server_ip: "IP/FQDN of CipherTrust Manager"
        server_private_ip: "Private IP in case that is different from above"
        server_port: 5432
        user: "CipherTrust Manager Username"
        password: "CipherTrust Manager Password"
        verify: false
    op_type: patch
    domain_id: "ID_STRING"
    connection_id: "ID_STRING"
'''

RETURN = '''

'''
_schema_less = dict()

argument_spec = dict(
    op_type=dict(type='str', options=['create', 'patch'], required=True),
    domain_id=dict(type='str'),
    admins=dict(type='list', element='str'),
    name=dict(type='str'),
    allow_user_management=dict(type='bool', required=False, default=False),
    hsm_connection_id=dict(type='str', required=False),
    hsm_kek_label=dict(type='str', required=False),
    meta=dict(type='dict', options=_schema_less, required=False),
    parent_ca_id=dict(type='str', required=False),
    connection_id=dict(type='str', required=False),
    domain_kek_label=dict(type='str', required=False),
)

def validate_parameters(domain_module):
    return True

def setup_module_object():
    module = ThalesCipherTrustModule(
        argument_spec=argument_spec,
        required_if=(
            ['op_type', 'patch', ['domain_id']],
            ['op_type', 'create', ['admins']],
            ['op_type', 'create', ['name']],
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
        response = create(
          node=module.params.get('localNode'),
          admins=module.params.get('admins'),
          name=module.params.get('name'),
          allow_user_management=module.params.get('allow_user_management'),
          hsm_connection_id=module.params.get('hsm_connection_id'),
          hsm_kek_label=module.params.get('hsm_kek_label'),
          meta=module.params.get('meta'),
          parent_ca_id=module.params.get('parent_ca_id'),
        )
        result['response'] = response
      except CMApiException as api_e:
        if api_e.api_error_code:
          module.fail_json(msg="status code: " + str(api_e.api_error_code) + " message: " + api_e.message)
      except AnsibleCMException as custom_e:
        module.fail_json(msg=custom_e.message)

    elif module.params.get('op_type') == 'patch':
      try:
        response = patch(
          node=module.params.get('localNode'),
          domain_id=module.params.get('domain_id'),
          connection_id=module.params.get('connection_id'),
          domain_kek_label=module.params.get('domain_kek_label'),
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