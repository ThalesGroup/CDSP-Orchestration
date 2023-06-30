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
from ansible_collections.thalesgroup.ciphertrust.plugins.module_utils.dpg import createAccessPolicy, updateAccessPolicy
from ansible_collections.thalesgroup.ciphertrust.plugins.module_utils.exceptions import CMApiException, AnsibleCMException

DOCUMENTATION = '''
---
module: domain_save
short_description: Manage DPG access policies governing data access
description:
    - This is a Thales CipherTrust Manager module for working with the CipherTrust Manager APIs, more specifically with DPG Access Policy API
    - Refer https://thalesdocs.com/ctp/con/dpg/latest/admin/index.html for API documentation
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
    policy_id:
      description:
        - Identifier of the access policy to be patched
      type: str
    default_error_replacement_value:
      description: Value to be revealed if the type is 'Error Replacement Value'
      type: str
    default_masking_format_id:
      description: Masking format used to reveal if the type is 'Masked Value'
      type: str
    default_reveal_type:
      description: Value using which data should be revealed
      choices: [Error Replacement Value, Masked Value, Ciphertext, Plaintext]
      type: str
    description:
      description: Description of the Access Policy
      required: false
      type: str
    name:
      description: Access Policy Name
      required: false
      type: str
    user_set_policy:
      description: List of policies to be added to the access policy
      required: false
      type: list
      element: dict
      suboptions:
        error_replacement_value:
          description: Value to be revealed if the type is 'Error Replacement Value'
          type: str
        masking_format_id:
          description: Masking format used to reveal if the type is 'Masked Value'
          type: str
        reveal_type:
          description: Value using which data should be revealed
          choices: [Error Replacement Value, Masked Value, Ciphertext, Plaintext]
          type: str
        user_set_id:
          description: User set to which the policy is applied.
          type: str
'''

EXAMPLES = '''
- name: "Create Access Policy"
  thalesgroup.ciphertrust.dpg_access_policy_save:
    localNode:
        server_ip: "IP/FQDN of CipherTrust Manager"
        server_private_ip: "Private IP in case that is different from above"
        server_port: 5432
        user: "CipherTrust Manager Username"
        password: "CipherTrust Manager Password"
        verify: false
    op_type: create

- name: "Patch Access Policy"
  thalesgroup.ciphertrust.dpg_access_policy_save:
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

_user_set_policy = dict(
    error_replacement_value=dict(type='str'),
    masking_format_id=dict(type='str'),
    reveal_type=dict(type='str', options=['Error Replacement Value', 'Masked Value', 'Ciphertext', 'Plaintext']),
    user_set_id=dict(type='str'),
)
argument_spec = dict(
    op_type=dict(type='str', options=['create', 'patch'], required=True),
    policy_id=dict(type='str'),
    default_error_replacement_value=dict(type='str'),
    default_masking_format_id=dict(type='str'),
    default_reveal_type=dict(type='str', options=['Error Replacement Value', 'Masked Value', 'Ciphertext', 'Plaintext']),
    description=dict(type='str'),
    name=dict(type='str'),
    user_set_policy=dict(type='list', element='dict', options=_user_set_policy),
)

def validate_parameters(dpg_access_policy_module):
    return True

def setup_module_object():
    module = ThalesCipherTrustModule(
        argument_spec=argument_spec,
        required_if=(
            ['op_type', 'patch', ['policy_id']],
            ['default_reveal_type', 'Error Replacement Value' ,['default_error_replacement_value']],
            ['default_reveal_type', 'Masked Value' ,['default_masking_format_id']]
        ),
        mutually_exclusive=[],
        supports_check_mode=True,
    )
    return module

def main():

    global module
    
    module = setup_module_object()
    validate_parameters(
        dpg_access_policy_module=module,
    )

    result = dict(
        changed=False,
    )

    if module.params.get('op_type') == 'create':
      try:
        response = createAccessPolicy(
          node=module.params.get('localNode'),
          default_error_replacement_value=module.params.get('default_error_replacement_value'),
          default_masking_format_id=module.params.get('default_masking_format_id'),
          default_reveal_type=module.params.get('default_reveal_type'),
          description=module.params.get('description'),
          name=module.params.get('name'),
          user_set_policy=module.params.get('user_set_policy'),
        )
        result['response'] = response
      except CMApiException as api_e:
        if api_e.api_error_code:
          module.fail_json(msg="status code: " + str(api_e.api_error_code) + " message: " + api_e.message)
      except AnsibleCMException as custom_e:
        module.fail_json(msg=custom_e.message)

    elif module.params.get('op_type') == 'patch':
      try:
        response = updateAccessPolicy(
          node=module.params.get('localNode'),
          policy_id=module.params.get('policy_id'),
          default_error_replacement_value=module.params.get('default_error_replacement_value'),
          default_masking_format_id=module.params.get('default_masking_format_id'),
          default_reveal_type=module.params.get('default_reveal_type'),
          description=module.params.get('description'),
          name=module.params.get('name'),
          user_set_policy=module.params.get('user_set_policy'),
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