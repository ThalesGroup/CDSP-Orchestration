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
from ansible_collections.thalesgroup.ciphertrust.plugins.module_utils.dpg import createDPGPolicy, updateDPGPolicy
from ansible_collections.thalesgroup.ciphertrust.plugins.module_utils.exceptions import CMApiException, AnsibleCMException

DOCUMENTATION = '''
---
module: dpg_policy_save
short_description: Manage DPG execution behavior for REST URLs and associated encryption parameters
description:
    - This is a Thales CipherTrust Manager module for working with the CipherTrust Manager APIs, more specifically with DPG policy API
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
        - Identifier of the DPG Policy to be patched
      type: str
    name:
      description: Name of the DPG policy
      type: str
      required: false
    description:
      description: Description of the DPG policy
      type: str
      required: false
    proxy_config:
      description: List of API urls to be added to the proxy configuration
      type: list
      element: dict
      required: false
'''

EXAMPLES = '''
- name: "Create DPG Policy"
  thalesgroup.ciphertrust.dpg_policy_save:
    localNode:
        server_ip: "IP/FQDN of CipherTrust Manager"
        server_private_ip: "Private IP in case that is different from above"
        server_port: 5432
        user: "CipherTrust Manager Username"
        password: "CipherTrust Manager Password"
        verify: false
    op_type: create

- name: "Patch DPG Policy"
  thalesgroup.ciphertrust.dpg_policy_save:
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

_api_token = dict(
    name=dict(type='str'),
    operation=dict(type='str'),
    protection_policy=dict(type='str'),
    access_policy=dict(type='str'),
)

_proxy_config = dict(
    api_url=dict(type='str'),
    destination_url=dict(type='str'),
    json_request_delete_tokens=dict(type='list', element='dict', options=_api_token, required=False),
    json_request_get_tokens=dict(type='list', element='dict', options=_api_token, required=False),
    json_request_patch_tokens=dict(type='list', element='dict', options=_api_token, required=False),
    json_request_post_tokens=dict(type='list', element='dict', options=_api_token, required=False),
    json_request_put_tokens=dict(type='list', element='dict', options=_api_token, required=False),
    json_response_delete_tokens=dict(type='list', element='dict', options=_api_token, required=False),
    json_response_get_tokens=dict(type='list', element='dict', options=_api_token, required=False),
    json_response_patch_tokens=dict(type='list', element='dict', options=_api_token, required=False),
    json_response_post_tokens=dict(type='list', element='dict', options=_api_token, required=False),
    json_response_put_tokens=dict(type='list', element='dict', options=_api_token, required=False),
    url_request_delete_tokens=dict(type='list', element='dict', options=_api_token, required=False),
    url_request_get_tokens=dict(type='list', element='dict', options=_api_token, required=False),
    url_request_patch_tokens=dict(type='list', element='dict', options=_api_token, required=False),
    url_request_post_tokens=dict(type='list', element='dict', options=_api_token, required=False),
    url_request_put_tokens=dict(type='list', element='dict', options=_api_token, required=False),
)

argument_spec = dict(
    op_type=dict(type='str', options=['create', 'patch'], required=True),
    policy_id=dict(type='str'),
    name=dict(type='str'),
    description=dict(type='int'),
    proxy_config=dict(type='list', element='dict', options=_proxy_config),
)

def validate_parameters(dpg_policy_module):
    return True

def setup_module_object():
    module = ThalesCipherTrustModule(
        argument_spec=argument_spec,
        required_if=(
            ['op_type', 'patch', ['policy_id']],
        ),
        mutually_exclusive=[],
        supports_check_mode=True,
    )
    return module

def main():

    global module
    
    module = setup_module_object()
    validate_parameters(
        dpg_policy_module=module,
    )

    result = dict(
        changed=False,
    )

    if module.params.get('op_type') == 'create':
      try:
        response = createDPGPolicy(
          node=module.params.get('localNode'),
          name=module.params.get('name'),
          description=module.params.get('description'),
          proxy_config=module.params.get('proxy_config'),
        )
        result['response'] = response
      except CMApiException as api_e:
        if api_e.api_error_code:
          module.fail_json(msg="status code: " + str(api_e.api_error_code) + " message: " + api_e.message)
      except AnsibleCMException as custom_e:
        module.fail_json(msg=custom_e.message)

    elif module.params.get('op_type') == 'patch':
      try:
        response = updateDPGPolicy(
          node=module.params.get('localNode'),
          policy_id=module.params.get('policy_id'),
          description=module.params.get('description'),
          proxy_config=module.params.get('proxy_config'),
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