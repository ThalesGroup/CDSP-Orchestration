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
from ansible_collections.thalesgroup.ciphertrust.plugins.module_utils.cckm_gcp import performGCPKeyRingOperation
from ansible_collections.thalesgroup.ciphertrust.plugins.module_utils.cckm_commons import addCCKMCloudAsset, editCCKMCloudAsset
from ansible_collections.thalesgroup.ciphertrust.plugins.module_utils.exceptions import CMApiException, AnsibleCMException

DOCUMENTATION = '''
---
module: cckm_gcp_keyring
short_description: CCKM module for GCP KeyRings
description:
    - This is a Thales CipherTrust Manager module for working with the CipherTrust Manager APIs, more specifically with CCKM for GCP KeyRing
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
        choices: [create, update, keyring_op]
        required: true
        type: str
    keyring_id:
        description: GCP Keyring ID to be acted upon
        type: str
    keyring_op_type:
        description: Operation to be performed on a keyring
        choices: [update-acls, remove-key-ring]
        type: str
    connection:
        description: Name or ID of the Google Cloud connection.
        type: str
    key_rings:
        description: Key Ring parameters.
        type: list
    project_id:
        description: The project id of the key ring.
        type: str
    acls:
        description: acls
        type: list
'''

EXAMPLES = '''
- name: "Create GCP KeyRing"
  thalesgroup.ciphertrust.cckm_gcp_keyring:
    localNode:
        server_ip: "IP/FQDN of CipherTrust Manager"
        server_private_ip: "Private IP in case that is different from above"
        server_port: 5432
        user: "CipherTrust Manager Username"
        password: "CipherTrust Manager Password"
        verify: false
    op_type: create
'''

RETURN = '''

'''
_key_ring = dict(
   name=dict(type='str'),
)

_acl = dict(
  actions=dict(type='list', element='str'),
  group=dict(type='str'),
  permit=dict(type='bool'),
  user_id=dict(type='str'),
)

argument_spec = dict(
    op_type=dict(type='str', options=[
       'create', 
       'update',
       'keyring_op',
       ], required=True),
    keyring_id=dict(type='str'),
    keyring_op_type=dict(type='str', options=[
       'update-acls', 
       'remove-key-ring',
       ]),
    connection=dict(type='str'),
    key_rings=dict(type='list', element='dict', options=_key_ring),
    project_id=dict(type='str'),
    acls=dict(type='list', element='dict', options=_acl),
)

def validate_parameters(cckm_gcp_keyring_module):
    return True

def setup_module_object():
    module = ThalesCipherTrustModule(
        argument_spec=argument_spec,
        required_if=(
            ['op_type', 'create', ['connection', 'key_rings', 'project_id']],
            ['op_type', 'update', ['keyring_id', 'connection']],
            ['op_type', 'keyring_op', ['keyring_id', 'keyring_op_type']],
        ),
        mutually_exclusive=[],
        supports_check_mode=True,
    )
    return module

def main():

    global module
    
    module = setup_module_object()
    validate_parameters(
        cckm_gcp_keyring_module=module,
    )

    result = dict(
        changed=False,
    )

    if module.params.get('op_type') == 'create':
      try:
        response = addCCKMCloudAsset(
          node=module.params.get('localNode'),
          asset_type="keyring",
          cloud_type="gcp",
          connection=module.params.get('connection'),
          key_rings=module.params.get('key_rings'),
          project_id=module.params.get('project_id'),
        )
        result['response'] = response
      except CMApiException as api_e:
        if api_e.api_error_code:
          module.fail_json(msg="status code: " + str(api_e.api_error_code) + " message: " + api_e.message)
      except AnsibleCMException as custom_e:
        module.fail_json(msg=custom_e.message)

    elif module.params.get('op_type') == 'update':
      try:
        response = editCCKMCloudAsset(
          node=module.params.get('localNode'),
          id=module.params.get('keyring_id'),
          asset_type="keyring",
          cloud_type="gcp",
          connection=module.params.get('connection'),
        )
        result['response'] = response
      except CMApiException as api_e:
        if api_e.api_error_code:
          module.fail_json(msg="status code: " + str(api_e.api_error_code) + " message: " + api_e.message)
      except AnsibleCMException as custom_e:
        module.fail_json(msg=custom_e.message)

    elif module.params.get('op_type') == 'keyring_op':
      if module.params.get('keyring_op_type') == 'update-acls':
        try:
          response = performGCPKeyRingOperation(
            node=module.params.get('localNode'),
            id=module.params.get('keyring_id'),
            keyring_op_type=module.params.get('keyring_op_type'),
            acls=module.params.get('acls'),
          )
          result['response'] = response
        except CMApiException as api_e:
          if api_e.api_error_code:
            module.fail_json(msg="status code: " + str(api_e.api_error_code) + " message: " + api_e.message)
        except AnsibleCMException as custom_e:
          module.fail_json(msg=custom_e.message)
      elif module.params.get('keyring_op_type') == 'remove-key-ring':
        try:
          response = performGCPKeyRingOperation(
            node=module.params.get('localNode'),
            id=module.params.get('keyring_id'),
            keyring_op_type=module.params.get('keyring_op_type'),
          )
          result['response'] = response
        except CMApiException as api_e:
          if api_e.api_error_code:
            module.fail_json(msg="status code: " + str(api_e.api_error_code) + " message: " + api_e.message)
        except AnsibleCMException as custom_e:
          module.fail_json(msg=custom_e.message)
      else:
        module.fail_json(msg="invalid asset operation")
    
    else:
        module.fail_json(msg="invalid op_type")
        
    module.exit_json(**result)

if __name__ == '__main__':
    main()