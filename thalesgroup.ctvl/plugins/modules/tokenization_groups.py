#!/usr/bin/python
# -*- coding: utf-8 -*-
#
# (c) 2023 Thales Group. All rights reserved.
# Author: Anurag Jain, Developer Advocate, Thales
#
# Licensed under the MIT License
#

from __future__ import absolute_import, division, print_function
__metaclass__ = type

from ansible_collections.thalesgroup.ctvl.plugins.module_utils.modules import ThalesCTVLModule
from ansible_collections.thalesgroup.ctvl.plugins.module_utils.commons import createCTVLAsset, patchCTVLAsset, deleteCTVLAsset
from ansible_collections.thalesgroup.ctvl.plugins.module_utils.exceptions import CTVLApiException, AnsibleCTVLException

DOCUMENTATION = '''
---
module: tokenization_groups
short_description: Create or update properties of CT-VL Tokenization Group
description:
    - This is a Thales CipherTrust Vaultless Tokenization module for working with the CT-VL CharacterSets APIs, create and update the Tokenization Groups on the CT-VL platform
version_added: "1.0.0"
author: Anurag Jain, Developer Advocate Thales Group
options:
    server:
        description:
            - this holds the connection parameters required to communicate with an instance of CipherTrust vault less Tokenization server (CT-VL)
            - holds IP/FQDN of the server, username, password, and SSL verify flag 
        required: true
        type: dict
        suboptions:
          url:
            description: CM Server IP or FQDN
            type: str
            required: true
          username:
            description: API user of CT-VL
            type: str
            required: true
          password:
            description: Password for the CT-VL API user
            type: str
            required: true
          verify:
            description: if SSL verification is required
            type: bool
            required: true
            default: false     
    op_type:
        description: Operation to be performed on the CT-VL Tokenization Group
        choices: [create, update, delete]
        required: true
        type: str
    id:
        description: CT-VL Tokenization Group ID to be updated or deleted
        type: int
    name:
        description: Tokenization group name
        required: true
        type: str
    key:
        description: Key used with the tokenization group
        required: false
        type: str
'''

EXAMPLES = '''
- name: "Create Tokenization Group"
  thalesgroup.ctvl.tokenization_groups:
    server:
        url: "IP/FQDN of CT-VL instance"
        username: "API Username"
        password: "API User Password"
        verify: false
    op_type: create
    name: token-group-name
    key: key-name

- name: "Update Tokenization Group"
  thalesgroup.ctvl.tokenization_groups:
    server:
        url: "IP/FQDN of CT-VL instance"
        username: "API Username"
        password: "API User Password"
        verify: false
    op_type: update
    id: 2
    name: token-group-name-upd
    key: key-name

- name: "Delete Tokenization Group"
  thalesgroup.ctvl.tokenization_groups:
    server:
        url: "IP/FQDN of CT-VL instance"
        username: "API Username"
        password: "API User Password"
        verify: false
    op_type: delete
    id: 2
'''

RETURN = '''
idtenant:
    description: Tokenization Group ID
    returned: always
    type: int
    sample: 2
name:
    description: Tokenization Group name
    returned: always
    type: str
    sample: 'token-group-name'
key:
    description: Key to be associated with the tokenization group
    returned: always
    type: str
    sample: 'key-name'
'''

argument_spec = dict(
    op_type=dict(type='str', options=['create', 'update', 'delete'], required=True),
    id=dict(type='int'),
    name=dict(type='str'),
    key=dict(type='str'),
)

def validate_parameters(token_group_module):
    return True

def setup_module_object():
    module = ThalesCTVLModule(
        argument_spec=argument_spec,
        required_if=(
            ['op_type', 'create', ['name', 'key']],
            ['op_type', 'update', ['id', 'name', 'key']],
            ['op_type', 'delete', ['id']],
        ),
        mutually_exclusive=[],
        supports_check_mode=True,
    )
    return module

def main():

    global module
    
    module = setup_module_object()
    validate_parameters(
        token_group_module=module,
    )

    result = dict(
        changed=False,
    )

    if module.params.get('op_type') == 'create':
      try:
        response = createCTVLAsset(
          server=module.params.get('server'),
          type='token_group',
          name=module.params.get('name'),
          key=module.params.get('key'),
        )
        result['response'] = response
      except CTVLApiException as api_e:
        if api_e.api_error_code:
          module.fail_json(msg="status code: " + str(api_e.api_error_code) + " message: " + api_e.message)
      except AnsibleCTVLException as custom_e:
        module.fail_json(msg=custom_e.message)

    elif module.params.get('op_type') == 'update':
      try:
        response = patchCTVLAsset(
          server=module.params.get('server'),
          type='token_group',
          id=module.params.get('id'),
          name=module.params.get('name'),
          key=module.params.get('key'),
        )
        result['response'] = response
      except CTVLApiException as api_e:
        if api_e.api_error_code:
          module.fail_json(msg="status code: " + str(api_e.api_error_code) + " message: " + api_e.message)
      except AnsibleCTVLException as custom_e:
        module.fail_json(msg=custom_e.message)

    elif module.params.get('op_type') == 'delete':
      try:
        response = deleteCTVLAsset(
          server=module.params.get('server'),
          type='token_group',
          id=module.params.get('id'),
        )
        result['response'] = response
      except CTVLApiException as api_e:
        if api_e.api_error_code:
          module.fail_json(msg="status code: " + str(api_e.api_error_code) + " message: " + api_e.message)
      except AnsibleCTVLException as custom_e:
        module.fail_json(msg=custom_e.message)

    else:
        module.fail_json(msg="invalid op_type")
        
    module.exit_json(**result)

if __name__ == '__main__':
    main()