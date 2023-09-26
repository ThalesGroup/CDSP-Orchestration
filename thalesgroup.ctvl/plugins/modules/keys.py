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
from ansible_collections.thalesgroup.ctvl.plugins.module_utils.commons import createCTVLAsset, patchCTVLAsset
from ansible_collections.thalesgroup.ctvl.plugins.module_utils.exceptions import CTVLApiException, AnsibleCTVLException

DOCUMENTATION = '''
---
module: keys
short_description: Create or manage CT-VL keys
description:
    - This is a Thales CipherTrust vault less Tokenization module for working with the CT-VL Keys APIs, create and update the keys on the CT-VL platforms
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
        description: Operation to be performed on the CT-VL key
        choices: [create, update]
        required: true
        type: str
    id:
        description: CT-VL key ID to be updated
        type: str
    name:
        description: Name of the key
        required: true
        type: str
    seedkey:
        description: Weather to seed the key or not
        required: false
        default: false
        type: bool
'''

EXAMPLES = '''
- name: "Create key"
  thalesgroup.ctvl.keys:
    server:
        url: "IP/FQDN of CT-VL instance"
        username: "API Username"
        password: "API User Password"
        verify: false
    op_type: create
    name: ctvl-key
    seedkey: false

- name: "Update key"
  thalesgroup.ctvl.keys:
    server:
        url: "IP/FQDN of CT-VL instance"
        username: "API Username"
        password: "API User Password"
        verify: false
    op_type: update
    id: 2
    name: "ctvl-key-upd"
    seedkey: false
'''

RETURN = '''

'''
argument_spec = dict(
    op_type=dict(type='str', options=['create', 'update'], required=True),
    id=dict(type='str'),
    name=dict(type='str', required=True),
    seedkey=dict(type='bool', required=False, default=False),
)

def validate_parameters(keys_module):
    return True

def setup_module_object():
    module = ThalesCTVLModule(
        argument_spec=argument_spec,
        required_if=(
            ['op_type', 'update', ['id']],
        ),
        mutually_exclusive=[],
        supports_check_mode=True,
    )
    return module

def main():

    global module
    
    module = setup_module_object()
    validate_parameters(
        keys_module=module,
    )

    result = dict(
        changed=False,
    )

    if module.params.get('op_type') == 'create':
      try:
        response = createCTVLAsset(
          server=module.params.get('server'),
          name=module.params.get('name'),
          seedkey=module.params.get('seedkey'),
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
          id=module.params.get('id'),
          name=module.params.get('name'),
          seedkey=module.params.get('seedkey'),
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