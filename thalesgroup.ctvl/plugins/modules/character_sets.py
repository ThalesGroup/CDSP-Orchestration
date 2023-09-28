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
module: character_sets
short_description: Create or update properties of a Character Set on CT-VL
description:
    - This is a Thales CipherTrust Vaultless Tokenization module for working with the CT-VL CharacterSets APIs, create and update the CharacterSet on the CT-VL platform
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
        description: Operation to be performed on the CT-VL CharacterMask
        choices: [create, update, delete]
        required: true
        type: str
    id:
        description: CT-VL CharacterSet ID to be updated
        type: str
    name:
        description: Tokenization character set name
        required: true
        type: str
    alphabet:
        description: A sequence of characters or a range (in HEX digits) defining the character set
        required: true
        type: str
    predefined:
        description: True if it’s a predefined character set. False if it’s a custom character set
        required: false
        type: bool
    range:
        description: Character set type. True if it’s a range, False if it’s a sequence of alphanumeric characters
        required: false
        type: bool
'''

EXAMPLES = '''
- name: "Create CharacterSet"
  thalesgroup.ctvl.character_sets:
    server:
        url: "IP/FQDN of CT-VL instance"
        username: "API Username"
        password: "API User Password"
        verify: false
    op_type: create
    name: charset-name
    alphabet: 0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz
    predefined: false
    range: false

- name: "Update CharacterSet"
  thalesgroup.ctvl.character_sets:
    server:
        url: "IP/FQDN of CT-VL instance"
        username: "API Username"
        password: "API User Password"
        verify: false
    op_type: update
    id: 2
    name: charset-name-updated
    alphabet: 0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz

- name: "Delete CharacterSet"
  thalesgroup.ctvl.character_sets:
    server:
        url: "IP/FQDN of CT-VL instance"
        username: "API Username"
        password: "API User Password"
        verify: false
    op_type: delete
    id: 2
'''

RETURN = '''
idtokencharset:
    description: CharacterSet ID
    returned: always
    type: int
    sample: 2
name:
    description: Tokenization character set name
    returned: always
    type: str
    sample: 'charset-name'
alphabet:
    description: A sequence of characters or a range (in HEX digits) defining the character set
    returned: always
    type: str
    sample: '0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz'
predefined:
    description: True if it’s a predefined character set. False if it’s a custom character set
    returned: changed
    type: bool
    sample: false
range:
    description: Character set type. True if it’s a range, False if it’s a sequence of alphanumeric characters
    returned: changed
    type: bool
    sample: false
'''

argument_spec = dict(
    op_type=dict(type='str', options=['create', 'update', 'delete'], required=True),
    id=dict(type='int'),
    name=dict(type='str', required=True),
    alphabet=dict(type='str', required=True),
    predefined=dict(type='int', required=False),
    range=dict(type='str', required=False),
)

def validate_parameters(charsets_module):
    return True

def setup_module_object():
    module = ThalesCTVLModule(
        argument_spec=argument_spec,
        required_if=(
            ['op_type', 'update', ['id']],
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
        charsets_module=module,
    )

    result = dict(
        changed=False,
    )

    if module.params.get('op_type') == 'create':
      try:
        response = createCTVLAsset(
          server=module.params.get('server'),
          type='charset',
          name=module.params.get('name'),
          alphabet=module.params.get('alphabet'),
          predefined=module.params.get('predefined'),
          range=module.params.get('range'),
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
          type='charset',
          id=module.params.get('id'),
          name=module.params.get('name'),
          alphabet=module.params.get('alphabet'),
          predefined=module.params.get('predefined'),
          range=module.params.get('range'),
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
          type='charset',
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