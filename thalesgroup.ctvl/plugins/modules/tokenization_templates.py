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
module: tokenization_templates
short_description: Create or update properties of CT-VL Tokenization Template
description:
    - This is a Thales CipherTrust Vaultless Tokenization module for working with the CT-VL CharacterSets APIs, create and update the Tokenization Template on the CT-VL platform
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
        description: Operation to be performed on the CT-VL Tokenization Template
        choices: [create, update, delete]
        required: true
        type: str
    id:
        description: CT-VL Tokenization Template ID to be updated or deleted
        type: int
    name:
        description: Tokenization Template name
        required: true
        type: str
    tenant:
        description: Tokenization group
        type: str
    format:
        description: Tokenization format
        choices: [FPE, FPE-luhn, YYYYMMDD, YYMMDD, MMDDYYYY, MMDDYY, DDMMYYYY, DDMMYY, MMYY, MMYYYY, Random, Random-Luhn, FF1, FF1-luhn]
        type: str
    keepleft:
        description: Number of character to leave unencrypted starting from the left
        type: int
    keepright:
        description: Number of character to leave unencrypted starting from the right
        type: int
    irreversible:
        description: Set irreversible to true if you never want the token to be detokenized
        type: bool
    copyruntdata:
        description: Return uncencrypted data instead of an error if teh input is smaller than 2 characters
        type: bool
    allowsmallinput:
        description: Allow inputs smaller than 6 characters
        type: bool
    charset:
        description: Character set allowed
        type: str
    prefix:
        description: An optional prefix to be added to all tokens
        type: str
    startyear:
        description: The smallest year the input data is assumed to fall
        type: int
    endyear:
        description: The highest year the input data is assumed to fall
        type: int
    daterecordcount:
        description: TODO
        type: int
    datetablenum:
        description: TODO
        type: int
    datetablenum_status:
        description: TODO
        type: str
'''

EXAMPLES = '''
- name: "Create Tokenization Template"
  thalesgroup.ctvl.tokenization_templates:
    server:
        url: "IP/FQDN of CT-VL instance"
        username: "API Username"
        password: "API User Password"
        verify: false
    op_type: create
    name: token-template-name
    tenant: token-group-name
    format: FPE
    charset: "All printable ASCII"
    keepleft: 4
    keepright: 2
    startyear: 0,
    endyear: 0,
    irreversible: false
    copyruntdata: true
    allowsmallinput: true

- name: "Update Tokenization Template"
  thalesgroup.ctvl.tokenization_templates:
    server:
        url: "IP/FQDN of CT-VL instance"
        username: "API Username"
        password: "API User Password"
        verify: false
    op_type: update
    id: 2
    name: token-template-name-upd
    tenant: token-group-name
    format: FPE
    charset: "All printable ASCII"

- name: "Delete Tokenization Template"
  thalesgroup.ctvl.tokenization_templates:
    server:
        url: "IP/FQDN of CT-VL instance"
        username: "API Username"
        password: "API User Password"
        verify: false
    op_type: delete
    id: 2
'''

RETURN = '''
idtokentemplate:
    description: Tokenization Template ID
    returned: always
    type: int
    sample: 2
name:
    description: Tokenization Template name
    returned: changed
    type: str
    sample: 'token-template-name'
tenant:
    description: Tokenization group
    type: str
    returned: changed
    sample: 'token-group-name'
format:
    description: Tokenization format
    type: str
    returned: changed
    sample: 'FPE'
keepleft:
    description: Number of character to leave unencrypted starting from the left
    type: int
    returned: changed
    sample: 4
keepright:
    description: Number of character to leave unencrypted starting from the right
    type: int
    returned: changed
    sample: 0
irreversible:
    description: Set irreversible to true if you never want the token to be detokenized
    type: bool
    returned: changed
    sample: false
copyruntdata:
    description: Return uncencrypted data instead of an error if teh input is smaller than 2 characters
    type: bool
    returned: changed
    sample: true
allowsmallinput:
    description: Allow inputs smaller than 6 characters
    type: bool
    returned: changed
    sample: true
charset:
    description: Character set allowed
    type: str
    returned: changed
    sample: 'All printable ASCII'
prefix:
    description: An optional prefix to be added to all tokens
    type: str
    returned: changed
    sample: ''
startyear:
    description: The smallest year the input data is assumed to fall
    type: int
    returned: changed
    sample: 0
endyear:
    description: The highest year the input data is assumed to fall
    type: int
    returned: changed
    sample: 0
daterecordcount:
    description: TODO
    type: int
    returned: changed
    sample: 0
datetablenum:
    description: TODO
    type: int
    returned: changed
    sample: 0
datetablenum_status:
    description: TODO
    type: str
    returned: changed
    sample: ''
'''

argument_spec = dict(
    op_type=dict(type='str', options=['create', 'update', 'delete'], required=True),
    id=dict(type='int'),
    name=dict(type='str'),
    tenant=dict(type='str'),
    format=dict(type='str', options=['FPE', 'FPE-luhn', 'YYYYMMDD', 'YYMMDD', 'MMDDYYYY', 'MMDDYY', 'DDMMYYYY', 'DDMMYY', 'MMYY', 'MMYYYY', 'Random', 'Random-Luhn', 'FF1', 'FF1-luhn']),
    keepleft=dict(type='int', required=False, default=0),
    keepright=dict(type='int', required=False, default=0),
    irreversible=dict(type='bool', required=False, default=False),
    copyruntdata=dict(type='bool', required=False, default=False),
    allowsmallinput=dict(type='bool', required=False, default=False),
    charset=dict(type='str'),
    prefix=dict(type='str', required=False),
    startyear=dict(type='int', required=False, default=0),
    endyear=dict(type='int', required=False, default=0),
    daterecordcount=dict(type='int', required=False, default=0),
    datetablenum=dict(type='int', required=False, default=0),
    datetablenum_status=dict(type='str', required=False),
)

def validate_parameters(token_template_module):
    return True

def setup_module_object():
    module = ThalesCTVLModule(
        argument_spec=argument_spec,
        required_if=(
            ['op_type', 'create', ['name', 'tenant', 'format', 'charset']],
            ['op_type', 'update', ['id', 'name', 'tenant', 'format', 'charset']],
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
        token_template_module=module,
    )

    result = dict(
        changed=False,
    )

    if module.params.get('op_type') == 'create':
      try:
        response = createCTVLAsset(
          server=module.params.get('server'),
          type='token_template',
          name=module.params.get('name'),
          tenant=module.params.get('tenant'),
          format=module.params.get('format'),
          keepleft=module.params.get('keepleft'),
          keepright=module.params.get('keepright'),
          irreversible=module.params.get('irreversible'),
          copyruntdata=module.params.get('copyruntdata'),
          allowsmallinput=module.params.get('allowsmallinput'),
          charset=module.params.get('charset'),
          prefix=module.params.get('prefix'),
          startyear=module.params.get('startyear'),
          endyear=module.params.get('endyear'),
          daterecordcount=module.params.get('daterecordcount'),
          datetablenum=module.params.get('datetablenum'),
          datetablenum_status=module.params.get('datetablenum_status'),
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
          type='token_template',
          id=module.params.get('id'),
          name=module.params.get('name'),
          tenant=module.params.get('tenant'),
          format=module.params.get('format'),
          keepleft=module.params.get('keepleft'),
          keepright=module.params.get('keepright'),
          irreversible=module.params.get('irreversible'),
          copyruntdata=module.params.get('copyruntdata'),
          allowsmallinput=module.params.get('allowsmallinput'),
          charset=module.params.get('charset'),
          prefix=module.params.get('prefix'),
          startyear=module.params.get('startyear'),
          endyear=module.params.get('endyear'),
          daterecordcount=module.params.get('daterecordcount'),
          datetablenum=module.params.get('datetablenum'),
          datetablenum_status=module.params.get('datetablenum_status'),
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
          type='token_template',
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