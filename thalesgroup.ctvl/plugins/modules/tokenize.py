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
from ansible_collections.thalesgroup.ctvl.plugins.module_utils.tokenization import tokenize, detokenize
from ansible_collections.thalesgroup.ctvl.plugins.module_utils.exceptions import CTVLApiException, AnsibleCTVLException

DOCUMENTATION = '''
---
module: tokenize
short_description: Tokenize or de-tokenize data using CTS services
description:
    - This is the CTS tokenization module that work with CTS API providing standard tokenization operations
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
        description: Operation to be performed using the CTS tokenization service
        choices: [tokenize, detokenize]
        required: true
        type: str
    tokengroup:
        description: Defines a group name space in the configuration database.
        type: str
    data:
        description: The data string to tokenize. The argument considers case and is limited to 128KiBs
        type: str
    tokentemplate:
        description: CT-VL GUI Administrator-defined name for a group of properties that define tokenization operation. Properties include the token group to which the template applies, the tokenization format (date, FPE or FPE with Luhn check, or FF1 or FF1 with Luhn check, or Random (lookup) or Random with Luhn check), number of leftmost or rightmost characters to not tokenize, whether you wish to never detokenize a tokenized entry, the character set used for tokenization, and an optional prefix for tokens.
        type: str
    token:
        description: The token to detokenize. token is case sensitive. Example value: 6029541314537206
        type: str
'''

EXAMPLES = '''
- name: "Tokenize Data"
  thalesgroup.ctvl.tokenize:
    server:
        url: "IP/FQDN of CT-VL instance"
        username: "API Username"
        password: "API User Password"
        verify: false
    op_type: tokenize
    tokengroup: demo-tg
    tokentemplate: demo-tt
    data: 1234-5678-9012-3456

- name: "De-tokenize Token"
  thalesgroup.ctvl.tokenize:
    server:
        url: "IP/FQDN of CT-VL instance"
        username: "API Username"
        password: "API User Password"
        verify: false
    op_type: detokenize
    tokengroup: demo-tg
    tokentemplate: demo-tt
    token: 1234Dd1N*d90~L56
'''

RETURN = '''
token:
    description: tokeized string
    type: str
    sample: '1234Dd1N*d90~L56'
data:
    description: detokeized string
    type: str
    sample: '1234xxxxxxxxxxxxx56'
status:
    description: status of the operation
    returned: always
    type: str
    sample: 'Succeed'
'''

argument_spec = dict(
    op_type=dict(type='str', options=['tokenize', 'detokenize'], required=True),
    data=dict(type='str'),
    token=dict(type='str'),
    tokengroup=dict(type='str', required=True),
    tokentemplate=dict(type='str', required=True),
)

def validate_parameters(tokenize_module):
    return True

def setup_module_object():
    module = ThalesCTVLModule(
        argument_spec=argument_spec,
        required_if=(
            ['op_type', 'tokenize', ['data']],
            ['op_type', 'detokenize', ['token']],
        ),
        mutually_exclusive=[],
        supports_check_mode=True,
    )
    return module

def main():

    global module
    
    module = setup_module_object()
    validate_parameters(
        tokenize_module=module,
    )

    result = dict(
        changed=False,
    )

    if module.params.get('op_type') == 'tokenize':
      try:
        response = tokenize(
          server=module.params.get('server'),
          tokengroup=module.params.get('tokengroup'),
          tokentemplate=module.params.get('tokentemplate'),
          data=module.params.get('data'),
        )
        result['response'] = response
      except CTVLApiException as api_e:
        if api_e.api_error_code:
          module.fail_json(msg="status code: " + str(api_e.api_error_code) + " message: " + api_e.message)
      except AnsibleCTVLException as custom_e:
        module.fail_json(msg=custom_e.message)

    elif module.params.get('op_type') == 'detokenize':
      try:
        response = detokenize(
          server=module.params.get('server'),
          tokengroup=module.params.get('tokengroup'),
          tokentemplate=module.params.get('tokentemplate'),
          token=module.params.get('token'),
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