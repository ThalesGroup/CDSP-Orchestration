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

from ansible_collections.thales.ciphertrust.plugins.module_utils.modules import ThalesCipherTrustModule
from ansible_collections.thales.ciphertrust.plugins.module_utils.cckm_gcp import performGCPEKMOperation
from ansible_collections.thales.ciphertrust.plugins.module_utils.cckm_commons import addCCKMCloudAsset, editCCKMCloudAsset
from ansible_collections.thales.ciphertrust.plugins.module_utils.exceptions import CMApiException, AnsibleCMException

DOCUMENTATION = '''
---
module: cckm_gcp_ekm
short_description: This is a Thales CipherTrust Manager module for working with the CipherTrust Manager APIs.
description:
    - This is a Thales CipherTrust Manager module for working with the CipherTrust Manager APIs, more specifically with CCKM for GCP EKM
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
        choices: [create, update, ekm_op]
        required: true
        type: str
'''

EXAMPLES = '''
- name: "Create GCP EKM"
  thales.ciphertrust.cckm_gcp_ekm:
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
_schema_less = dict()

_policy_basic = dict(
  clients=dict(type='list', element='str'),
  attestation_instance_names=dict(type='list', element='str'),
  attestation_project_ids=dict(type='list', element='str'),
  attestation_zones=dict(type='list', element='str'),
  justification_reason=dict(type='list', element='str'),
  justification_required=dict(type='bool'),
)

_policy = dict(
  basic=dict(type='dict', options=_policy_basic),
  rego=dict(type='str'),
)

argument_spec = dict(
    op_type=dict(type='str', options=[
       'create', 
       'update',
       'ekm_op',
       ], required=True),
    ekm_id=dict(type='str'),
    ekm_op_type=dict(type='str', options=[
       'rotate', 
       'enable',
       'disable',
       ]),
    keyURIHostname=dict(type='str'),
    name=dict(type='str'),
    policy=dict(type='dict', options=_policy),
    algorithm=dict(type='str', options=[
      'AES256', 
      'RSA_SIGN_PSS_2048_SHA256', 
      'RSA_SIGN_PSS_3072_SHA256', 
      'RSA_SIGN_PSS_4096_SHA256', 
      'RSA_SIGN_PSS_4096_SHA512', 
      'RSA_SIGN_PKCS1_2048_SHA256', 
      'RSA_SIGN_PKCS1_3072_SHA256', 
      'RSA_SIGN_PKCS1_4096_SHA256', 
      'RSA_SIGN_PKCS1_4096_SHA512', 
      'EC_SIGN_P256_SHA256', 
      'EC_SIGN_P384_SHA384',
      ]),
    cvm_required_for_decrypt=dict(type='bool'),
    cvm_required_for_encrypt=dict(type='bool'),
    endpoint_type=dict(type='str', options=['ekm', 'ekm-ude']),
    existing_key_id=dict(type='str'),
    key_type=dict(type='str', options=['symmetric', 'asymmetric']),
    meta=dict(type='dict', options=_schema_less),
    raw_policy_enabled=dict(type='bool'),
)

def validate_parameters(cckm_gcp_ekm_module):
    return True

def setup_module_object():
    module = ThalesCipherTrustModule(
        argument_spec=argument_spec,
        required_if=(
            ['op_type', 'create', ['keyURIHostname', 'name', 'policy']],
            ['op_type', 'update', ['ekm_id']],
            ['op_type', 'ekm_op', ['ekm_id', 'ekm_op_type']],
        ),
        mutually_exclusive=[],
        supports_check_mode=True,
    )
    return module

def main():

    global module
    
    module = setup_module_object()
    validate_parameters(
        cckm_gcp_ekm_module=module,
    )

    result = dict(
        changed=False,
    )

    if module.params.get('op_type') == 'create':
      try:
        response = addCCKMCloudAsset(
          node=module.params.get('localNode'),
          asset_type="ekm",
          cloud_type="gcp",
          keyURIHostname=module.params.get('keyURIHostname'),
          name=module.params.get('name'),
          policy=module.params.get('policy'),
          algorithm=module.params.get('algorithm'),
          cvm_required_for_decrypt=module.params.get('cvm_required_for_decrypt'),
          cvm_required_for_encrypt=module.params.get('cvm_required_for_encrypt'),
          endpoint_type=module.params.get('endpoint_type'),
          existing_key_id=module.params.get('existing_key_id'),
          key_type=module.params.get('key_type'),
          meta=module.params.get('meta'),
          raw_policy_enabled=module.params.get('raw_policy_enabled'),
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
          id=module.params.get('ekm_id'),
          asset_type="ekm",
          cloud_type="gcp",
          cvm_required_for_decrypt=module.params.get('cvm_required_for_decrypt'),
          cvm_required_for_encrypt=module.params.get('cvm_required_for_encrypt'),
          keyURIHostname=module.params.get('keyURIHostname'),
          meta=module.params.get('meta'),
          policy=module.params.get('policy'),
          raw_policy_enabled=module.params.get('raw_policy_enabled'),
        )
        result['response'] = response
      except CMApiException as api_e:
        if api_e.api_error_code:
          module.fail_json(msg="status code: " + str(api_e.api_error_code) + " message: " + api_e.message)
      except AnsibleCMException as custom_e:
        module.fail_json(msg=custom_e.message)

    elif module.params.get('op_type') == 'ekm_op':
        try:
          response = performGCPEKMOperation(
            node=module.params.get('localNode'),
            id=module.params.get('ekm_id'),
            ekm_op_type=module.params.get('ekm_op_type'),
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