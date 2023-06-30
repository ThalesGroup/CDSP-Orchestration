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
from ansible_collections.thalesgroup.ciphertrust.plugins.module_utils.cckm_aws import updateACLs
from ansible_collections.thalesgroup.ciphertrust.plugins.module_utils.cckm_commons import addCCKMCloudAsset, editCCKMCloudAsset
from ansible_collections.thalesgroup.ciphertrust.plugins.module_utils.exceptions import CMApiException, AnsibleCMException

DOCUMENTATION = '''
---
module: cckm_aws_kms
short_description: CCKM module for AWS Key Management System
description:
    - This is a Thales CipherTrust Manager module for working with the CipherTrust Manager APIs, more specifically with CCKM for AWS KMS
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
        choices: [create, update, update-acls]
        required: true
        type: str
    kms_id:
        description: AWS KMS ID to be acted upton
        type: str
    account_id:
        description: ID of the AWS account.
        type: str
    name:
        description: Unique name for the KMS.
        type: str
    connection:
        description: Name or ID of the connection in which the account is managed.
        type: str
    regions:
        description: AWS regions to be added to the CCKM.
        type: list
    assume_role_arn:
        description: Amazon Resource Name (ARN) of the role to be assumed.
        type: str
    assume_role_external_id:
        description: External ID for the role to be assumed. This parameter can be specified only with "assume_role_arn".
        type: str
    acls:
        description: acls
        type: list
'''

EXAMPLES = '''
- name: "Create CCKM AWS KMS"
  thalesgroup.ciphertrust.cckm_aws_kms:
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
       'update-acls',
       ], required=True),
    kms_id=dict(type='str'),
    account_id=dict(type='str'),
    name=dict(type='str'),
    connection=dict(type='str'),
    regions=dict(type='list', element='str'),
    assume_role_arn=dict(type='str'),
    assume_role_external_id=dict(type='str'),
    acls=dict(type='list', element='dict', options=_acl),
)

def validate_parameters(cckm_aws_kms_module):
    return True

def setup_module_object():
    module = ThalesCipherTrustModule(
        argument_spec=argument_spec,
        required_if=(
            ['op_type', 'create', ['account_id', 'connection', 'name', 'regions']],
            ['op_type', 'update', ['kms_id']],
            ['op_type', 'update-acls', ['kms_id']],
        ),
        mutually_exclusive=[],
        supports_check_mode=True,
    )
    return module

def main():

    global module
    
    module = setup_module_object()
    validate_parameters(
        cckm_aws_kms_module=module,
    )

    result = dict(
        changed=False,
    )

    if module.params.get('op_type') == 'create':
      try:
        response = addCCKMCloudAsset(
          node=module.params.get('localNode'),
          asset_type="kms",
          cloud_type="aws",
          account_id=module.params.get('account_id'),
          connection=module.params.get('connection'),
          name=module.params.get('name'),
          regions=module.params.get('regions'),
          assume_role_arn=module.params.get('assume_role_arn'),
          assume_role_external_id=module.params.get('assume_role_external_id'),
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
          asset_type="kms",
          cloud_type="aws",
          node=module.params.get('localNode'),
          id=module.params.get('kms_id'),
          connection=module.params.get('connection'),
          regions=module.params.get('regions'),
          assume_role_arn=module.params.get('assume_role_arn'),
          assume_role_external_id=module.params.get('assume_role_external_id'),        
        )
        result['response'] = response
      except CMApiException as api_e:
        if api_e.api_error_code:
          module.fail_json(msg="status code: " + str(api_e.api_error_code) + " message: " + api_e.message)
      except AnsibleCMException as custom_e:
        module.fail_json(msg=custom_e.message)

    elif module.params.get('op_type') == 'update-acls':
      try:
        response = updateACLs(
          node=module.params.get('localNode'),
          id=module.params.get('kms_id'),
          acls=module.params.get('acls'),
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