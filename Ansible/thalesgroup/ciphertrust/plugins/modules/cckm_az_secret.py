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
from ansible_collections.thalesgroup.ciphertrust.plugins.module_utils.cckm_azure import performAZSecretOperation
from ansible_collections.thalesgroup.ciphertrust.plugins.module_utils.cckm_commons import addCCKMCloudAsset, editCCKMCloudAsset, createSyncJob, cancelSyncJob
from ansible_collections.thalesgroup.ciphertrust.plugins.module_utils.exceptions import CMApiException, AnsibleCMException

DOCUMENTATION = '''
---
module: cckm_az_secret
short_description: CCKM module for Azure Secrets
description:
    - This is a Thales CipherTrust Manager module for working with the CipherTrust Manager APIs, more specifically with CCKM for Azure Secrets API
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
        choices: [create, update, secret_op, create-sync-job, cancel-sync-job]
        required: true
        type: str
    secret_id:
        description: Azure Secret Identifier to be acted upton
        type: str
    job_id:
        description: Synchronization job ID to be cancelled
        type: str
    secret_op_type:
        description: Operation to be performed
        choices: [soft-delete, hard-delete, restore, recover]
        type: str
    azure_param:
        description: Azure secret parameters.
        type: dict
    secret_name:
        description: Name for the Azure secret. Secret names can only contain alphanumeric characters and hyphens.
        type: dict
    key_vault:
        description: Azure secret parameters.
        type: dict
    attributes:
        description: Secret attributes to be updated.
        type: dict
    tags:
        description: Application specific metadata in the form of key-value pair.
        type: dict
    key_vaults:
        description: Name or ID of key vaults from which Azure secrets will be synchronized. synchronize_all and key_vaults are mutually exclusive. Specify either the synchronize_all or key_vaults.
        type: dict
    synchronize_all:
        description: Set true to synchronize all secrets from all vaults. synchronize_all and key_vaults are mutually exclusive. Specify either the synchronize_all or key_vaults.
        type: dict
'''

EXAMPLES = '''
- name: "Create Azure Secret"
  thalesgroup.ciphertrust.cckm_az_secret:
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

_azure_param_attribute = dict(
  enabled=dict(type='bool'),
  exp=dict(type='str'),
  nbf=dict(type='str'),
)

_azure_param = dict(
  value=dict(type='str'),
  attributes=dict(type='dict', options=_azure_param_attribute),
  contentType=dict(type='str'),
  tags=dict(type='dict', options=_schema_less),
)

argument_spec = dict(
    op_type=dict(type='str', options=[
       'create', 
       'update',
       'secret_op',
       'create-sync-job',
       'cancel-sync-job',
       ], required=True),
    secret_id=dict(type='str'),
    job_id=dict(type='str'),
    secret_op_type=dict(type='str', options=['soft-delete', 'hard-delete', 'restore', 'recover']),
    # op_type = create
    azure_param=dict(type='dict', options=_azure_param),
    secret_name=dict(type='str'),
    key_vault=dict(type='str'),
    # op_type = update
    attributes=dict(type='dict', options=_schema_less),
    tags=dict(type='dict', options=_schema_less),
    # op_type = create-sync-job
    key_vaults=dict(type='list', element='str'),
    synchronize_all=dict(type='bool'),
)

def validate_parameters(cckm_az_secret_module):
    return True

def setup_module_object():
    module = ThalesCipherTrustModule(
        argument_spec=argument_spec,
        required_if=(
            ['op_type', 'create', ['azure_param', 'secret_name', 'key_vault']],
            ['op_type', 'update', ['secret_id']],
            ['op_type', 'secret_op', ['secret_id', 'secret_op_type']],
            ['op_type', 'cancel-sync-job', ['job_id']],
        ),
        mutually_exclusive=[],
        supports_check_mode=True,
    )
    return module

def main():

    global module
    
    module = setup_module_object()
    validate_parameters(
        cckm_az_secret_module=module,
    )

    result = dict(
        changed=False,
    )

    if module.params.get('op_type') == 'create':
      try:
        response = addCCKMCloudAsset(
          node=module.params.get('localNode'),
          asset_type="secret",
          cloud_type="az",
          azure_param=module.params.get('azure_param'),
          secret_name=module.params.get('secret_name'),
          key_vault=module.params.get('key_vault'),
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
          id=module.params.get('key_id'),
          asset_type="secret",
          cloud_type="az",
          attributes=module.params.get('attributes'),
          tags=module.params.get('tags'),
        )
        result['response'] = response
      except CMApiException as api_e:
        if api_e.api_error_code:
          module.fail_json(msg="status code: " + str(api_e.api_error_code) + " message: " + api_e.message)
      except AnsibleCMException as custom_e:
        module.fail_json(msg=custom_e.message)

    elif module.params.get('op_type') == 'secret_op':
      if module.params.get('secret_op_type') == 'restore':
        try:
          response = performAZSecretOperation(
            node=module.params.get('localNode'),
            id=module.params.get('secret_id'),
            secret_op_type=module.params.get('secret_op_type'),
            key_vault=module.params.get('key_vault'),
          )
          result['response'] = response
        except CMApiException as api_e:
          if api_e.api_error_code:
            module.fail_json(msg="status code: " + str(api_e.api_error_code) + " message: " + api_e.message)
        except AnsibleCMException as custom_e:
          module.fail_json(msg=custom_e.message)
      else:         
        try:
          response = performAZSecretOperation(
            node=module.params.get('localNode'),
            id=module.params.get('secret_id'),
            secret_op_type=module.params.get('secret_op_type'),
          )
          result['response'] = response
        except CMApiException as api_e:
          if api_e.api_error_code:
            module.fail_json(msg="status code: " + str(api_e.api_error_code) + " message: " + api_e.message)
        except AnsibleCMException as custom_e:
          module.fail_json(msg=custom_e.message)

    elif module.params.get('op_type') == 'create-sync-job':
      try:
        response = createSyncJob(
          node=module.params.get('localNode'),
          asset_type="secret",
          cloud_type="az",
          key_vaults=module.params.get('key_vaults'),
          synchronize_all=module.params.get('synchronize_all'),
        )
        result['response'] = response
      except CMApiException as api_e:
        if api_e.api_error_code:
          module.fail_json(msg="status code: " + str(api_e.api_error_code) + " message: " + api_e.message)
      except AnsibleCMException as custom_e:
        module.fail_json(msg=custom_e.message)

    elif module.params.get('op_type') == 'cancel-sync-job':
      try:
        response = cancelSyncJob(
          node=module.params.get('localNode'),
          id=module.params.get('job_id'),
          asset_type="secret",
          cloud_type="az",
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