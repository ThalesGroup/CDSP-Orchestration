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
from ansible_collections.thalesgroup.ciphertrust.plugins.module_utils.cckm_azure import performAZVaultOperation
from ansible_collections.thalesgroup.ciphertrust.plugins.module_utils.cckm_commons import addCCKMCloudAsset, editCCKMCloudAsset
from ansible_collections.thalesgroup.ciphertrust.plugins.module_utils.exceptions import CMApiException, AnsibleCMException

DOCUMENTATION = '''
---
module: cckm_az_vault
short_description: CCKM module for Azure Key Vault
description:
    - This is a Thales CipherTrust Manager module for working with the CipherTrust Manager APIs, more specifically with CCKM for Azure Vault
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
        choices: [create, update, vault_op, update-acls]
        required: true
        type: str
    vault_id:
        description: Azure Key Vault to be acted upon
        type: str
    connection:
        description: Name or ID of the connection. Connection name must be associated with the key vault to which it belongs.
        type: str
    subscription_id:
        description: Subscription ID of the vault.
        type: str
    vaults:
        description: Azure vault parameters.
        type: list
    vault_op_type:
        description: Operation that can be performed on an Azure Vault
        choices: [enable-rotation-job, disable-rotation-job, update-acls, remove-vault]
        type: str
    acls:
        description: acls
        type: list
    job_config_id:
        description: Id of the scheduler job that will perform key rotation.
        type: str
    override_key_scheduler:
        description: Whether to use key scheduler or vault scheduler if both exist.
        type: bool
'''

EXAMPLES = '''
- name: "Create Azure Vault"
  thalesgroup.ciphertrust.cckm_az_vault:
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

_schema_less = dict()

_azure_vault_property_sku = dict(
   family=dict(type='str'),
   name=dict(type='str', options=['Standard', 'Premium']),
)

_azure_vault_property = dict(
   createMode=dict(type='str', options=['CreateModeRecover', 'CreateModeDefault']),
   enablePurgeProtection=dict(type='bool'),
   enableRbacAuthorization=dict(type='bool'),
   enableSoftDelete=dict(type='bool'),
   enabledForDeployment=dict(type='bool'),
   enabledForDiskEncryption=dict(type='bool'),
   enabledForTemplateDeployment=dict(type='bool'),
   sku=dict(type='dict', options=_azure_vault_property_sku),
   softDeleteRetentionInDays=dict(type='int'),
   tenantId=dict(type='str'),
   vaultUri=dict(type='str'),
)

_azure_vault = dict(
   azure_vault_id=dict(type='str'),
   location=dict(type='str'),
   name=dict(type='str'),
   properties=dict(type='dict', options=_azure_vault_property),
   type=dict(type='str'),
   tags=dict(type='dict', options=_schema_less),
)

argument_spec = dict(
    op_type=dict(type='str', options=[
       'create', 
       'update',
       'vault_op',
       'update-acls',
       ], required=True),
    vault_id=dict(type='str'),
    connection=dict(type='str'),
    subscription_id=dict(type='str'),
    vaults=dict(type='list', element='dict', options=_azure_vault),
    vault_op_type=dict(type='str', options=['enable-rotation-job', 'disable-rotation-job', 'update-acls', 'remove-vault']),
    acls=dict(type='list', element='dict', options=_acl),
    job_config_id=dict(type='str'),
    override_key_scheduler=dict(type='bool'),
)

def validate_parameters(cckm_az_vault_module):
    return True

def setup_module_object():
    module = ThalesCipherTrustModule(
        argument_spec=argument_spec,
        required_if=(
            ['op_type', 'create', ['connection', 'subscription_id', 'vaults']],
            ['op_type', 'update', ['vault_id', 'connection']],
            ['op_type', 'vault_op', ['vault_id', 'vault_op_type']],
        ),
        mutually_exclusive=[],
        supports_check_mode=True,
    )
    return module

def main():

    global module
    
    module = setup_module_object()
    validate_parameters(
        cckm_az_vault_module=module,
    )

    result = dict(
        changed=False,
    )

    if module.params.get('op_type') == 'create':
      try:
        response = addCCKMCloudAsset(
          node=module.params.get('localNode'),
          asset_type="vault",
          cloud_type="az",
          connection=module.params.get('connection'),
          subscription_id=module.params.get('subscription_id'),
          vaults=module.params.get('vaults'),
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
          id=module.params.get('vault_id'),
          asset_type="vault",
          cloud_type="az",
          connection=module.params.get('connection'),      
        )
        result['response'] = response
      except CMApiException as api_e:
        if api_e.api_error_code:
          module.fail_json(msg="status code: " + str(api_e.api_error_code) + " message: " + api_e.message)
      except AnsibleCMException as custom_e:
        module.fail_json(msg=custom_e.message)

    elif module.params.get('op_type') == 'vault_op':
      if module.params.get('vault_op_type') == 'enable-rotation-job':
        try:
          response = performAZVaultOperation(
            node=module.params.get('localNode'),
            id=module.params.get('vault_id'),
            vault_op=module.params.get('vault_op_type'),
            job_config_id=module.params.get('job_config_id'),
            override_key_scheduler=module.params.get('override_key_scheduler'),
          )
          result['response'] = response
        except CMApiException as api_e:
          if api_e.api_error_code:
            module.fail_json(msg="status code: " + str(api_e.api_error_code) + " message: " + api_e.message)
        except AnsibleCMException as custom_e:
          module.fail_json(msg=custom_e.message)
      elif module.params.get('vault_op_type') == 'update-acls':
        try:
          response = performAZVaultOperation(
            node=module.params.get('localNode'),
            id=module.params.get('vault_id'),
            vault_op=module.params.get('vault_op_type'),
            acls=module.params.get('acls'),
          )
          result['response'] = response
        except CMApiException as api_e:
          if api_e.api_error_code:
            module.fail_json(msg="status code: " + str(api_e.api_error_code) + " message: " + api_e.message)
        except AnsibleCMException as custom_e:
          module.fail_json(msg=custom_e.message)         
      else:         
        try:
          response = performAZVaultOperation(
            node=module.params.get('localNode'),
            id=module.params.get('vault_id'),
            vault_op=module.params.get('vault_op_type'),
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