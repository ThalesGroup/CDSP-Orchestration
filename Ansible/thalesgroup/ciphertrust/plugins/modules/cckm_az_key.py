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
from ansible_collections.thalesgroup.ciphertrust.plugins.module_utils.cckm_azure import performAZKeyOperation, uploadKeyOnAZ
from ansible_collections.thalesgroup.ciphertrust.plugins.module_utils.cckm_commons import addCCKMCloudAsset, editCCKMCloudAsset, createSyncJob, cancelSyncJob
from ansible_collections.thalesgroup.ciphertrust.plugins.module_utils.exceptions import CMApiException, AnsibleCMException

DOCUMENTATION = '''
---
module: cckm_az_key
short_description: CCKM module for Azure Keys
description:
    - This is a Thales CipherTrust Manager module for working with the CipherTrust Manager APIs, more specifically with CCKM for Azure Keys API
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
        choices: [create, update, key_op, upload-key, create-sync-job, cancel-sync-job]
        required: true
        type: str
    key_id:
        description: Id of the key to be acted upon
        type: str
    job_id:
        description: Synchronization job to be deleted
        type: str
    key_op_type:
        description: Operation to be performed on the key
        type: str
        choices: [soft-delete, hard-delete, restore, recover, delete-backup, enable-rotation-job, disable-rotation-job]
    azure_param:
        description: Azure key parameters.
        type: dict
    key_name:
        description: Name for the key on Azure. Key names can only contain alphanumeric characters and dashes.
        type: str
    key_vault:
        description: Id or name of the key vault where the key will be created on Azure.
        type: str
    attributes:
        description: Key attributes to be updated.
        type: dict
    key_ops:
        description: Key operations to be updated.
        type: list
        choices: [encrypt, decrypt, sign, verify, wrapKey, unwrapKey]
    tags:
        description: Application specific metadata in the form of key-value pair.
        type: dict
    key_vaults:
        description: Name or ID of key vaults from which Azure keys will be synchronized. synchronize_all and key_vaults are mutually exclusive. Specify either the synchronize_all or key_vaults.
        type: list
    synchronize_all:
        description: Set true to synchronize all keys from all vaults. synchronize_all and key_vaults are mutually exclusive. Specify either the synchronize_all or key_vaults.
        type: bool
    dsm_key_identifier:
        description: Identifier of the dsm key. It is a required parameter if source key tier is dsm.
        type: str
    exportable:
        description: Allow private key to be exported from Azure. Currently, it is only valid when key source is hsm-luna and vault is a premium vault or a managed-hsm vault.
        type: bool
    kek_kid:
        description: Identifier of azure key encryption key.
        type: str
    local_key_identifier:
        description: Identifier of the CipherTrust Manager key to upload. Key name or ID can be specified. It is a required parameter if source key tier is local.
        type: str
    luna_key_identifier:
        description: Identifier of the luna hsm key. It is a required parameter if source key tier is hsm-luna.
        type: str
    password:
        description: PFX password. Specify only if the PFX certificate is provided.
        type: str
    pfx:
        description: PFX key. Specify a Base64 encoded key.
        type: str
    release_policy:
        description: Key release policy. Must be set if exportable is true.
        type: dict
    source_key_tier:
        description: Source key tier. Options are local, pfx, dsm, and hsm-luna. Default is local.
        type: str
        choices: [local', pfx, dsm, hsm-luna]
        default: local
    auto_rotate_key_source:
        description: Source of the key material. Options are native, hsm-luna, dsm and ciphertrust.
        type: str
        choices: [native, hsm-luna, dsm, ciphertrust]
    auto_rotate_key_type:
        description: Algorithm for the key.
        type: str
        choices: [EC, EC-HSM, RSA, RSA-HSM]
    job_config_id:
        description: Id of the scheduler job that will perform key rotation.
        type: str
    auto_rotate_domain_id:
        description: Id of the domain in which dsm key will be created.
        type: str
    auto_rotate_ec_name:
        description: Name of the Elliptical curve key. Required only when key_type is EC
        type: str
        choices: [P-256, P-384, P-521, SECP256K1]
    auto_rotate_enable_key:
        description: Whether to enable the newly rotated key.
        type: bool
    auto_rotate_key_size:
        description: Size of the new rotated key. Required only when key_type is RSA.
        type: str
        choices: [2048, 3072, 4096]
    auto_rotate_partition_id:
        description: Id of the partition in which hsm key will be created.
        type: str
    auto_rotate_release_policy:
        description: Optional, new key release policy for exportable keys.
        type: dict
'''

EXAMPLES = '''
- name: "Create Azure Key"
  thalesgroup.ciphertrust.cckm_az_key:
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

_azure_param = dict(
  kty=dict(type='str', options=['EC', 'EC-HSM', 'RSA', 'RSA-HSM']),
  attributes=dict(type='dict', options=_schema_less),
  crv=dict(type='str', options=['P-256', 'P-384', 'P-521', 'SECP256K1']),
  key_ops=dict(type='list', element='str'),
  key_size=dict(type='int', options=[2048, 3072, 4096]),
  tags=dict(type='dict', options=_schema_less),
  hsm=dict(type='bool'),
)

argument_spec = dict(
    op_type=dict(type='str', options=[
       'create', 
       'update',
       'key_op',
       'upload-key',
       'create-sync-job',
       'cancel-sync-job',
       ], required=True),
    key_id=dict(type='str'),
    job_id=dict(type='str'),
    key_op_type=dict(type='str', options=['soft-delete', 'hard-delete', 'restore', 'recover', 'delete-backup', 'enable-rotation-job', 'disable-rotation-job']),
    # op_type = create
    azure_param=dict(type='dict', options=_azure_param),
    key_name=dict(type='str'),
    key_vault=dict(type='str'),
    # op_type = update
    attributes=dict(type='dict', options=_schema_less),
    key_ops=dict(type='list', element='str'),
    tags=dict(type='dict', options=_schema_less),
    # op_type = create-sync-job
    key_vaults=dict(type='list', element='str'),
    synchronize_all=dict(type='bool'),
    # op_type = upload-key
    dsm_key_identifier=dict(type='str'),
    exportable=dict(type='bool'),
    kek_kid=dict(type='str'),
    local_key_identifier=dict(type='str'),
    luna_key_identifier=dict(type='str'),
    password=dict(type='str'),
    pfx=dict(type='str'),
    release_policy=dict(type='dict', options=_schema_less),
    source_key_tier=dict(type='str', options=['local', 'pfx', 'dsm', 'hsm-luna'], default='local'),
    # op_type = key_op, key_op_type = enable-rotation-job
    auto_rotate_key_source=dict(type='str', options=['native', 'hsm-luna', 'dsm', 'ciphertrust']),
    auto_rotate_key_type=dict(type='str', options=['EC', 'EC-HSM', 'RSA', 'RSA-HSM']),
    job_config_id=dict(type='str'),
    auto_rotate_domain_id=dict(type='str'),
    auto_rotate_ec_name=dict(type='str', options=['P-256', 'P-384', 'P-521', 'SECP256K1']),
    auto_rotate_enable_key=dict(type='bool'),
    auto_rotate_key_size=dict(type='int', options=[2048, 3072, 4096]),
    auto_rotate_partition_id=dict(type='str'),
    auto_rotate_release_policy=dict(type='dict', options=_schema_less),
)

def validate_parameters(cckm_az_key_module):
    return True

def setup_module_object():
    module = ThalesCipherTrustModule(
        argument_spec=argument_spec,
        required_if=(
            ['op_type', 'create', ['azure_param', 'key_name', 'key_vault']],
            ['op_type', 'update', ['key_id']],
            ['op_type', 'key_op', ['key_id', 'key_op_type']],
            ['op_type', 'cancel-sync-job', ['job_id']],
            ['op_type', 'upload-key', ['key_name', 'key_vault']],
        ),
        mutually_exclusive=[],
        supports_check_mode=True,
    )
    return module

def main():

    global module
    
    module = setup_module_object()
    validate_parameters(
        cckm_az_key_module=module,
    )

    result = dict(
        changed=False,
    )

    if module.params.get('op_type') == 'create':
      try:
        response = addCCKMCloudAsset(
          node=module.params.get('localNode'),
          asset_type="key",
          cloud_type="az",
          azure_param=module.params.get('azure_param'),
          key_name=module.params.get('key_name'),
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
          asset_type="key",
          cloud_type="az",
          attributes=module.params.get('attributes'),
          key_ops=module.params.get('key_ops'),
          tags=module.params.get('tags'),
        )
        result['response'] = response
      except CMApiException as api_e:
        if api_e.api_error_code:
          module.fail_json(msg="status code: " + str(api_e.api_error_code) + " message: " + api_e.message)
      except AnsibleCMException as custom_e:
        module.fail_json(msg=custom_e.message)

    elif module.params.get('op_type') == 'key_op':
      if module.params.get('key_op_type') == 'restore':
        try:
          response = performAZKeyOperation(
            node=module.params.get('localNode'),
            id=module.params.get('key_id'),
            key_op_type=module.params.get('key_op_type'),
            key_vault=module.params.get('key_vault'),
          )
          result['response'] = response
        except CMApiException as api_e:
          if api_e.api_error_code:
            module.fail_json(msg="status code: " + str(api_e.api_error_code) + " message: " + api_e.message)
        except AnsibleCMException as custom_e:
          module.fail_json(msg=custom_e.message)   
      elif module.params.get('key_op_type') == 'enable-rotation-job':
        try:
          response = performAZKeyOperation(
            node=module.params.get('localNode'),
            id=module.params.get('key_id'),
            key_op_type=module.params.get('key_op_type'),
            auto_rotate_key_source=module.params.get('auto_rotate_key_source'),
            auto_rotate_key_type=module.params.get('auto_rotate_key_type'),
            job_config_id=module.params.get('job_config_id'),
            auto_rotate_domain_id=module.params.get('auto_rotate_domain_id'),
            auto_rotate_ec_name=module.params.get('auto_rotate_ec_name'),
            auto_rotate_enable_key=module.params.get('auto_rotate_enable_key'),
            auto_rotate_key_size=module.params.get('auto_rotate_key_size'),
            auto_rotate_partition_id=module.params.get('auto_rotate_partition_id'),
            auto_rotate_key_source=module.params.get('auto_rotate_release_policy'),
          )
          result['response'] = response
        except CMApiException as api_e:
          if api_e.api_error_code:
            module.fail_json(msg="status code: " + str(api_e.api_error_code) + " message: " + api_e.message)
        except AnsibleCMException as custom_e:
          module.fail_json(msg=custom_e.message)       
      else:         
        try:
          response = performAZKeyOperation(
            node=module.params.get('localNode'),
            id=module.params.get('key_id'),
            key_op_type=module.params.get('key_op_type'),
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
          asset_type="key",
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
          asset_type="key",
          cloud_type="az",
        )
        result['response'] = response
      except CMApiException as api_e:
        if api_e.api_error_code:
          module.fail_json(msg="status code: " + str(api_e.api_error_code) + " message: " + api_e.message)
      except AnsibleCMException as custom_e:
        module.fail_json(msg=custom_e.message)

    elif module.params.get('op_type') == 'upload-key':
      try:
        response = uploadKeyOnAZ(
          node=module.params.get('localNode'),
          key_name=module.params.get('key_name'),
          key_vault=module.params.get('key_vault'),
          azure_param=module.params.get('azure_param'),
          dsm_key_identifier=module.params.get('dsm_key_identifier'),
          exportable=module.params.get('exportable'),
          kek_kid=module.params.get('kek_kid'),
          local_key_identifier=module.params.get('local_key_identifier'),
          luna_key_identifier=module.params.get('luna_key_identifier'),
          password=module.params.get('password'),
          pfx=module.params.get('pfx'),
          release_policy=module.params.get('release_policy'),
          source_key_tier=module.params.get('source_key_tier'),
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