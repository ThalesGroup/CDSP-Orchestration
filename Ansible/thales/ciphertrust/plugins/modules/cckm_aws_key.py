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
from ansible_collections.thales.ciphertrust.plugins.module_utils.cckm_aws import performKeyOperation, uploadKeyToAWS, verifyKeyAlias
from ansible_collections.thales.ciphertrust.plugins.module_utils.cckm_commons import addCCKMCloudAsset, editCCKMCloudAsset, createSyncJob, cancelSyncJob
from ansible_collections.thales.ciphertrust.plugins.module_utils.exceptions import CMApiException, AnsibleCMException

DOCUMENTATION = '''
---
module: cckm_aws_key
short_description: This is a Thales CipherTrust Manager module for working with the CipherTrust Manager APIs.
description:
    - This is a Thales CipherTrust Manager module for working with the CipherTrust Manager APIs, more specifically with CCKM for AWS Keys
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
        choices: [create, patch]
        required: true
        type: str
'''

EXAMPLES = '''
- name: "Create AWS Connection"
  thales.ciphertrust.connection_manager_aws:
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

_aws_key_param_tag = dict(
   TagKey=dict(type='str'),
   TagValue=dict(type='str'),
)

_aws_key_param = dict(
   Alias=dict(type='str'),
   BypassPolicyLockoutSafetyCheck=dict(type='bool'),
   CustomerMasterKeySpec=dict(type='str', options=['SYMMETRIC_DEFAULT', 'RSA_2048', 'RSA_3072', 'RSA_4096', 'ECC_NIST_P256', 'ECC_NIST_P384', 'ECC_NIST_P521', 'ECC_NIST_P256K1']),
   KeyUsage=dict(type='str', options=['ENCRYPT_DECRYPT', 'SIGN_VERIFY']),
   MultiRegion=dict(type='bool'),
   Origin=dict(type='str', options=['AWS_KMS', 'EXTERNAL']),
   Description=dict(type='str'),
   Policy=dict(type='dict', options=_schema_less),
   Tags=dict(type='list', element='dict', options=_aws_key_param_tag),
   ValidTo=dict(type='str'),
)

argument_spec = dict(
    op_type=dict(type='str', options=[
       'create', 
       'create-sync-job',
       'cancel-sync-job',
       'key_op',
       'upload-key-aws',
       'verify-key-alias',
       'create-aws-template',
       'patch-aws-template',
       ], required=True),
    key_id=dict(type='str'),
    template_id=dict(type='str'),
    job_id=dict(type='str'),
    key_op_type=dict(type='str', options=[
      'enable-rotation-job',
      'disable-rotation-job',
      'import-material',
      'delete-material',
      'rotate',
      'schedule-deletion',
      'policy',
      'update-description',
      'enable',
      'disable',
      'add-tags',
      'remove-tags',
      'add-alias',
      'delete-alias',
      'cancel-deletion',
      'enable-auto-rotation',
      'disable-auto-rotation',
      'replicate-key',
      'update-primary-region',
    ]),
    kms=dict(type='str'),
    name=dict(type='str'),
    region=dict(type='str'),
    aws_param=dict(type='dict', options=_aws_key_param),
    external_accounts=dict(type='list', element='str'),
    key_admins=dict(type='list', element='str'),
    key_admins_roles=dict(type='list', element='str'),
    key_users=dict(type='list', element='str'),
    key_users_roles=dict(type='list', element='str'),
    policytemplate=dict(type='str'),
    # synchronization-jobs
    kms_list=dict(type='list', element='str'),
    regions=dict(type='list', element='str'),
    synchronize_all=dict(type='bool'),
    # enable-rotation-job
    job_config_id=dict(type='str'),
    auto_rotate_disable_encrypt=dict(type='bool'),
    auto_rotate_domain_id=dict(type='str'),
    auto_rotate_key_source=dict(type='str', options=['local', 'dsm', 'hsm']),
    auto_rotate_partition_id=dict(type='str'),
    # import-material
    key_expiration=dict(type='bool'),
    source_key_identifier=dict(type='str'),
    source_key_tier=dict(type='str', options=['local', 'dsm', 'hsm-luna']),
    valid_to=dict(type='str'),
    # rotate
    description=dict(type='str'),
    disable_encrypt=dict(type='bool'),
    retain_alias=dict(type='bool'),
    source_key_id=dict(type='str'),
    # schedule-deletion
    days=dict(type='int'),
    # policy
    policy=dict(type='dict', options=_schema_less),
    # add-alias
    alias=dict(type='str'),
    # patch-aws-template
    auto_push=dict(type='bool'),
    # replicate-key
    replica_region=dict(type='str'),
    # update-primary-region
    PrimaryRegion=dict(type='str'),
)

def validate_parameters(cckm_aws_key_module):
    return True

def setup_module_object():
    module = ThalesCipherTrustModule(
        argument_spec=argument_spec,
        required_if=(
            ['op_type', 'create', ['kms', 'region']],
            ['op_type', 'cancel-sync-job', ['job_id']],
            ['op_type', 'key_op', ['key_id', 'key_op_type']],
            ['op_type', 'upload-key-aws', ['kms', 'region', 'source_key_identifier']],
            ['op_type', 'verify-key-alias', ['alias', 'kms', 'region']],
            ['op_type', 'create-aws-template', ['kms', 'name']],
            ['op_type', 'patch-aws-template', ['template_id', 'kms']],
        ),
        mutually_exclusive=[],
        supports_check_mode=True,
    )
    return module

def main():

    global module
    
    module = setup_module_object()
    validate_parameters(
        cckm_aws_key_module=module,
    )

    result = dict(
        changed=False,
    )

    if module.params.get('op_type') == 'create':
      try:
        response = addCCKMCloudAsset(
          node=module.params.get('localNode'),
          asset_type="key",
          cloud_type="aws",
          aws_param=module.params.get('aws_param'),
          kms=module.params.get('kms'),
          region=module.params.get('region'),
          external_accounts=module.params.get('external_accounts'),
          key_admins=module.params.get('key_admins'),
          key_admins_roles=module.params.get('key_admins_roles'),
          key_users=module.params.get('key_users'),
          key_users_roles=module.params.get('key_users_roles'),
          policytemplate=module.params.get('policytemplate'),
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
          cloud_type="aws",
          kms=module.params.get('kms'),
          regions=module.params.get('regions'),
          synchronize_all=module.params.get('synchronize_all'),
        )
        result['response'] = response
      except CMApiException as api_e:
        if api_e.api_error_code:
          module.fail_json(msg="status code: " + str(api_e.api_error_code) + " message: " + api_e.message)
      except AnsibleCMException as custom_e:
        module.fail_json(msg=custom_e.message)

    elif module.params.get('op_type') == 'cancel-synchronization-job':
      try:
        response = cancelSyncJob(
          node=module.params.get('localNode'),
          id=module.params.get('job_id'),
          asset_type="key",
          cloud_type="aws",
        )
        result['response'] = response
      except CMApiException as api_e:
        if api_e.api_error_code:
          module.fail_json(msg="status code: " + str(api_e.api_error_code) + " message: " + api_e.message)
      except AnsibleCMException as custom_e:
        module.fail_json(msg=custom_e.message)

    elif module.params.get('op_type') == 'key_op':
      if module.params.get('key_op_type') == "enable-rotation-job":
        try:
          response = performKeyOperation(
            node=module.params.get('localNode'),
            key_op_type=module.params.get('key_op_type'),
            id=module.params.get('key_id'),
            job_config_id=module.params.get('job_config_id'),
            auto_rotate_disable_encrypt=module.params.get('auto_rotate_disable_encrypt'),
            auto_rotate_domain_id=module.params.get('auto_rotate_domain_id'),
            auto_rotate_key_source=module.params.get('auto_rotate_key_source'),
            auto_rotate_partition_id=module.params.get('auto_rotate_partition_id'),
          )
          result['response'] = response
        except CMApiException as api_e:
          if api_e.api_error_code:
            module.fail_json(msg="status code: " + str(api_e.api_error_code) + " message: " + api_e.message)
        except AnsibleCMException as custom_e:
          module.fail_json(msg=custom_e.message)
      elif module.params.get('key_op_type') == "import-material":
        try:
          response = performKeyOperation(
            node=module.params.get('localNode'),
            key_op_type=module.params.get('key_op_type'),
            id=module.params.get('key_id'),
            key_expiration=module.params.get('key_expiration'),
            source_key_identifier=module.params.get('source_key_identifier'),
            source_key_tier=module.params.get('source_key_tier'),
            valid_to=module.params.get('valid_to'),
          )
          result['response'] = response
        except CMApiException as api_e:
          if api_e.api_error_code:
            module.fail_json(msg="status code: " + str(api_e.api_error_code) + " message: " + api_e.message)
        except AnsibleCMException as custom_e:
          module.fail_json(msg=custom_e.message)
      elif module.params.get('key_op_type') == "rotate":
        try:
          response = performKeyOperation(
            node=module.params.get('localNode'),
            key_op_type=module.params.get('key_op_type'),
            id=module.params.get('key_id'),
            description=module.params.get('description'),
            disable_encrypt=module.params.get('disable_encrypt'),
            key_expiration=module.params.get('key_expiration'),
            retain_alias=module.params.get('retain_alias'),
            source_key_id=module.params.get('source_key_id'),
            source_key_tier=module.params.get('source_key_tier'),
            valid_to=module.params.get('valid_to'),
          )
          result['response'] = response
        except CMApiException as api_e:
          if api_e.api_error_code:
            module.fail_json(msg="status code: " + str(api_e.api_error_code) + " message: " + api_e.message)
        except AnsibleCMException as custom_e:
          module.fail_json(msg=custom_e.message)
      elif module.params.get('key_op_type') == "schedule-deletion":
        try:
          response = performKeyOperation(
            node=module.params.get('localNode'),
            key_op_type=module.params.get('key_op_type'),
            id=module.params.get('key_id'),
            days=module.params.get('days'),
          )
          result['response'] = response
        except CMApiException as api_e:
          if api_e.api_error_code:
            module.fail_json(msg="status code: " + str(api_e.api_error_code) + " message: " + api_e.message)
        except AnsibleCMException as custom_e:
          module.fail_json(msg=custom_e.message)
      elif module.params.get('key_op_type') == "policy":
        try:
          response = performKeyOperation(
            node=module.params.get('localNode'),
            key_op_type=module.params.get('key_op_type'),
            id=module.params.get('key_id'),
            external_accounts=module.params.get('external_accounts'),
            key_admins=module.params.get('key_admins'),
            key_admins_roles=module.params.get('key_admins_roles'),
            key_users=module.params.get('key_users'),
            key_users_roles=module.params.get('key_users_roles'),
            policy=module.params.get('policy'),
            policytemplate=module.params.get('policytemplate'),
          )
          result['response'] = response
        except CMApiException as api_e:
          if api_e.api_error_code:
            module.fail_json(msg="status code: " + str(api_e.api_error_code) + " message: " + api_e.message)
        except AnsibleCMException as custom_e:
          module.fail_json(msg=custom_e.message)
      elif module.params.get('key_op_type') == "update-description":
        try:
          response = performKeyOperation(
            node=module.params.get('localNode'),
            key_op_type=module.params.get('key_op_type'),
            id=module.params.get('key_id'),
            description=module.params.get('description'),
          )
          result['response'] = response
        except CMApiException as api_e:
          if api_e.api_error_code:
            module.fail_json(msg="status code: " + str(api_e.api_error_code) + " message: " + api_e.message)
        except AnsibleCMException as custom_e:
          module.fail_json(msg=custom_e.message)
      elif module.params.get('key_op_type') == "add-tags":
        try:
          response = performKeyOperation(
            node=module.params.get('localNode'),
            key_op_type=module.params.get('key_op_type'),
            id=module.params.get('key_id'),
            tags=module.params.get('tags'),
          )
          result['response'] = response
        except CMApiException as api_e:
          if api_e.api_error_code:
            module.fail_json(msg="status code: " + str(api_e.api_error_code) + " message: " + api_e.message)
        except AnsibleCMException as custom_e:
          module.fail_json(msg=custom_e.message)
      elif module.params.get('key_op_type') == "remove-tags":
        try:
          response = performKeyOperation(
            node=module.params.get('localNode'),
            key_op_type=module.params.get('key_op_type'),
            id=module.params.get('key_id'),
            tags=module.params.get('tags'),
          )
          result['response'] = response
        except CMApiException as api_e:
          if api_e.api_error_code:
            module.fail_json(msg="status code: " + str(api_e.api_error_code) + " message: " + api_e.message)
        except AnsibleCMException as custom_e:
          module.fail_json(msg=custom_e.message)
      elif module.params.get('key_op_type') == "add-alias":
        try:
          response = performKeyOperation(
            node=module.params.get('localNode'),
            key_op_type=module.params.get('key_op_type'),
            id=module.params.get('key_id'),
            tags=module.params.get('alias'),
          )
          result['response'] = response
        except CMApiException as api_e:
          if api_e.api_error_code:
            module.fail_json(msg="status code: " + str(api_e.api_error_code) + " message: " + api_e.message)
        except AnsibleCMException as custom_e:
          module.fail_json(msg=custom_e.message)
      elif module.params.get('key_op_type') == "delete-alias":
        try:
          response = performKeyOperation(
            node=module.params.get('localNode'),
            key_op_type=module.params.get('key_op_type'),
            id=module.params.get('key_id'),
            tags=module.params.get('alias'),
          )
          result['response'] = response
        except CMApiException as api_e:
          if api_e.api_error_code:
            module.fail_json(msg="status code: " + str(api_e.api_error_code) + " message: " + api_e.message)
        except AnsibleCMException as custom_e:
          module.fail_json(msg=custom_e.message)
      elif module.params.get('key_op_type') == "replicate-key":
        try:
          response = performKeyOperation(
            node=module.params.get('localNode'),
            key_op_type=module.params.get('key_op_type'),
            id=module.params.get('key_id'),
            replica_region=module.params.get('replica_region'),
            aws_param=module.params.get('aws_param'),
            external_accounts=module.params.get('external_accounts'),
            key_admins=module.params.get('key_admins'),
            key_admins_roles=module.params.get('key_admins_roles'),
            key_users=module.params.get('key_users'),
            key_users_roles=module.params.get('key_users_roles'),
            policytemplate=module.params.get('policytemplate'),
          )
          result['response'] = response
        except CMApiException as api_e:
          if api_e.api_error_code:
            module.fail_json(msg="status code: " + str(api_e.api_error_code) + " message: " + api_e.message)
        except AnsibleCMException as custom_e:
          module.fail_json(msg=custom_e.message)
      elif module.params.get('key_op_type') == "update-primary-region":
        try:
          response = performKeyOperation(
            node=module.params.get('localNode'),
            key_op_type=module.params.get('key_op_type'),
            id=module.params.get('key_id'),
            PrimaryRegion=module.params.get('PrimaryRegion'),
          )
          result['response'] = response
        except CMApiException as api_e:
          if api_e.api_error_code:
            module.fail_json(msg="status code: " + str(api_e.api_error_code) + " message: " + api_e.message)
        except AnsibleCMException as custom_e:
          module.fail_json(msg=custom_e.message)
      else:
        try:
          response = performKeyOperation(
            node=module.params.get('localNode'),
            key_op_type=module.params.get('key_op_type'),
            id=module.params.get('key_id'),
          )
          result['response'] = response
        except CMApiException as api_e:
          if api_e.api_error_code:
            module.fail_json(msg="status code: " + str(api_e.api_error_code) + " message: " + api_e.message)
        except AnsibleCMException as custom_e:
          module.fail_json(msg=custom_e.message)
  
    elif module.params.get('op_type') == 'upload-key-aws':
      try:
        response = uploadKeyToAWS(
          node=module.params.get('localNode'),
          kms=module.params.get('kms'),
          region=module.params.get('region'),
          source_key_identifier=module.params.get('source_key_identifier'),
          aws_param=module.params.get('aws_param'),
          external_accounts=module.params.get('external_accounts'),
          key_admins=module.params.get('key_admins'),
          key_admins_roles=module.params.get('key_admins_roles'),
          key_expiration=module.params.get('key_expiration'),
          key_users=module.params.get('key_users'),
          key_users_roles=module.params.get('key_users_roles'),
          policytemplate=module.params.get('policytemplate'),
          source_key_tier=module.params.get('source_key_tier'),
        )
        result['response'] = response
      except CMApiException as api_e:
        if api_e.api_error_code:
          module.fail_json(msg="status code: " + str(api_e.api_error_code) + " message: " + api_e.message)
      except AnsibleCMException as custom_e:
        module.fail_json(msg=custom_e.message)

    elif module.params.get('op_type') == 'verify-key-alias':
      try:
        response = verifyKeyAlias(
          node=module.params.get('localNode'),
          alias=module.params.get('alias'),
          kms=module.params.get('kms'),
          region=module.params.get('region'),
        )
        result['response'] = response
      except CMApiException as api_e:
        if api_e.api_error_code:
          module.fail_json(msg="status code: " + str(api_e.api_error_code) + " message: " + api_e.message)
      except AnsibleCMException as custom_e:
        module.fail_json(msg=custom_e.message)

    elif module.params.get('op_type') == 'create-aws-template':
      try:
        response = addCCKMCloudAsset(
          node=module.params.get('localNode'),
          asset_type="template",
          cloud_type="aws",
          kms=module.params.get('kms'),
          name=module.params.get('name'),
          external_accounts=module.params.get('external_accounts'),
          key_admins=module.params.get('key_admins'),
          key_admins_roles=module.params.get('key_admins_roles'),
          key_users=module.params.get('key_users'),
          key_users_roles=module.params.get('key_users_roles'),
          policy=module.params.get('policy'),
        )
        result['response'] = response
      except CMApiException as api_e:
        if api_e.api_error_code:
          module.fail_json(msg="status code: " + str(api_e.api_error_code) + " message: " + api_e.message)
      except AnsibleCMException as custom_e:
        module.fail_json(msg=custom_e.message)

    elif module.params.get('op_type') == 'patch-aws-template':
      try:
        response = editCCKMCloudAsset(
          node=module.params.get('localNode'),
          asset_type="template",
          cloud_type="aws",
          id=module.params.get('template_id'),
          kms=module.params.get('kms'),
          auto_push=module.params.get('auto_push'),
          external_accounts=module.params.get('external_accounts'),
          key_admins=module.params.get('key_admins'),
          key_admins_roles=module.params.get('key_admins_roles'),
          key_users=module.params.get('key_users'),
          key_users_roles=module.params.get('key_users_roles'),
          policy=module.params.get('policy'),
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