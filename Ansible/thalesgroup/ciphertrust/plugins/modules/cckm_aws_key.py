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
from ansible_collections.thalesgroup.ciphertrust.plugins.module_utils.cckm_aws import performKeyOperation, uploadKeyToAWS, verifyKeyAlias
from ansible_collections.thalesgroup.ciphertrust.plugins.module_utils.cckm_commons import addCCKMCloudAsset, editCCKMCloudAsset, createSyncJob, cancelSyncJob
from ansible_collections.thalesgroup.ciphertrust.plugins.module_utils.exceptions import CMApiException, AnsibleCMException

DOCUMENTATION = '''
---
module: cckm_aws_key
short_description: CCKM module for AWS Keys
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
        choices: [create, create-sync-job, cancel-sync-job, key_op, upload-key-aws, verify-key-alias, create-aws-template, patch-aws-template]
        required: true
        type: str
    key_id:
        description: AWS Key to be acted upon
        type: str
    template_id:
        description: AWS Key Policy to be acted upon
        type: str
    job_id:
        description: Synchronization Job ID
        type: str
    key_op_type:
        description: Operation to be performed
        choices: [enable-rotation-job, disable-rotation-job, import-material, delete-material, rotate, schedule-deletion, policy, update-description, enable, disable, add-tags, remove-tags, add-alias, delete-alias, cancel-deletion, enable-auto-rotation, disable-auto-rotation, replicate-key, update-primary-region]
        required: true
        type: str
    kms:
        description: Name or ID of the KMS to be used to create the key.
        type: str
    name:
        description: Unique name of the policy template.
        type: str
    region:
        description: Name of the available regions.
        type: str
    aws_param:
        description: Synchronization Job ID
        type: str
    external_accounts:
        description: AWS accounts that can use this key. External accounts are mutually exclusive to policy and policy template. If no policy parameters are specified, the default policy is used.
        type: list
    key_admins:
        description: IAM users who can administer this key using the KMS API. Key admins are mutually exclusive to policy and policy template. If no policy parameters are specified, the default policy is used.
        type: list
    key_admins_roles:
        description: IAM roles that can administer this key using the KMS API. Key admins are mutually exclusive to policy and policy template. If no policy parameters are specified, the default policy is used.
        type: list
    key_users:
        description: IAM users who can use the KMS key in cryptographic operations. Key users are mutually exclusive to policy and policy template. If no policy parameters are specified, the default policy is used.
        type: list
    key_users_roles:
        description: IAM roles that can use the KMS key in cryptographic operations. Key users are mutually exclusive to policy and policy template. If no policy parameters are specified, the default policy is used.
        type: list
    policytemplate:
        description: ID of the policy template to apply. Policy template is mutually exclusive to all other policy parameters. If no policy parameters are specified, the default policy is used.
        type: str
    kms_list:
        description: Name or ID of KMS resource from which the AWS custom key stores will be synchronized. synchronize_all and kms, regions are mutually exclusive. Specify either synchronize_all or kms and regions.
        type: list
    synchronize_all:
        description: Set true to synchronize all custom key stores from all kms and regions. synchronize_all and kms, regions are mutually exclusive. Specify either synchronize_all or kms and regions.
        type: bool
    regions:
        description: Regions from which the AWS custom key stores will be synchronized. If not specified, custom key stores from all regions are synchronized. synchronize_all and kms, regions are mutually exclusive. Specify either synchronize_all or kms and regions.
        type: list
    job_config_id:
        description: ID of the scheduler configuration job that will schedule the key rotation.
        type: str
    auto_rotate_disable_encrypt:
        description: Disable encryption on the old key.
        type: bool
    auto_rotate_domain_id:
        description: Id of the domain in which dsm key will be created.
        type: str
    auto_rotate_key_source:
        description: 
          - Key source from where the key will be uploaded.
          - local for CipherTrust Manager and it is default one
          - dsm for Data Security Manager (DSM)
          - hsm-luna for Luna HSM
        type: str
        choices: [local, dsm, hsm]
    auto_rotate_partition_id:
        description: Id of the partition in which hsm-luna key will be created.
        type: str
    key_expiration:
        description: Whether to disable encryption on key which is getting rotated .
        type: bool
    source_key_identifier:
        description:
          - If source_key_tier is local, source_key_identifier is the key identifier of the ciphertrust manager key to be uploaded. source_key_identifier is the mandatory parameter in case of dsm.
          - If source_key_tier is dsm, source_key_identifier is the key identifier of the dsm key to be uploaded. By default, a new CipherTrust Manager key would be generated automatically.
          - If key material is re-imported, AWS allows re-importing the same key material only, therefore it is mandatory to provide source key identifier of the same CipherTrust Manager key which was imported previously.
        type: str
    source_key_tier:
        description: Source key tier. Options are local, dsm and hsm-luna. Default is local.
        type: str
    valid_to:
        description: Id of the partition in which hsm-luna key will be created.
        type: str
        choices: [local, dsm, hsm]
    description:
        description: Description for the new key (after key rotation).
        type: str
    disable_encrypt:
        description: Indicates whether to disable encryption on the new key (after key rotation).
        type: bool
    retain_alias:
        description: Indicates whether to retain the alias with the timestamp on the archived key after key rotation.
        type: bool
    source_key_id:
        description:
          - If source_key_tier is dsm or hsm-luna, this parameter is the key identifier of the key to be uploaded. source_key_id is a mandatory parameter in the case of dsm and hsm-luna.
          - If source_key_tier is local, this parameter is the key identifier of the CipherTrust Manager key to be uploaded. By default, a new CipherTrust Manager key is generated automatically.
        type: str
    days:
        description: Number of days after which the key will be deleted.
        type: int
    tags:
        description: Tags to be added to the AWS key
        type: list
    policy:
        description: Key policy to attach to the KMS key. Policy is mutually exclusive to all other policy parameters. If no policy parameters are specified the default policy is created.
        type: dict
    alias:
        description: Alias to be added to the AWS key.
        type: str
    auto_push:
        description: Pushes the verified policy template to all the associated keys. Mandatorily required to update a 'verified' policy-template.
        type: bool
    replica_region:
        description: Name of the available regions.
        type: str
    PrimaryRegion:
        description: The AWS Region of the new primary key.Enter the region ID, such as us-east-1 ap-southeast-2. There must be an existing replica key in this region.
        type: str
'''

EXAMPLES = '''
- name: "Create AWS Key"
  thalesgroup.ciphertrust.cckm_aws_key:
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
    # add-tags
    tags=dict(type='list', element='str'),
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

    elif module.params.get('op_type') == 'cancel-sync-job':
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