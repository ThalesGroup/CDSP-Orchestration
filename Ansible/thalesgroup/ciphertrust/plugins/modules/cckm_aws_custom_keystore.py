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
from ansible_collections.thalesgroup.ciphertrust.plugins.module_utils.cckm_aws import performCKSOperation, performHYOKKeyOperation
from ansible_collections.thalesgroup.ciphertrust.plugins.module_utils.cckm_commons import addCCKMCloudAsset, editCCKMCloudAsset, createSyncJob, cancelSyncJob
from ansible_collections.thalesgroup.ciphertrust.plugins.module_utils.exceptions import CMApiException, AnsibleCMException

DOCUMENTATION = '''
---
module: cckm_aws_custom_keystore
short_description: CCKM module for AWS Custom Key Store
description:
    - This is a Thales CipherTrust Manager module for working with the CipherTrust Manager APIs, more specifically with CCKM for AWS Custom Key Store
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
        choices: [create, update, create-synchronization-job, cancel-synchronization-job, create-virtual-key, update-virtual-key,create-hyok-key, cks_op, hyok_op]
        required: true
        type: str
    cks_id:
        description: AWS Custom Key Store ID
        type: str
    cks_key_id:
        description: AWS Custom Key Store Key ID
        type: str
    virtual_key_id:
        description: Virtual Key ID
        type: str
    hyok_key_id:
        description: HYOK Key ID
        type: str
    job_id:
        description: Synchronization Job ID
        type: str
    cks_op_type:
        description: Operation that can be performed on a Custom Key Store
        choices: [create-aws-key, connect, link, block, unblock, disconnect, rotate-credential]
        type: str
    hyok_op_type:
        description: Operation that can be performed on an HYOK Key
        choices: [block, unblock, link]
        type: str
    aws_param:
        description: Parameters related to AWS interaction with a custom key store
        type: dict
    kms:
        description: Name or ID of the AWS Account container in which to create the key store.
        type: str
    name:
        description: Unique name for the custom key store
        type: str
    region:
        description: Name of the available AWS regions
        type: str
    linked_state:
        description: Indicates whether the custom key store is linked with AWS. Applicable to a custom key store of type EXTERNAL_KEY_STORE. Default value is false. When false, creating a custom key store in the CCKM does not trigger the AWS KMS to create a new key store. Also, the new custom key store will not synchronize with any key stores within the AWS KMS until the new key store is linked.
        type: bool
    local_hosted_params:
        description: Parameters for a custom key store that is locally hosted
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
    cks_key_param:
        description: AWS key parameters.
        type: dict
    key_store_password:
        description: The password of the kmsuser crypto user (CU) account configured in the specified CloudHSM cluster. This parameter does not change the password in CloudHSM cluster. User needs to configure the credentials on CloudHSM cluster separately. Required field for custom key store of type AWS_CLOUDHSM. Omit for External Key Stores.
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
    source_key_id:
        description: The unique id of the source key (Luna HSM key) for the first version of the virtual key.
        type: str
    deletable:
        description: Mouse over a property in the schema to view its details.
        type: bool
'''

EXAMPLES = '''
- name: "Create AWS CKS"
  thalesgroup.ciphertrust.cckm_aws_custom_keystore:
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

_aws_param = dict(
   cloud_hsm_cluster_id=dict(type='str'),
   custom_key_store_type=dict(type='str', options=['EXTERNAL_KEY_STORE', 'AWS_CLOUDHSM']),
   key_store_password=dict(type='str'),
   trust_anchor_certificate=dict(type='str'),
   xks_proxy_connectivity=dict(type='str', options=['VPC_ENDPOINT_SERVICE', 'PUBLIC_ENDPOINT']),
   xks_proxy_uri_endpoint=dict(type='str'),
   xks_proxy_vpc_endpoint_service_name=dict(type='str'),
)

_aws_key_param_tag = dict(
   TagKey=dict(type='str'),
   TagValue=dict(type='str'),
)

_cks_key_param = dict(
   Alias=dict(type='str'),
   Description=dict(type='str'),
   Policy=dict(type='dict', options=_schema_less),
   Tags=dict(type='list', element='dict', options=_aws_key_param_tag),
)

_local_hosted_param = dict(
   blocked=dict(type='bool'),
   health_check_key_id=dict(type='str'),
   max_credentials=dict(type='str'),
   partition_id=dict(type='str'),
   source_key_tier=dict(type='str', options=['local', 'luna-hsm']),
   custom_key_store_id=dict(type='str'),
   linked_state=dict(type='bool'),
   source_key_id=dict(type='str'),
)

argument_spec = dict(
    op_type=dict(type='str', options=[
       'create', 
       'update',
       'create-synchronization-job',
       'cancel-synchronization-job',
       'create-virtual-key',
       'update-virtual-key',
       'create-hyok-key',
       'cks_op',
       'hyok_op',
       ], required=True),
    cks_id=dict(type='str'),
    cks_key_id=dict(type='str'),
    virtual_key_id=dict(type='str'),
    hyok_key_id=dict(type='str'),
    cks_op_type=dict(type='str', options=['create-aws-key', 'connect', 'link', 'block', 'unblock', 'disconnect', 'rotate-credential']),
    hyok_op_type=dict(type='str', options=['block', 'unblock', 'link']),
    # Create CKS
    aws_param=dict(type='dict', options=_aws_param),
    kms=dict(type='str'),
    name=dict(type='str'),
    region=dict(type='str'),
    linked_state=dict(type='bool'),
    local_hosted_params=dict(type='dict', options=_local_hosted_param),
    # create-aws-key params
    external_accounts=dict(type='list', element='str'),
    key_admins=dict(type='list', element='str'),
    key_admins_roles=dict(type='list', element='str'),
    key_users=dict(type='list', element='str'),
    key_users_roles=dict(type='list', element='str'),
    policytemplate=dict(type='str'),
    cks_key_param=dict(type='dict', options=_cks_key_param),
    # connect-cks
    key_store_password=dict(type='str'),
    # synchronization-jobs
    kms_list=dict(type='list', element='str'),
    regions=dict(type='list', element='str'),
    synchronize_all=dict(type='bool'),
    job_id=dict(type='str'),
    # create-virtual-key
    source_key_id=dict(type='str'),
    # update-virtual-key
    deletable=dict(type='bool'),
)

def validate_parameters(cckm_aws_cks_module):
    return True

def setup_module_object():
    module = ThalesCipherTrustModule(
        argument_spec=argument_spec,
        required_if=(
            ['op_type', 'update', ['cks_id']],
            ['op_type', 'create', ['aws_param', 'kms', 'name', 'region']],
            ['op_type', 'create-virtual-key', ['source_key_id']],
            ['op_type', 'cancel-synchronization-job', ['job_id']]
            ['op_type', 'cks_op', ['cks_id', 'cks_op_type']]
            ['op_type', 'hyok_op', ['hyok_key_id', 'hyok_op_type']]
        ),
        mutually_exclusive=[],
        supports_check_mode=True,
    )
    return module

def main():

    global module
    
    module = setup_module_object()
    validate_parameters(
        cckm_aws_cks_module=module,
    )

    result = dict(
        changed=False,
    )

    if module.params.get('op_type') == 'create':
      try:
        response = addCCKMCloudAsset(
          node=module.params.get('localNode'),
          asset_type="cks",
          cloud_type="aws",
          aws_param=module.params.get('aws_param'),
          kms=module.params.get('kms'),
          name=module.params.get('name'),
          region=module.params.get('region'),
          linked_state=module.params.get('linked_state'),
          local_hosted_params=module.params.get('local_hosted_params'),
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
          id=module.params.get('cks_id'),
          asset_type="cks",
          cloud_type="aws",
          aws_param=module.params.get('aws_param'),
          local_hosted_params=module.params.get('local_hosted_params'),
          name=module.params.get('name'),
        )
        result['response'] = response
      except CMApiException as api_e:
        if api_e.api_error_code:
          module.fail_json(msg="status code: " + str(api_e.api_error_code) + " message: " + api_e.message)
      except AnsibleCMException as custom_e:
        module.fail_json(msg=custom_e.message)

    elif module.params.get('op_type') == 'cks_op':
      if module.params.get('cks_op_type') == 'create-aws-key':
        try:
          response = performCKSOperation(
            node=module.params.get('localNode'),
            id=module.params.get('cks_id'),
            cks_op_type=module.params.get('cks_op_type'),
            aws_param=module.params.get('cks_key_param'),
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
      elif module.params.get('cks_op_type') == 'connect':
        try:
          response = performCKSOperation(
            node=module.params.get('localNode'),
            cks_op_type=module.params.get('cks_op_type'),
            id=module.params.get('cks_id'),
            key_store_password=module.params.get('key_store_password'),
          )
          result['response'] = response
        except CMApiException as api_e:
          if api_e.api_error_code:
            module.fail_json(msg="status code: " + str(api_e.api_error_code) + " message: " + api_e.message)
        except AnsibleCMException as custom_e:
          module.fail_json(msg=custom_e.message)
      elif module.params.get('cks_op_type') == 'link':
        try:
          response = performCKSOperation(
            node=module.params.get('localNode'),
            cks_op_type=module.params.get('cks_op_type'),
            id=module.params.get('cks_id'),
            aws_param=module.params.get('aws_param'),
          )
          result['response'] = response
        except CMApiException as api_e:
          if api_e.api_error_code:
            module.fail_json(msg="status code: " + str(api_e.api_error_code) + " message: " + api_e.message)
        except AnsibleCMException as custom_e:
          module.fail_json(msg=custom_e.message)
      else:        
        try:
          response = performCKSOperation(
            node=module.params.get('localNode'),
            id=module.params.get('vault_id'),
            cks_op_type=module.params.get('cks_op_type'),
          )
          result['response'] = response
        except CMApiException as api_e:
          if api_e.api_error_code:
            module.fail_json(msg="status code: " + str(api_e.api_error_code) + " message: " + api_e.message)
        except AnsibleCMException as custom_e:
          module.fail_json(msg=custom_e.message)

    elif module.params.get('op_type') == 'create-synchronization-job':
      try:
        response = createSyncJob(
          node=module.params.get('localNode'),
          asset_type="cks",
          cloud_type="aws",
          kms=module.params.get('kms_list'),
          synchronize_all=module.params.get('synchronize_all'),
          regions=module.params.get('regions'),
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
          asset_type="cks",
          cloud_type="aws",
        )
        result['response'] = response
      except CMApiException as api_e:
        if api_e.api_error_code:
          module.fail_json(msg="status code: " + str(api_e.api_error_code) + " message: " + api_e.message)
      except AnsibleCMException as custom_e:
        module.fail_json(msg=custom_e.message)

    elif module.params.get('op_type') == 'create-virtual-key':
      try:
        response = addCCKMCloudAsset(
          node=module.params.get('localNode'),
          asset_type="virtual-key",
          cloud_type="aws",
          source_key_id=module.params.get('source_key_id'),
        )
        result['response'] = response
      except CMApiException as api_e:
        if api_e.api_error_code:
          module.fail_json(msg="status code: " + str(api_e.api_error_code) + " message: " + api_e.message)
      except AnsibleCMException as custom_e:
        module.fail_json(msg=custom_e.message)

    elif module.params.get('op_type') == 'update-virtual-key':
      try:
        response = editCCKMCloudAsset(
          node=module.params.get('localNode'),
          asset_type="virtual-key",
          cloud_type="aws",
          id=module.params.get('virtual_key_id'),
          deletable=module.params.get('deletable'),
        )
        result['response'] = response
      except CMApiException as api_e:
        if api_e.api_error_code:
          module.fail_json(msg="status code: " + str(api_e.api_error_code) + " message: " + api_e.message)
      except AnsibleCMException as custom_e:
        module.fail_json(msg=custom_e.message)

    elif module.params.get('op_type') == 'create-hyok-key':
      try:
        response = addCCKMCloudAsset(
          node=module.params.get('localNode'),
          asset_type="hyok-key",
          cloud_type="aws",
          aws_param=module.params.get('aws_key_param'),
          external_accounts=module.params.get('external_accounts'),
          key_admins=module.params.get('key_admins'),
          key_admins_roles=module.params.get('key_admins_roles'),
          key_users=module.params.get('key_users'),
          key_users_roles=module.params.get('key_users_roles'),
          local_hosted_params=module.params.get('local_hosted_params'),
          policytemplate=module.params.get('policytemplate'),
        )
        result['response'] = response
      except CMApiException as api_e:
        if api_e.api_error_code:
          module.fail_json(msg="status code: " + str(api_e.api_error_code) + " message: " + api_e.message)
      except AnsibleCMException as custom_e:
        module.fail_json(msg=custom_e.message)

    elif module.params.get('op_type') == 'hyok_op':
      if module.params.get('hyok_op_type') == 'link':
        try:
          response = performHYOKKeyOperation(
            node=module.params.get('localNode'),
            id=module.params.get('hyok_key_id'),
            hyok_op_type=module.params.get('hyok_op_type'),
            aws_param=module.params.get('aws_key_param'),
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
      else:        
        try:
          response = performHYOKKeyOperation(
            node=module.params.get('localNode'),
            id=module.params.get('hyok_key_id'),
            hyok_op_type=module.params.get('hyok_op_type'),
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