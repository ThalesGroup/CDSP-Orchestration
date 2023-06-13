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
from ansible_collections.thales.ciphertrust.plugins.module_utils.cckm_aws import createCustomKeyStore, editCustomKeyStore, createAWSKeyCKS, blockCKS, unblockCKS, connectCKS, disconnectCKS, linkLocalCKSWithAWS, synchronize_AWS_CKS, cancelSynchronizeJob, rotateCredential, createVirtualKey, editVirtualKey, createHYOKKey, blockHYOKKey, unblockHYOKKey, linkHYOKKey
from ansible_collections.thales.ciphertrust.plugins.module_utils.exceptions import CMApiException, AnsibleCMException

DOCUMENTATION = '''
---
module: cckm_aws_custom_keystore
short_description: This is a Thales CipherTrust Manager module for working with the CipherTrust Manager APIs.
description:
    - This is a Thales CipherTrust Manager module for working with the CipherTrust Manager APIs, more specifically with CCKM for AWS
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

_aws_key_param = dict(
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
       'edit',
       'create-aws-key-cks',
       'block-cks-access',
       'unblock-cks-access',
       'connect-cks',
       'disconnect-cks',
       'link-local-cks',
       'create-synchronization-job',
       'cancel-synchronization-job',
       'rotate-credential',
       'create-virtual-key',
       'update-virtual-key',
       'create-hyok-key',
       'block-hyok-key',
       'unblock-hyok-key',
       'link-hyok-key',
       ], required=True),
    cks_id=dict(type='str'),
    cks_key_id=dict(type='str'),
    virtual_key_id=dict(type='str'),
    hyok_key_id=dict(type='str'),
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
    aws_key_param=dict(type='dict', options=_aws_key_param),
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

def validate_parameters(cckm_aws_module):
    return True

def setup_module_object():
    module = ThalesCipherTrustModule(
        argument_spec=argument_spec,
        required_if=(
            ['op_type', 'patch', ['cks_id']],
            ['op_type', 'create', ['aws_param', 'kms', 'name', 'region']],
        ),
        mutually_exclusive=[],
        supports_check_mode=True,
    )
    return module

def main():

    global module
    
    module = setup_module_object()
    validate_parameters(
        cckm_aws_module=module,
    )

    result = dict(
        changed=False,
    )

    if module.params.get('op_type') == 'create':
      try:
        response = createCustomKeyStore(
          node=module.params.get('localNode'),
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

    elif module.params.get('op_type') == 'edit':
      try:
        response = editCustomKeyStore(
          node=module.params.get('localNode'),
          id=module.params.get('cks_id'),
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

    elif module.params.get('op_type') == 'create-aws-key-cks':
      try:
        response = createAWSKeyCKS(
          node=module.params.get('localNode'),
          id=module.params.get('cks_id'),
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

    elif module.params.get('op_type') == 'block-cks-access':
      try:
        response = blockCKS(
          node=module.params.get('localNode'),
          id=module.params.get('cks_id'),
        )
        result['response'] = response
      except CMApiException as api_e:
        if api_e.api_error_code:
          module.fail_json(msg="status code: " + str(api_e.api_error_code) + " message: " + api_e.message)
      except AnsibleCMException as custom_e:
        module.fail_json(msg=custom_e.message)

    elif module.params.get('op_type') == 'unblock-cks-access':
      try:
        response = unblockCKS(
          node=module.params.get('localNode'),
          id=module.params.get('cks_id'),
        )
        result['response'] = response
      except CMApiException as api_e:
        if api_e.api_error_code:
          module.fail_json(msg="status code: " + str(api_e.api_error_code) + " message: " + api_e.message)
      except AnsibleCMException as custom_e:
        module.fail_json(msg=custom_e.message)

    elif module.params.get('op_type') == 'connect-cks':
      try:
        response = connectCKS(
          node=module.params.get('localNode'),
          id=module.params.get('cks_id'),
          key_store_password=module.params.get('key_store_password'),
        )
        result['response'] = response
      except CMApiException as api_e:
        if api_e.api_error_code:
          module.fail_json(msg="status code: " + str(api_e.api_error_code) + " message: " + api_e.message)
      except AnsibleCMException as custom_e:
        module.fail_json(msg=custom_e.message)

    elif module.params.get('op_type') == 'disconnect-cks':
      try:
        response = disconnectCKS(
          node=module.params.get('localNode'),
          id=module.params.get('cks_id'),
        )
        result['response'] = response
      except CMApiException as api_e:
        if api_e.api_error_code:
          module.fail_json(msg="status code: " + str(api_e.api_error_code) + " message: " + api_e.message)
      except AnsibleCMException as custom_e:
        module.fail_json(msg=custom_e.message)

    elif module.params.get('op_type') == 'link-local-cks':
      try:
        response = linkLocalCKSWithAWS(
          node=module.params.get('localNode'),
          id=module.params.get('cks_id'),
          aws_param=module.params.get('aws_param'),
        )
        result['response'] = response
      except CMApiException as api_e:
        if api_e.api_error_code:
          module.fail_json(msg="status code: " + str(api_e.api_error_code) + " message: " + api_e.message)
      except AnsibleCMException as custom_e:
        module.fail_json(msg=custom_e.message)

    elif module.params.get('op_type') == 'create-synchronization-job':
      try:
        response = synchronize_AWS_CKS(
          node=module.params.get('localNode'),
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
        response = cancelSynchronizeJob(
          node=module.params.get('localNode'),
          id=module.params.get('job_id'),
        )
        result['response'] = response
      except CMApiException as api_e:
        if api_e.api_error_code:
          module.fail_json(msg="status code: " + str(api_e.api_error_code) + " message: " + api_e.message)
      except AnsibleCMException as custom_e:
        module.fail_json(msg=custom_e.message)

    elif module.params.get('op_type') == 'rotate-credential':
      try:
        response = rotateCredential(
          node=module.params.get('localNode'),
          id=module.params.get('cks_id'),
        )
        result['response'] = response
      except CMApiException as api_e:
        if api_e.api_error_code:
          module.fail_json(msg="status code: " + str(api_e.api_error_code) + " message: " + api_e.message)
      except AnsibleCMException as custom_e:
        module.fail_json(msg=custom_e.message)

    elif module.params.get('op_type') == 'create-virtual-key':
      try:
        response = createVirtualKey(
          node=module.params.get('localNode'),
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
        response = editVirtualKey(
          node=module.params.get('localNode'),
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
        response = createHYOKKey(
          node=module.params.get('localNode'),
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

    elif module.params.get('op_type') == 'block-hyok-key':
      try:
        response = blockHYOKKey(
          node=module.params.get('localNode'),
          id=module.params.get('hyok_key_id'),
        )
        result['response'] = response
      except CMApiException as api_e:
        if api_e.api_error_code:
          module.fail_json(msg="status code: " + str(api_e.api_error_code) + " message: " + api_e.message)
      except AnsibleCMException as custom_e:
        module.fail_json(msg=custom_e.message)

    elif module.params.get('op_type') == 'unblock-hyok-key':
      try:
        response = unblockHYOKKey(
          node=module.params.get('localNode'),
          id=module.params.get('hyok_key_id'),
        )
        result['response'] = response
      except CMApiException as api_e:
        if api_e.api_error_code:
          module.fail_json(msg="status code: " + str(api_e.api_error_code) + " message: " + api_e.message)
      except AnsibleCMException as custom_e:
        module.fail_json(msg=custom_e.message)

    elif module.params.get('op_type') == 'link-hyok-key':
      try:
        response = linkHYOKKey(
          node=module.params.get('localNode'),
          id=module.params.get('hyok_key_id'),
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
        module.fail_json(msg="invalid op_type")
        
    module.exit_json(**result)

if __name__ == '__main__':
    main()