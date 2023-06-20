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
from ansible_collections.thales.ciphertrust.plugins.module_utils.cckm_gcp import performKeyOperation, performKeyVersionOperation, uploadKeyGCP, updateAllKeyVersions
from ansible_collections.thales.ciphertrust.plugins.module_utils.cckm_commons import addCCKMCloudAsset, editCCKMCloudAsset, createSyncJob, cancelSyncJob
from ansible_collections.thales.ciphertrust.plugins.module_utils.exceptions import CMApiException, AnsibleCMException

DOCUMENTATION = '''
---
module: cckm_gcp_key
short_description: This is a Thales CipherTrust Manager module for working with the CipherTrust Manager APIs.
description:
    - This is a Thales CipherTrust Manager module for working with the CipherTrust Manager APIs, more specifically with CCKM for GCP Keys
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
'''

EXAMPLES = '''
- name: "Create GCP Key"
  thales.ciphertrust.cckm_gcp_key:
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

_gcp_key_param = dict(
  algorithm=dict(type='str', options=[
      'RSA_SIGN_PSS_2048_SHA256',
      'RSA_SIGN_PSS_3072_SHA256',
      'RSA_SIGN_PSS_4096_SHA256',
      'RSA_SIGN_PSS_4096_SHA512',
      'RSA_SIGN_PKCS1_2048_SHA256',
      'RSA_SIGN_PKCS1_3072_SHA256',
      'RSA_SIGN_PKCS1_4096_SHA256',
      'RSA_SIGN_PKCS1_4096_SHA512',
      'RSA_DECRYPT_OAEP_2048_SHA256',
      'RSA_DECRYPT_OAEP_3072_SHA256',
      'RSA_DECRYPT_OAEP_4096_SHA256',
      'RSA_DECRYPT_OAEP_4096_SHA512',
      'EC_SIGN_P256_SHA256',
      'EC_SIGN_P384_SHA384',
      'EC_SIGN_SECP256K1_SHA256',
      'GOOGLE_SYMMETRIC_ENCRYPTION',
      'HMAC_SHA256',
      ]),
  key_name=dict(type='str'),
  protection_level=dict(type='str', options=['SOFTWARE', 'HSM']),
  purpose=dict(type='str', options=['ENCRYPT_DECRYPT', 'ASYMMETRIC_SIGN', 'ASYMMETRIC_DECRYPT', 'MAC']),
  labels=dict(type='dict', options=_schema_less),
  next_rotation_time=dict(type='str'),
  rotation_period=dict(type='str'),
)

argument_spec = dict(
    op_type=dict(type='str', options=[
       'create',
       'update',
       'key_op',
       'key_version_op',
       'upload-key',
       'create-sync-job',
       'cancel-sync-job',
       'update-all-versions',
       ], required=True),
    key_id=dict(type='str'),
    version_id=dict(type='str'),
    job_id=dict(type='str'),
    key_op_type=dict(type='str', options=['create-version', 'refresh', 'enable-auto-rotation', 'disable-auto-rotation']),
    key_version_op_type=dict(type='str', options=['refresh', 'enable', 'disable', 'schedule-destroy', 'cancel-schedule-destroy', 'download-public-key']),
    gcp_key_params=dict(type='dict', options=_gcp_key_param),
    key_ring=dict(type='str'),
    labels=dict(type='dict', options=_schema_less),
    next_rotation_time=dict(type='str'),
    rotation_period=dict(type='str'),
    primary_version_id=dict(type='str'),
    version_template_algorithm=dict(type='str', options=[
      'RSA_SIGN_PSS_2048_SHA256',
      'RSA_SIGN_PSS_3072_SHA256',
      'RSA_SIGN_PSS_4096_SHA256',
      'RSA_SIGN_PSS_4096_SHA512',
      'RSA_SIGN_PKCS1_2048_SHA256',
      'RSA_SIGN_PKCS1_3072_SHA256',
      'RSA_SIGN_PKCS1_4096_SHA256',
      'RSA_SIGN_PKCS1_4096_SHA512',
      'RSA_DECRYPT_OAEP_2048_SHA256',
      'RSA_DECRYPT_OAEP_3072_SHA256',
      'RSA_DECRYPT_OAEP_4096_SHA256',
      'RSA_DECRYPT_OAEP_4096_SHA512',
      'EC_SIGN_P256_SHA256',
      'EC_SIGN_P384_SHA384',
      'EC_SIGN_SECP256K1_SHA256',
    ]),
    # create key version
    is_native=dict(type='bool'),
    algorithm=dict(type='str', options=[
      'RSA_SIGN_PSS_2048_SHA256',
      'RSA_SIGN_PSS_3072_SHA256',
      'RSA_SIGN_PSS_4096_SHA256',
      'RSA_SIGN_PSS_4096_SHA512',
      'RSA_SIGN_PKCS1_2048_SHA256',
      'RSA_SIGN_PKCS1_3072_SHA256',
      'RSA_SIGN_PKCS1_4096_SHA256',
      'RSA_SIGN_PKCS1_4096_SHA512',
      'RSA_DECRYPT_OAEP_2048_SHA256',
      'RSA_DECRYPT_OAEP_3072_SHA256',
      'RSA_DECRYPT_OAEP_4096_SHA256',
      'RSA_DECRYPT_OAEP_4096_SHA512',
      'EC_SIGN_P256_SHA256',
      'EC_SIGN_P384_SHA384',
      'EC_SIGN_SECP256K1_SHA256',
      'GOOGLE_SYMMETRIC_ENCRYPTION',
      ]),
    source_key_id=dict(type='str'),
    source_key_tier=dict(type='str', options=['local', 'dsm', 'hsm-luna']),
    # update-all-versions
    operation=dict(type='str', options=['enable', 'disable', 'schedule_destroy', 'cancel_destroy']),
    # enable-auto-rotation
    auto_rotate_algorithm=dict(type='str', options=[
      'RSA_SIGN_PSS_2048_SHA256',
      'RSA_SIGN_PSS_3072_SHA256',
      'RSA_SIGN_PSS_4096_SHA256',
      'RSA_SIGN_PSS_4096_SHA512',
      'RSA_SIGN_PKCS1_2048_SHA256',
      'RSA_SIGN_PKCS1_3072_SHA256',
      'RSA_SIGN_PKCS1_4096_SHA256',
      'RSA_SIGN_PKCS1_4096_SHA512',
      'RSA_DECRYPT_OAEP_2048_SHA256',
      'RSA_DECRYPT_OAEP_3072_SHA256',
      'RSA_DECRYPT_OAEP_4096_SHA256',
      'RSA_DECRYPT_OAEP_4096_SHA512',
      'EC_SIGN_P256_SHA256',
      'EC_SIGN_P384_SHA384',
      'EC_SIGN_SECP256K1_SHA256',
      'GOOGLE_SYMMETRIC_ENCRYPTION',
      'HMAC_SHA256',
      ]),
    auto_rotate_key_source=dict(type='str', options=['native', 'hsm-luna', 'dsm', 'ciphertrust']),
    job_config_id=dict(type='str'),
    auto_rotate_domain_id=dict(type='str'),
    auto_rotate_partition_id=dict(type='str'),
    # create-sync-job
    key_rings=dict(type='list', element='str'),
    synchronize_all=dict(type='bool'),
)

def validate_parameters(cckm_gcp_key_module):
    return True

def setup_module_object():
    module = ThalesCipherTrustModule(
        argument_spec=argument_spec,
        required_if=(
            ['op_type', 'create', ['gcp_key_params', 'key_ring']],
            ['op_type', 'update', ['key_id']],
            ['op_type', 'key_op', ['key_id', 'key_op_type']],
            ['op_type', 'key_version_op', ['version_id', 'key_version_op_type']],
            ['op_type', 'upload-key', ['gcp_key_params', 'key_ring']],
            ['op_type', 'update-all-versions', ['key_id', 'operation']],            
        ),
        mutually_exclusive=[],
        supports_check_mode=True,
    )
    return module

def main():

    global module
    
    module = setup_module_object()
    validate_parameters(
        cckm_gcp_key_module=module,
    )

    result = dict(
        changed=False,
    )

    if module.params.get('op_type') == 'create':
      try:
        response = addCCKMCloudAsset(
          node=module.params.get('localNode'),
          asset_type="key",
          cloud_type="gcp",
          gcp_key_params=module.params.get('gcp_key_params'),
          key_ring=module.params.get('key_ring'),
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
          cloud_type="gcp",
          labels=module.params.get('labels'),
          next_rotation_time=module.params.get('next_rotation_time'),
          primary_version_id=module.params.get('primary_version_id'),
          rotation_period=module.params.get('rotation_period'),
          version_template_algorithm=module.params.get('version_template_algorithm'),
        )
        result['response'] = response
      except CMApiException as api_e:
        if api_e.api_error_code:
          module.fail_json(msg="status code: " + str(api_e.api_error_code) + " message: " + api_e.message)
      except AnsibleCMException as custom_e:
        module.fail_json(msg=custom_e.message)

    elif module.params.get('op_type') == 'key_op':
      if module.params.get('key_op_type') == "create-version":
        try:
          response = performKeyOperation(
            node=module.params.get('localNode'),
            id=module.params.get('key_id'),
            key_op_type=module.params.get('key_op_type'),
            is_native=module.params.get('is_native'),
            algorithm=module.params.get('algorithm'),
            source_key_id=module.params.get('source_key_id'),
            source_key_tier=module.params.get('source_key_tier'),
          )
          result['response'] = response
        except CMApiException as api_e:
          if api_e.api_error_code:
            module.fail_json(msg="status code: " + str(api_e.api_error_code) + " message: " + api_e.message)
        except AnsibleCMException as custom_e:
          module.fail_json(msg=custom_e.message)

      elif module.params.get('key_op_type') == "enable-auto-rotation":
        try:
          response = performKeyOperation(
            node=module.params.get('localNode'),
            id=module.params.get('key_id'),
            key_op_type=module.params.get('key_op_type'),
            auto_rotate_algorithm=module.params.get('auto_rotate_algorithm'),
            auto_rotate_key_source=module.params.get('auto_rotate_key_source'),
            job_config_id=module.params.get('job_config_id'),
            auto_rotate_domain_id=module.params.get('auto_rotate_domain_id'),
            auto_rotate_partition_id=module.params.get('auto_rotate_partition_id'),
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
            id=module.params.get('key_id'),
            key_op_type=module.params.get('key_op_type'),
          )
          result['response'] = response
        except CMApiException as api_e:
          if api_e.api_error_code:
            module.fail_json(msg="status code: " + str(api_e.api_error_code) + " message: " + api_e.message)
        except AnsibleCMException as custom_e:
          module.fail_json(msg=custom_e.message)

    elif module.params.get('op_type') == 'key_version_op':
      try:
        response = performKeyVersionOperation(
          node=module.params.get('localNode'),
          id=module.params.get('key_id'),
          version_id=module.params.get('version_id'),
          key_version_op_type=module.params.get('key_version_op_type'),
        )
        result['response'] = response
      except CMApiException as api_e:
        if api_e.api_error_code:
          module.fail_json(msg="status code: " + str(api_e.api_error_code) + " message: " + api_e.message)
      except AnsibleCMException as custom_e:
        module.fail_json(msg=custom_e.message)

    elif module.params.get('op_type') == 'upload-key':
      try:
        response = uploadKeyGCP(
          node=module.params.get('localNode'),
          gcp_key_params=module.params.get('gcp_key_params'),
          key_ring=module.params.get('key_ring'),
          source_key_id=module.params.get('source_key_id'),
          source_key_tier=module.params.get('source_key_tier'),
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
          cloud_type="gcp",
          key_rings=module.params.get('key_rings'),
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
          cloud_type="gcp",
        )
        result['response'] = response
      except CMApiException as api_e:
        if api_e.api_error_code:
          module.fail_json(msg="status code: " + str(api_e.api_error_code) + " message: " + api_e.message)
      except AnsibleCMException as custom_e:
        module.fail_json(msg=custom_e.message)

    elif module.params.get('op_type') == 'update-all-versions':
      try:
        response = updateAllKeyVersions(
          node=module.params.get('localNode'),
          key_id=module.params.get('key_id'),
          operation=module.params.get('operation'),
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