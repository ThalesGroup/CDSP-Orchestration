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
from ansible_collections.thalesgroup.ciphertrust.plugins.module_utils.cckm_sfdc import updateSFDCOrgACLs
from ansible_collections.thalesgroup.ciphertrust.plugins.module_utils.cckm_commons import addCCKMCloudAsset, editCCKMCloudAsset, createSyncJob, cancelSyncJob
from ansible_collections.thalesgroup.ciphertrust.plugins.module_utils.exceptions import CMApiException, AnsibleCMException

DOCUMENTATION = '''
---
module: cckm_sfdc_secret
short_description: CCKM module for SFDC Secrets
description:
    - This is a Thales CipherTrust Manager module for working with the CipherTrust Manager APIs, more specifically with CCKM for SFDC Cloud Certificates and Tenant Secrets
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
        choices: [create, update_acls, add_cache_only_key_endpoint, update_cache_only_key_endpoint]
        required: true
        type: str
    sfdc_org_id:
        description: ID of the SFDC organization to be added
        type: str
    endpoint_id:
        description: ID of the SFDC cache only key endpoint to be updated
        type: str
    connection:
        description: Name or ID of the SFDC connection
        type: str
    org_id:
        description: ID of the SFDC organization to be updated
        type: str
    acls:
        description: acls
        type: list
    name:
        description: name for endpoint
        type: str
    organization_id:
        description: SFDC Organization ID to which this endpoint should belong to
        type: str
    password_authentication:
        description: endpoint password Authentication details
        type: dict
    url_hostname:
        description: Base hostname of url
        type: str
'''

EXAMPLES = '''
- name: "Create SFDC Cloud Certificate"
  thalesgroup.ciphertrust.cckm_sfdc_secret:
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
argument_spec = dict(
    op_type=dict(type='str', options=[
       'create_cert',
       'create_key',
       'update_key',
       'key_op',
       'create_sync_job',
       'cancel_sync_job',
       'upload_cache_only_key',
       'upload_key',
       ], required=True),
    key_id=dict(type='str'),
    job_id=dict(type='str'),
    key_op_type=dict(type='str', options=[
       'destroy',
       'import',
       'activate',
       'delete-backup',
       ]),
    secret_type=dict(type='str', options=[
       'key',
       'certificate',
       ]),
    name=dict(type='str'),
    organization_id=dict(type='str'),
    organization_ids=dict(type='list', element='str'),
    synchronize_all=dict(type='bool'),
    type=dict(type='str', options=[
       'Data',
       'EventBus',
       'SearchIndex',
       'DeterministicData',
       'Analytics',
       ]),
    sfdc_named_credential_id=dict(type='str'),
    source_key_identifier=dict(type='str'),
    source_key_tier=dict(type='str', options=['local', 'dsm', 'hsm-luna']),
    certificate_id=dict(type='str'),
    key_derivation_mode=dict(type='str', options=['NONE', 'PBKDF2']),
)

def validate_parameters(cckm_sfdc_secret_module):
    return True

def setup_module_object():
    module = ThalesCipherTrustModule(
        argument_spec=argument_spec,
        required_if=(
            ['op_type', 'create_cert', ['name', 'organization_id']],
            ['op_type', 'create_key', ['organization_id', 'type']],
            ['op_type', 'update_key', ['key_id']],
            ['op_type', 'key_op', ['key_id']],
        ),
        mutually_exclusive=[],
        supports_check_mode=True,
    )
    return module

def main():

    global module
    
    module = setup_module_object()
    validate_parameters(
        cckm_sfdc_secret_module=module,
    )

    result = dict(
        changed=False,
    )

    if module.params.get('op_type') == 'create':
      try:
        response = addCCKMCloudAsset(
          node=module.params.get('localNode'),
          asset_type="org",
          cloud_type="sfdc",
          sfdc_org_id=module.params.get('sfdc_org_id'),
          connection=module.params.get('connection'),
        )
        result['response'] = response
      except CMApiException as api_e:
        if api_e.api_error_code:
          module.fail_json(msg="status code: " + str(api_e.api_error_code) + " message: " + api_e.message)
      except AnsibleCMException as custom_e:
        module.fail_json(msg=custom_e.message)

    elif module.params.get('op_type') == 'update_acls':
      try:
        response = updateSFDCOrgACLs(
          node=module.params.get('localNode'),
          id=module.params.get('org_id'),
          acls=module.params.get('acls'),
        )
        result['response'] = response
      except CMApiException as api_e:
        if api_e.api_error_code:
          module.fail_json(msg="status code: " + str(api_e.api_error_code) + " message: " + api_e.message)
      except AnsibleCMException as custom_e:
        module.fail_json(msg=custom_e.message)

    elif module.params.get('op_type') == 'add_cache_only_key_endpoint':
      try:
        response = addCCKMCloudAsset(
          node=module.params.get('localNode'),
          asset_type="cache_only_key_endpoint",
          cloud_type="sfdc",
          name=module.params.get('name'),
          organization_id=module.params.get('organization_id'),
          password_authentication=module.params.get('password_authentication'),
          url_hostname=module.params.get('url_hostname'),
        )
        result['response'] = response
      except CMApiException as api_e:
        if api_e.api_error_code:
          module.fail_json(msg="status code: " + str(api_e.api_error_code) + " message: " + api_e.message)
      except AnsibleCMException as custom_e:
        module.fail_json(msg=custom_e.message)

    elif module.params.get('op_type') == 'update_cache_only_key_endpoint':
      try:
        response = editCCKMCloudAsset(
          node=module.params.get('localNode'),
          id=module.params.get('endpoint_id'),
          asset_type="cache_only_key_endpoint",
          cloud_type="sfdc",
          password_authentication=module.params.get('password_authentication'),
          url_hostname=module.params.get('url_hostname'),
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