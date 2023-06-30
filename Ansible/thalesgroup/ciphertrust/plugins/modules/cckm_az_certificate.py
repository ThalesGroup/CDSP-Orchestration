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
from ansible_collections.thalesgroup.ciphertrust.plugins.module_utils.cckm_azure import performAZCertificateOperation, importCertToAZ
from ansible_collections.thalesgroup.ciphertrust.plugins.module_utils.cckm_commons import addCCKMCloudAsset, editCCKMCloudAsset, createSyncJob, cancelSyncJob
from ansible_collections.thalesgroup.ciphertrust.plugins.module_utils.exceptions import CMApiException, AnsibleCMException

DOCUMENTATION = '''
---
module: cckm_az_certificate
short_description: CCKM module for Azure Certificates
description:
    - This is a Thales CipherTrust Manager module for working with the CipherTrust Manager APIs, more specifically with CCKM for Azure Certificates API
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
        choices: [create, update, certificate_op, create-sync-job, cancel-sync-job, import]
        required: true
        type: str
    certificate_id:
        description: Azure Certificate ID to be acted upon
        type: str
    job_id:
        description: Sync Job ID to be updated
        type: str
    certificate_op_type:
        description: Action to be performed on Certificate
        choices: [soft-delete, hard-delete, restore, recover]
        type: str
    azure_param:
        description: Azure certificate parameters.
        type: dict
    cert_name:
        description: Name for the certificate on Azure. Certificate names can only contain alphanumeric characters and hyphens (-).
        type: str
    key_vault:
        description: ID or name of the Azure vault where the certificate will be created.
        type: str
    tags:
        description: Application specific metadata in the form of key-value pair.
        type: dict
    attributes:
        description: Secret attributes to be updated.
        type: dict
    key_vaults:
        description: Name or ID of key vaults from which Azure secrets will be synchronized. synchronize_all and key_vaults are mutually exclusive. Specify either the synchronize_all or key_vaults.
        type: list
    synchronize_all:
        description: Set true to synchronize all certificates from all vaults. synchronize_all and key_vaults are mutually exclusive. Specify either the synchronize_all or key_vaults.
        type: bool
    caid:
        description: ID or name of the certificate authority.
        type: str
    private_key_pem:
        description: Private key in PEM format.
        type: str
    source_cert_identifier:
        description: ID of the certificate that will be imported into the Azure vault.
        type: str
    password:
        description: Password of the private key, if encrypted.
        type: str
'''

EXAMPLES = '''
- name: "Create Azure Certificate"
  thalesgroup.ciphertrust.cckm_az_certificate:
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

_azure_param_policy_issuer = dict(
  name=dict(type='str'),
  cert_transparency=dict(type='bool'),
  cty=dict(type='str'),
)

_azure_param_policy_key_prop = dict(
  kty=dict(type='str', options=['EC', 'EC-HSM', 'RSA', 'RSA-HSM']),
  crv=dict(type='str', options=['P-256', 'P-384', 'P-521', 'SECP256K1']),
  exportable=dict(type='bool'),
  key_size=dict(type='int', options=[2048, 3072, 4096]),
  reuse_key=dict(type='bool'),
)

_azure_param_policy_x509_prop_san = dict(
  dns_names=dict(type='list', element='str'),
  emails=dict(type='list', element='str'),
  upns=dict(type='list', element='str'),
)

_azure_param_policy_x509_prop = dict(
  subject=dict(type='str'),
  ekus=dict(type='list', element='str'),
  key_usage=dict(type='list', element='str'),
  sans=dict(type='list', element='dict', options=_azure_param_policy_x509_prop_san),
  validity_months=dict(type='int'),
)

_azure_param_policy_lifetime_action_action = dict(
  action_type=dict(type='str', options=['AutoRenew', 'EmailContacts']),
)

_azure_param_policy_lifetime_action_trigger = dict(
  days_before_expiry=dict(type='int'),
  lifetime_percentage=dict(type='int'),
)

_azure_param_policy_lifetime_action = dict(
  action=dict(type='dict', options=_azure_param_policy_lifetime_action_action),
  trigger=dict(type='dict', options=_azure_param_policy_lifetime_action_trigger),
)

_azure_param_policy_secret_prop = dict(
  contentType=dict(type='str', options=['application/x-pkcs12', 'application/x-pem-file']),
)

_azure_param_policy = dict(
  issuer=dict(type='dict', options=_azure_param_policy_issuer),
  key_props=dict(type='dict', options=_azure_param_policy_key_prop),
  x509_props=dict(type='dict', options=_azure_param_policy_x509_prop),
  attributes=dict(type='dict', options=_schema_less),
  lifetime_actions=dict(type='list', element='dict', options=_azure_param_policy_lifetime_action),
  secret_props=dict(type='dict', options=_azure_param_policy_secret_prop),
)

_azure_param = dict(
  policy=dict(type='dict', options=_azure_param_policy),
  tags=dict(type='dict', options=_schema_less),
)

_azure_cert_update_attribute = dict(
  enabled=dict(type='bool'),
)

argument_spec = dict(
    op_type=dict(type='str', options=[
       'create', 
       'update',
       'certificate_op',
       'create-sync-job',
       'cancel-sync-job',
       'import',
       ], required=True),
    certificate_id=dict(type='str'),
    job_id=dict(type='str'),
    certificate_op_type=dict(type='str', options=['soft-delete', 'hard-delete', 'restore', 'recover']),
    azure_param=dict(type='dict', options=_azure_param),
    cert_name=dict(type='str'),
    key_vault=dict(type='str'),
    tags=dict(type='dict', options=_schema_less),
    attributes=dict(type='dict', options=_azure_cert_update_attribute),
    # op_type = create-sync-job
    key_vaults=dict(type='list', element='str'),
    synchronize_all=dict(type='bool'),
    # op_type = import
    caid=dict(type='str'),
    private_key_pem=dict(type='str'),
    source_cert_identifier=dict(type='str'),
    password=dict(type='str'),
)

def validate_parameters(cckm_az_certificate_module):
    return True

def setup_module_object():
    module = ThalesCipherTrustModule(
        argument_spec=argument_spec,
        required_if=(
            ['op_type', 'create', ['azure_param', 'cert_name', 'key_vault']],
            ['op_type', 'update', ['certificate_id']],
            ['op_type', 'certificate_op', ['certificate_id', 'certificate_op_type']],
            ['op_type', 'cancel-sync-job', ['job_id']],
            ['op_type', 'import', ['caid', 'cert_name', 'key_vault', 'private_key_pem', 'source_cert_identifier']],
        ),
        mutually_exclusive=[],
        supports_check_mode=True,
    )
    return module

def main():

    global module
    
    module = setup_module_object()
    validate_parameters(
        cckm_az_certificate_module=module,
    )

    result = dict(
        changed=False,
    )

    if module.params.get('op_type') == 'create':
      try:
        response = addCCKMCloudAsset(
          node=module.params.get('localNode'),
          asset_type="certificate",
          cloud_type="az",
          azure_param=module.params.get('azure_param'),
          cert_name=module.params.get('cert_name'),
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
          id=module.params.get('certificate_id'),
          asset_type="certificate",
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

    elif module.params.get('op_type') == 'certificate_op':
      if module.params.get('certificate_op_type') == 'restore':
        try:
          response = performAZCertificateOperation(
            node=module.params.get('localNode'),
            id=module.params.get('certificate_id'),
            certificate_op_type=module.params.get('certificate_op_type'),
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
          response = performAZCertificateOperation(
            node=module.params.get('localNode'),
            id=module.params.get('certificate_id'),
            certificate_op_type=module.params.get('certificate_op_type'),
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
          asset_type="certificate",
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
          asset_type="certificate",
          cloud_type="az",
        )
        result['response'] = response
      except CMApiException as api_e:
        if api_e.api_error_code:
          module.fail_json(msg="status code: " + str(api_e.api_error_code) + " message: " + api_e.message)
      except AnsibleCMException as custom_e:
        module.fail_json(msg=custom_e.message)

    elif module.params.get('op_type') == 'import':
      try:
        response = importCertToAZ(
          node=module.params.get('localNode'),
          caid=module.params.get('caid'),
          cert_name=module.params.get('cert_name'),
          key_vault=module.params.get('key_vault'),
          private_key_pem=module.params.get('private_key_pem'),
          source_cert_identifier=module.params.get('source_cert_identifier'),
          azure_param=module.params.get('azure_param'),
          password=module.params.get('password'),
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