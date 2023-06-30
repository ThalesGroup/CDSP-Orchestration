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
from ansible_collections.thalesgroup.ciphertrust.plugins.module_utils.connection_management import createConnection, patchConnection
from ansible_collections.thalesgroup.ciphertrust.plugins.module_utils.exceptions import CMApiException, AnsibleCMException

DOCUMENTATION = '''
---
module: connection_manager_azure
short_description: Manage connections to the Azure cloud
description:
    - This is a Thales CipherTrust Manager module for working with the CipherTrust Manager APIs, more specifically with Connection Manager API for Azure
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
    connection_id:
        description: Unique ID of the connection to be updated
        default: none
        type: str
    name:
        description: Unique connection name
        required: true
        default: none
        type: str
    description:
        description: Description about the connection
        required: false
        default: none
        type: str
    meta:
        description: Optional end-user or service data stored with the connection
        required: false
        type: dict
    products:
        description: Array of the CipherTrust products associated with the connection.
        required: false
        default: none
        type: list
        element: str
    client_id:
        description: Unique Identifier (client ID) for the Azure application
        default: none
        type: str
    tenant_id:
        description: Tenant ID of the Azure application
        default: none
        type: str
    active_directory_endpoint:
        description: Azure stack active directory authority URL
        default: none
        type: str
    azure_stack_connection_type:
        description: Azure stack connection type
        default: none
        type: str
    azure_stack_server_cert:
        description: Azure stack server certificate
        default: none
        type: str
    cert_duration:
        description: Duration in days for which the azure certificate is valid, default (730 i.e. 2 Years)
        default: 730
        type: int
    certificate:
        description: User has the option to upload external certificate for Azure Cloud connection. This option cannot be used with option is_certificate_used and client_secret.User first has to generate a new Certificate Signing Request (CSR) in POST /v1/connectionmgmt/connections/csr. The generated CSR can be signed with any internal or external CA. The Certificate must have an RSA key strength of 2048 or 4096. User can also update the new external certificate in the existing connection in Update (PATCH) API call. Any unused certificate will automatically deleted in 24 hours.
        default: none
        type: str
    client_secret:
        description: Secret key for the Azure application. Required in Azure Stack connection.
        default: none
        type: str
    cloud_name:
        description: Name of the cloud
        default: none
        type: str
    is_certificate_used:
        description: User has the option to choose the Certificate Authentication method instead of Client Secret for Azure Cloud connection. In order to use the Certificate, set it to true. Once the connection is created, in the response user will get a certificate. By default, the certificate is valid for 2 Years. User can update the certificate in the existing connection by setting it to true in Update (PATCH) API call.
        type: bool
    key_vault_dns_suffix:
        description: Azure stack key vault dns suffix
        default: none
        type: str
    management_url:
        description: Azure stack management URL
        default: none
        type: str
    resource_manager_url:
        description: Azure stack resource manager URL
        default: none
        type: str
    vault_resource_url:
        description: Azure stack vault service resource URL
        default: none
        type: str
'''

EXAMPLES = '''
- name: "Create Azure Connection"
  thalesgroup.ciphertrust.connection_manager_azure:
    localNode:
        server_ip: "IP/FQDN of CipherTrust Manager"
        server_private_ip: "Private IP in case that is different from above"
        server_port: 5432
        user: "CipherTrust Manager Username"
        password: "CipherTrust Manager Password"
        verify: false
    op_type: create
    name: azure-connection
    products:
      - cckm
    client_secret: 3bf0dbe6-a2c7-431d-9a6f-4843b74c71285nfjdu2
    cloud_name: AzureCloud
    client_id: 3bf0dbe6-a2c7-431d-9a6f-4843b74c7e12
    tenant_id: 3bf0dbe6-a2c7-431d-9a6f-4843b74c71285nfjdu2

- name: "Update Azure Connection"
  thalesgroup.ciphertrust.connection_manager_azure:
    localNode:
        server_ip: "IP/FQDN of CipherTrust Manager"
        server_private_ip: "Private IP in case that is different from above"
        server_port: 5432
        user: "CipherTrust Manager Username"
        password: "CipherTrust Manager Password"
        verify: false
    op_type: patch
'''

RETURN = '''

'''
_schema_less = dict()

argument_spec = dict(
    op_type=dict(type='str', options=['create', 'patch'], required=True),
    client_id=dict(type='str', required=True),
    connection_id=dict(type='str', required=False),
    name=dict(type='str'),
    tenant_id=dict(type='str'),
    active_directory_endpoint=dict(type='str'),
    azure_stack_connection_type=dict(type='str', options=['AAD', 'ADFS']),
    azure_stack_server_cert=dict(type='str'),
    cert_duration=dict(type='int', default=730),
    certificate=dict(type='str'),
    client_secret=dict(type='str'),
    cloud_name=dict(type='str', options=['AzureCloud', 'AzureChinaCloud', 'AzureUSGovernment', 'AzureStack']),
    description=dict(type='str'),
    is_certificate_used=dict(type='bool'),
    key_vault_dns_suffix=dict(type='str'),
    management_url=dict(type='str'),
    meta=dict(type='dict', options=_schema_less),
    products=dict(type='list', element='str'),
    resource_manager_url=dict(type='str'),
    vault_resource_url=dict(type='str'),
)

def validate_parameters(domain_module):
    return True

def setup_module_object():
    module = ThalesCipherTrustModule(
        argument_spec=argument_spec,
        required_if=(
            ['op_type', 'patch', ['connection_id']],
            ['op_type', 'create', ['name', 'client_id', 'tenant_id']],
        ),
        mutually_exclusive=[],
        supports_check_mode=True,
    )
    return module

def main():

    global module
    
    module = setup_module_object()
    validate_parameters(
        domain_module=module,
    )

    result = dict(
        changed=False,
    )

    if module.params.get('op_type') == 'create':
      try:
        response = createConnection(
          node=module.params.get('localNode'),
          connection_type='azure',
          client_id=module.params.get('client_id'),
          name=module.params.get('name'),
          tenant_id=module.params.get('tenant_id'),
          active_directory_endpoint=module.params.get('active_directory_endpoint'),
          azure_stack_connection_type=module.params.get('azure_stack_connection_type'),
          azure_stack_server_cert=module.params.get('azure_stack_server_cert'),
          cert_duration=module.params.get('cert_duration'),
          certificate=module.params.get('certificate'),
          client_secret=module.params.get('client_secret'),
          cloud_name=module.params.get('cloud_name'),
          description=module.params.get('description'),
          is_certificate_used=module.params.get('is_certificate_used'),
          key_vault_dns_suffix=module.params.get('key_vault_dns_suffix'),
          management_url=module.params.get('management_url'),
          meta=module.params.get('meta'),
          products=module.params.get('products'),
          resource_manager_url=module.params.get('resource_manager_url'),
          vault_resource_url=module.params.get('vault_resource_url'),
        )
        result['response'] = response
      except CMApiException as api_e:
        if api_e.api_error_code:
          module.fail_json(msg="status code: " + str(api_e.api_error_code) + " message: " + api_e.message)
      except AnsibleCMException as custom_e:
        module.fail_json(msg=custom_e.message)

    elif module.params.get('op_type') == 'patch':
      try:
        response = patchConnection(
          node=module.params.get('localNode'),
          connection_type='azure',
          connection_id=module.params.get('connection_id'),
          client_id=module.params.get('client_id'),
          tenant_id=module.params.get('tenant_id'),
          active_directory_endpoint=module.params.get('active_directory_endpoint'),
          azure_stack_connection_type=module.params.get('azure_stack_connection_type'),
          azure_stack_server_cert=module.params.get('azure_stack_server_cert'),
          cert_duration=module.params.get('cert_duration'),
          certificate=module.params.get('certificate'),
          client_secret=module.params.get('client_secret'),
          cloud_name=module.params.get('cloud_name'),
          description=module.params.get('description'),
          is_certificate_used=module.params.get('is_certificate_used'),
          key_vault_dns_suffix=module.params.get('key_vault_dns_suffix'),
          management_url=module.params.get('management_url'),
          meta=module.params.get('meta'),
          products=module.params.get('products'),
          resource_manager_url=module.params.get('resource_manager_url'),
          vault_resource_url=module.params.get('vault_resource_url'),
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