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
from ansible_collections.thalesgroup.ciphertrust.plugins.module_utils.cckm_gcp import performGCPWorkspaceEndpointOperation
from ansible_collections.thalesgroup.ciphertrust.plugins.module_utils.cckm_commons import addCCKMCloudAsset, editCCKMCloudAsset
from ansible_collections.thalesgroup.ciphertrust.plugins.module_utils.exceptions import CMApiException, AnsibleCMException

DOCUMENTATION = '''
---
module: cckm_gcp_workspace_cse
short_description: CCKM module for GCP Workspace CSE
description:
    - This is a Thales CipherTrust Manager module for working with the CipherTrust Manager APIs, more specifically with CCKM for GCP Workspace CSE
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
        choices: [create_issuer, create_endpoint, update_endpoint, endpoint_op]
        required: true
        type: str
    endpoint_id:
        description: ID of KACLS endpoint for Google Workspace CSE to be acted upon
        type: str
    endpoint_op_type:
        description: Operation to be performed on KACLS endpoint for Google Workspace CSE
        choices: [rotate-key, disable, enable, archive, recover, wrapprivatekey]
        type: str
    name:
        description: Unique name for the KACLS issuer.
        type: str
    dryRun:
        description: Set true to skip persisting the issuer. All the same validation checks, auto-discovery, and connectivity checks will be performed, and the server will return the same status codes and response body. It can be used to test creating the issuer without modifying the server state. Default value is set to False.
        type: bool
    iss:
        description: Issuer claim of IDP JWT, e.g. https://dev-abc.auth.com
        type: str
    jwksURL:
        description: JWKS url for IDP, e.g. https://dev-abc.auth.com/.well-known/jwks.json
        type: str
    meta:
        description: Additional information associated with the issuer.
        type: str
    openidConfigurationURL:
        description: IDP configuration URL, e.g. https://dev-abc.auth.com/.well-known/openid-configuration
        type: str
    authenticationAud:
        description: List of supported audience for authentication JWT.
        type: list
    endpoint_url_hostname:
        description: Endpoint base url hostname for KACLS endpoint.
        type: str
    authorizationAud:
        description: List of supported audience for authorization JWT.
        type: list
    cors:
        description: List of CORS (Cross-Origin Resource Sharing) to support.
        type: list
    issuer:
        description: List of trusted issuer IDs to use with this endpoint. These are managed through the /GoogleWorkspaceCSE/issuers URL. If not specified, all the issuers will be trusted.
        type: list
    private_key:
        description: PEM encoded PKCS#1 or PKCS#8 (unencrypted) RSA Private Key.
        type: str
    perimeter_id:
        description: The perimeter ID to encrypt with the key
        type: str
'''

EXAMPLES = '''
- name: "Create GCP Workspace CSE"
  thalesgroup.ciphertrust.cckm_gcp_workspace_cse:
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

argument_spec = dict(
    op_type=dict(type='str', options=[
       'create_issuer',
       'create_endpoint',
       'update_endpoint',
       'endpoint_op',
       ], required=True),
    endpoint_id=dict(type='str'),
    endpoint_op_type=dict(type='str', options=[
       'rotate-key',
       'disable',
       'enable',
       'archive',
       'recover',
       'wrapprivatekey',
       ]),
    name=dict(type='str'),
    dryRun=dict(type='bool'),
    iss=dict(type='str'),
    jwksURL=dict(type='str'),
    meta=dict(type='dict', options=_schema_less),
    openidConfigurationURL=dict(type='str'),
    authenticationAud=dict(type='list', element='str'),
    endpoint_url_hostname=dict(type='str'),
    authorizationAud=dict(type='list', element='str'),
    cors=dict(type='list', element='str'),
    issuer=dict(type='list', element='str'),
    # endpoint_op_type = wrapprivatekey
    private_key=dict(type='str'),
    perimeter_id=dict(type='str'),
)

def validate_parameters(cckm_gcp_workspace_module):
    return True

def setup_module_object():
    module = ThalesCipherTrustModule(
        argument_spec=argument_spec,
        required_if=(
            ['op_type', 'create_issuer', ['name']],
            ['op_type', 'create_endpoint', ['authenticationAud', 'endpoint_url_hostname', 'name']],
            ['op_type', 'update_endpoint', ['endpoint_id']],
            ['op_type', 'endpoint_op', ['endpoint_id', 'endpoint_op_type']],          
        ),
        mutually_exclusive=[],
        supports_check_mode=True,
    )
    return module

def main():

    global module
    
    module = setup_module_object()
    validate_parameters(
        cckm_gcp_workspace_module=module,
    )

    result = dict(
        changed=False,
    )

    if module.params.get('op_type') == 'create_issuer':
      try:
        response = addCCKMCloudAsset(
          node=module.params.get('localNode'),
          asset_type="workspace",
          cloud_type="gcp",
          name=module.params.get('name'),
          dryRun=module.params.get('dryRun'),
          iss=module.params.get('iss'),
          jwksURL=module.params.get('jwksURL'),
          meta=module.params.get('meta'),
          openidConfigurationURL=module.params.get('openidConfigurationURL'),
        )
        result['response'] = response
      except CMApiException as api_e:
        if api_e.api_error_code:
          module.fail_json(msg="status code: " + str(api_e.api_error_code) + " message: " + api_e.message)
      except AnsibleCMException as custom_e:
        module.fail_json(msg=custom_e.message)

    elif module.params.get('op_type') == 'create_endpoint':
      try:
        response = addCCKMCloudAsset(
          node=module.params.get('localNode'),
          asset_type="workspace_endpoint",
          cloud_type="gcp",
          authenticationAud=module.params.get('authenticationAud'),
          endpoint_url_hostname=module.params.get('endpoint_url_hostname'),
          name=module.params.get('name'),
          authorizationAud=module.params.get('authorizationAud'),
          cors=module.params.get('cors'),
          issuer=module.params.get('issuer'),
          meta=module.params.get('meta'),
        )
        result['response'] = response
      except CMApiException as api_e:
        if api_e.api_error_code:
          module.fail_json(msg="status code: " + str(api_e.api_error_code) + " message: " + api_e.message)
      except AnsibleCMException as custom_e:
        module.fail_json(msg=custom_e.message)

    elif module.params.get('op_type') == 'update_endpoint':
      try:
        response = editCCKMCloudAsset(
          node=module.params.get('localNode'),
          id=module.params.get('endpoint_id'),
          asset_type="workspace_endpoint",
          cloud_type="gcp",
          authenticationAud=module.params.get('authenticationAud'),
          endpoint_url_hostname=module.params.get('endpoint_url_hostname'),
          authorizationAud=module.params.get('authorizationAud'),
          cors=module.params.get('cors'),
          issuer=module.params.get('issuer'),
        )
        result['response'] = response
      except CMApiException as api_e:
        if api_e.api_error_code:
          module.fail_json(msg="status code: " + str(api_e.api_error_code) + " message: " + api_e.message)
      except AnsibleCMException as custom_e:
        module.fail_json(msg=custom_e.message)

    elif module.params.get('op_type') == 'endpoint_op':
      if module.params.get('endpoint_op_type') == "wrapprivatekey":
        try:
          response = performGCPWorkspaceEndpointOperation(
            node=module.params.get('localNode'),
            id=module.params.get('endpoint_id'),
            endpoint_op_type=module.params.get('endpoint_op_type'),
            private_key=module.params.get('private_key'),
            perimeter_id=module.params.get('perimeter_id'),
          )
          result['response'] = response
        except CMApiException as api_e:
          if api_e.api_error_code:
            module.fail_json(msg="status code: " + str(api_e.api_error_code) + " message: " + api_e.message)
        except AnsibleCMException as custom_e:
          module.fail_json(msg=custom_e.message)

      else:
        try:
          response = performGCPWorkspaceEndpointOperation(
            node=module.params.get('localNode'),
            id=module.params.get('endpoint_id'),
            endpoint_op_type=module.params.get('endpoint_op_type'),
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