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
from ansible_collections.thalesgroup.ciphertrust.plugins.module_utils.regtokens import create, patch
from ansible_collections.thalesgroup.ciphertrust.plugins.module_utils.exceptions import CMApiException, AnsibleCMException

DOCUMENTATION = '''
---
module: cm_regtoken
short_description: Create or update registration token
description:
    - The module is to create or update client registration token
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
    id:
        description: registration token ID to be updated
        type: str
    ca_id:
        description: ID of the trusted Certificate Authority that will be used to sign client certificate during registration process. By default local Certificate Authority will be used to issue certificates.
        type: str
    cert_duration:
        description: Duration in days for which the CipherTrust Manager client's certificate is valid, default (730).
        type: int
        default: 730
    label:
        description: Label is the key value pair. In case of KMIP client registration, Key is KmipClientProfile and in case of PA client registration Key is ClientProfile. Value for the key is the profile name of protectapp/Kmip client profile to be mapped with the token for protectapp/Kmip client registration.
        type: dict
    lifetime:
        description: Duration in minutes/hours/days for which this token can be used for registering CipherTrust Manager clients. No limit by default. For 'x' amount of time, it should formatted as xm for x minutes, xh for hours and xd for days.
        type: str
    max_clients:
        description: Maximum number of clients that can be registered using this registration token. No limit by default.
        type: int
    name_prefix:
        description: Prefix for the client name. For a client registered using this registration token, name_prefix, if specified, client name will be constructed as 'name_prefix{nth client registered using this registation token}', If name_prefix is not specified, CipherTrust Manager server will generate a random name for the client.
        type: str
'''

EXAMPLES = '''
- name: "Create Registration Token"
  thalesgroup.ciphertrust.cm_regtoken:
    localNode:
        server_ip: "IP/FQDN of CipherTrust Manager"
        server_private_ip: "Private IP in case that is different from above"
        server_port: 5432
        user: "CipherTrust Manager Username"
        password: "CipherTrust Manager Password"
        verify: false
    op_type: create
    ca_id: 76c4da32-0953-4c6a-bf77-c5a70314244c
    cert_duration: 730
    label:
      ClientProfile: DefaultClientProfile
    lifetime: 30d
    max_clients: 100
    name_prefix: "ansible_client"
'''

RETURN = '''

'''

_schema_less = dict()

_label = dict(
   ClientProfile=dict(type='str'),
)

argument_spec = dict(
    op_type=dict(type='str', options=['create', 'patch'], required=True),
    id=dict(type='str'),
    ca_id=dict(type='str'),
    cert_duration=dict(type='int'),
    label=dict(type='dict', options=_label),
    lifetime=dict(type='str'),
    max_clients=dict(type='int'),
    name_prefix=dict(type='str'),
)

def validate_parameters(regtoken_module):
    return True

def setup_module_object():
    module = ThalesCipherTrustModule(
        argument_spec=argument_spec,
        required_if=(
            ['op_type', 'patch', ['id']],
        ),
        mutually_exclusive=[],
        supports_check_mode=True,
    )
    return module

def main():

    global module
    
    module = setup_module_object()
    validate_parameters(
        regtoken_module=module,
    )

    result = dict(
        changed=False,
    )

    if module.params.get('op_type') == 'create':
      try:
        response = create(
          node=module.params.get('localNode'),
          ca_id=module.params.get('ca_id'),
          cert_duration=module.params.get('cert_duration'),
          label=module.params.get('label'),
          lifetime=module.params.get('lifetime'),
          max_clients=module.params.get('max_clients'),
          name_prefix=module.params.get('name_prefix'),
        )
        result['response'] = response
      except CMApiException as api_e:
        if api_e.api_error_code:
          module.fail_json(msg="status code: " + str(api_e.api_error_code) + " message: " + api_e.message)
      except AnsibleCMException as custom_e:
        module.fail_json(msg=custom_e.message)

    elif module.params.get('op_type') == 'patch':
      try:
        response = patch(
          node=module.params.get('localNode'),
          id=module.params.get('id'),
          lifetime=module.params.get('lifetime'),
          max_clients=module.params.get('max_clients'),
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