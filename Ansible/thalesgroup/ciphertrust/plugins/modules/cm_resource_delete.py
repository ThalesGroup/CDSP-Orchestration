#!/usr/bin/python
# -*- coding: utf-8 -*-
#
# (c) 2022 Thales Group. All rights reserved.
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
from ansible_collections.thalesgroup.ciphertrust.plugins.module_utils.cm_api import DELETEByNameOrId
from ansible_collections.thalesgroup.ciphertrust.plugins.module_utils.exceptions import CMApiException, AnsibleCMException

DOCUMENTATION = '''
---
module: cm_resource_delete
short_description: Delete CipherTrust Manager resource using ID
description:
    - This is a Thales CipherTrust Manager module for working with the CipherTrust Manager APIs, more specifically delete resource APIs.
version_added: "1.0.0"
author: Anurag Jain, Developer Advocate Thales Group
options:
    localNode:
        description:
            - this holds the connection parameters required to communicate with an instance of CipherTrust Manager (CM)
            - holds IP/FQDN of the server, username, password, and port 
        type: dict
        required: true
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
    key:
        description:
            - This is a string type of option that can have either the name of the ID of the resource to be deleted
        required: true
        type: str
    resource_type:
        description:
            - This is a string type of option that can hold the resource type.
        required: true
        choices:
            - keys
            - protection-policies
            - access-policies
            - user-sets
            - interfaces
            - character-sets
            - users
            - dpg-policies
            - client-profiles
            - masking-formats
        type: str
'''

EXAMPLES = '''
# Delete Resource at CipherTrust Manager
- name: "Delete key on Ciphertrust Manager"
  thalesgroup.ciphertrust.cm_resource_delete:
    localNode: 
        server_ip: "IP/FQDN of CipherTrust Manager"
        server_private_ip: "Private IP in case that is different from above"
        server_port: 5432
        user: "CipherTrust Manager Username"
        password: "CipherTrust Manager Password"
        verify: false
    key: "resource_id"
    resource_type: "keys"
'''

RETURN = '''
message:
    description: String with response
    returned: changed or success
    type: string
    sample: successfully deleted
'''

_arr_resource_type_choices = [
    'keys', 
    'protection-policies', 
    'access-policies', 
    'user-sets', 
    'interfaces', 
    'character-sets', 
    'users', 
    'dpg-policies', 
    'client-profiles', 
    'masking-formats',
    'resourceset',
    'signatureset',
    'userset',
    'processset',
    'cte-policy',
    'cte-client-group',
    'csigroup',
    'cte-client',
]

argument_spec = dict(
    key=dict(type='str', required=True),
    resource_type=dict(type='str', choices=_arr_resource_type_choices, required=True),
)

def validate_parameters(user_module):
    return True

def setup_module_object():
    module = ThalesCipherTrustModule(
        argument_spec=argument_spec,
        required_if=[],
        mutually_exclusive=[],
        supports_check_mode=True,
    )
    return module

def main():
    global module
    
    module = setup_module_object()
    validate_parameters(
        user_module=module,
    )

    result = dict(
        changed=False,
    )

    endpoint = ''
    resource_type=module.params.get('resource_type')
    #Create the API end point based on the resource_type
    if resource_type == "keys":
        endpoint = 'vault/keys2'
    elif resource_type == "interfaces":
        endpoint = 'configs/interfaces'
    elif resource_type == "users":
        endpoint = 'usermgmt/users'
    elif resource_type == "client-profiles":
        endpoint = 'data-protection/client-profiles'
    elif resource_type == "dpg-policies":
        endpoint = 'data-protection/dpg-policies'
    elif resource_type == "access-policies":
        endpoint='data-protection/access-policies'
    elif resource_type == "user-sets":
        endpoint='data-protection/user-sets'
    elif resource_type == "protection-policies":
        endpoint='data-protection/protection-policies'
    elif resource_type == "character-sets":
        endpoint='data-protection/character-sets'
    elif resource_type == "masking-formats":
        endpoint='data-protection/masking-formats'
    elif resource_type == "resourceset":
        endpoint='transparent-encryption/resourcesets'
    elif resource_type == "signatureset":
        endpoint='transparent-encryption/signaturesets'
    elif resource_type == "userset":
        endpoint='transparent-encryption/usersets'
    elif resource_type == "processset":
        endpoint='transparent-encryption/processsets'
    elif resource_type == "cte-policy":
        endpoint='transparent-encryption/policies'
    elif resource_type == "cte-client-group":
        endpoint='transparent-encryption/clientgroups'
    elif resource_type == "csigroup":
        endpoint='transparent-encryption/csigroups'
    else:
        module.fail_json(msg='resource_type not supported yet')

    try:
        response = DELETEByNameOrId(
            key=module.params.get('key'),
            cm_node=module.params.get('localNode'),
            cm_api_endpoint=endpoint
        )
        result['response'] = response
    except CMApiException as api_e:
        if api_e.api_error_code:
          module.fail_json(msg="status code: " + str(api_e.api_error_code) + " message: " + api_e.message)
    except AnsibleCMException as custom_e:
        module.fail_json(msg=custom_e.message)

    module.exit_json(**result)

if __name__ == '__main__':
    main()