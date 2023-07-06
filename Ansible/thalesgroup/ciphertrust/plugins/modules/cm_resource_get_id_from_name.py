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
from ansible_collections.thalesgroup.ciphertrust.plugins.module_utils.cm_api import GETIdByQueryParam
from ansible_collections.thalesgroup.ciphertrust.plugins.module_utils.exceptions import CMApiException, AnsibleCMException

DOCUMENTATION = '''
---
module: cm_resource_get_id_from_name
short_description: Get CipherTrust Manager resource ID from resource name
description:
    - This is a Thales CipherTrust Manager module for working with the CipherTrust Manager APIs, more specifically List API with some filter.
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
    query_param:
        description:
            - This is a string type of option that holds the query parameter type to be used to filter the list resources API response
        required: true
        choices:
            - name
            - username
            - email
            - status
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
    query_param_value:
        description:
            - This is a string type of option that will hold the value of filter query parameter
        required: true
        type: str
'''

EXAMPLES = '''
- name: "Get Key ID"
  thalesgroup.ciphertrust.cm_resource_get_id_from_name:
    localNode:
        server_ip: "IP/FQDN of CipherTrust Manager"
        server_private_ip: "Private IP in case that is different from above"
        server_port: 5432
        user: "CipherTrust Manager Username"
        password: "CipherTrust Manager Password"
        verify: false
    query_param: "name"
    query_param_value: "AnsibleKey"
    resource_type: "keys"
'''

RETURN = '''
id:
    description: String with the ID returned by the CipherTrust Manager
    returned: changed or success
    type: string
    sample: 123456789
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
_arr_query_param_choices = [
    'name',
    'username', 
    'email', 
    'status'
]
argument_spec = dict(
    resource_type=dict(type='str', choices=_arr_resource_type_choices, required=True),
    query_param=dict(type='str', choices=_arr_query_param_choices, required=True),
    query_param_value=dict(type='str', required=True),
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
        endpoint='vault/keys2'
        query_id='id'
    elif resource_type == "interfaces":
        endpoint='configs/interfaces'
        query_id='id'
    elif resource_type == "users":
        endpoint='usermgmt/users'
        query_id='user_id'
    elif resource_type == "client-profiles":
        endpoint='data-protection/client-profiles'
        query_id='id'
    elif resource_type == "dpg-policies":
        endpoint='data-protection/dpg-policies'
        query_id='id'
    elif resource_type == "access-policies":
        endpoint='data-protection/access-policies'
        query_id='id'
    elif resource_type == "user-sets":
        endpoint='data-protection/user-sets'
        query_id='id'
    elif resource_type == "character-sets":
        endpoint='data-protection/character-sets'
        query_id='id'
    elif resource_type == "masking-formats":
        endpoint='data-protection/masking-formats'
        query_id='id'
    elif resource_type == "resourceset":
        endpoint='transparent-encryption/resourcesets'
        query_id='id'
    elif resource_type == "signatureset":
        endpoint='transparent-encryption/signaturesets'
        query_id='id'
    elif resource_type == "userset":
        endpoint='transparent-encryption/usersets'
        query_id='id'
    elif resource_type == "processset":
        endpoint='transparent-encryption/processsets'
        query_id='id'
    elif resource_type == "cte-policy":
        endpoint='transparent-encryption/policies'
        query_id='id'
    elif resource_type == "cte-client-group":
        endpoint='transparent-encryption/clientgroups'
        query_id='id'        
    elif resource_type == "cte-client":
        endpoint='transparent-encryption/clients'
        query_id='id'
    elif resource_type == "csigroup":
        endpoint='transparent-encryption/csigroups'
        query_id='id'
    else:
        module.fail_json(msg='resource_type not supported yet')

    try:
        response = GETIdByQueryParam(
            cm_node=module.params.get('localNode'),
            param=module.params.get('query_param'),
            value=module.params.get('query_param_value'),
            cm_api_endpoint=endpoint,
            id=query_id,
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
