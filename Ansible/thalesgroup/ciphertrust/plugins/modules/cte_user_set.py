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
from ansible_collections.thalesgroup.ciphertrust.plugins.module_utils.cte import createUserSet, updateUserSet, addUserToSet, updateUserInSetByIndex, deleteUserInSetByIndex
from ansible_collections.thalesgroup.ciphertrust.plugins.module_utils.exceptions import CMApiException, AnsibleCMException

DOCUMENTATION = '''
---
module: cte_user_set
short_description: Create and manage CTE user-sets
description:
    - Create and edit CTE User set or add, edit, or remove a user to or from the user set
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
      choices: [create, patch, add_user, patch_user, delete_user]
      required: true
      type: str
    id:
      description: Identifier of the CTE CSI Storage Group to be patched
      type: str
    userIndex:
      description:
        - Identifier of the CTE User within UserSet to be patched or deleted
      type: str
    name:
      description: Name of the user set
      type: str
    description
      description: Description of the user set
      type: str
    users
      description: List of users to be added to the user set
      type: list
    gid
      description: Group id of the user which shall be added in user-set
      type: int
    gname
      description: Group name of the user which shall be added in user-set
      type: str
    os_domain
      description: OS domain name in case of windows environment
      type: str
    uid
      description: User id of the user which shall be added in user-set
      type: int
    uname
      description: Name of the user which shall be added in user-set
      type: str
'''

EXAMPLES = '''
- name: "Create CTE Userset"
  thalesgroup.ciphertrust.cte_user_set:
    localNode:
        server_ip: "IP/FQDN of CipherTrust Manager"
        server_private_ip: "Private IP in case that is different from above"
        server_port: 5432
        user: "CipherTrust Manager Username"
        password: "CipherTrust Manager Password"
        verify: false
    op_type: create
    name: UserSet1
    description: "Using Ansible"
    users:
      - uname: root1234
        uid: 1000
        gname: rootGroup
        gid: 1000
      - uname: test1234
        uid: 1234
        gname: testGroup
        gid: 1234
  register: userset

- name: "Add user to UserSet"
  thalesgroup.ciphertrust.cte_user_set:
    localNode:
        server_ip: "IP/FQDN of CipherTrust Manager"
        server_private_ip: "Private IP in case that is different from above"
        server_port: 5432
        user: "CipherTrust Manager Username"
        password: "CipherTrust Manager Password"
        verify: false
    op_type: add_user
    id: "{{ userset['response']['id'] }}"
    users:
      - uname: root0001
        uid: 1001
        gname: rootGroup
        gid: 1000
'''

RETURN = '''

'''

_user = dict(
  gid=dict(type='int'),
  gname=dict(type='str'),
  os_domain=dict(type='str'),
  uid=dict(type='int'),
  uname=dict(type='str'),
)

argument_spec = dict(
    op_type=dict(type='str', options=[
      'create', 
      'patch', 
      'add_user', 
      'patch_user',
      'delete_user',
    ], required=True),
    id=dict(type='str'),
    userIndex=dict(type='int'),
    name=dict(type='str'),
    description=dict(type='str'),
    users=dict(type='list', element='dict', options=_user),
    gid=dict(type='int'),
    gname=dict(type='str'),
    os_domain=dict(type='str'),
    uid=dict(type='int'),
    uname=dict(type='str'),
)

def validate_parameters(cte_user_set_module):
    return True

def setup_module_object():
    module = ThalesCipherTrustModule(
        argument_spec=argument_spec,
        required_if=(
            ['op_type', 'create', ['name']],
            ['op_type', 'patch', ['id']],
            ['op_type', 'add_user', ['id']],
            ['op_type', 'patch_user', ['id', 'userIndex']],
            ['op_type', 'delete_user', ['id', 'userIndex']],            
        ),
        mutually_exclusive=[],
        supports_check_mode=True,
    )
    return module

def main():

    global module
    
    module = setup_module_object()
    validate_parameters(
        cte_user_set_module=module,
    )

    result = dict(
        changed=False,
    )

    if module.params.get('op_type') == 'create':
      try:
        response = createUserSet(
          node=module.params.get('localNode'),
          name=module.params.get('name'),
          description=module.params.get('description'),
          users=module.params.get('users'),
        )
        result['response'] = response
      except CMApiException as api_e:
        if api_e.api_error_code:
          module.fail_json(msg="status code: " + str(api_e.api_error_code) + " message: " + api_e.message)
      except AnsibleCMException as custom_e:
        module.fail_json(msg=custom_e.message)

    elif module.params.get('op_type') == 'patch':
      try:
        response = updateUserSet(
          node=module.params.get('localNode'),
          id=module.params.get('id'),
          description=module.params.get('description'),
          users=module.params.get('users'),
        )
        result['response'] = response
      except CMApiException as api_e:
        if api_e.api_error_code:
          module.fail_json(msg="status code: " + str(api_e.api_error_code) + " message: " + api_e.message)
      except AnsibleCMException as custom_e:
        module.fail_json(msg=custom_e.message)

    elif module.params.get('op_type') == 'add_user':
      try:
        response = addUserToSet(
          node=module.params.get('localNode'),
          id=module.params.get('id'),
          users=module.params.get('users'),
        )
        result['response'] = response
      except CMApiException as api_e:
        if api_e.api_error_code:
          module.fail_json(msg="status code: " + str(api_e.api_error_code) + " message: " + api_e.message)
      except AnsibleCMException as custom_e:
        module.fail_json(msg=custom_e.message)

    elif module.params.get('op_type') == 'patch_user':
      try:
        response = updateUserInSetByIndex(
          node=module.params.get('localNode'),
          id=module.params.get('id'),
          userIndex=str(module.params.get('userIndex')),
          gid=module.params.get('gid'),
          gname=module.params.get('gname'),
          os_domain=module.params.get('os_domain'),
          uid=module.params.get('uid'),
          uname=module.params.get('uname'),
        )
        result['response'] = response
      except CMApiException as api_e:
        if api_e.api_error_code:
          module.fail_json(msg="status code: " + str(api_e.api_error_code) + " message: " + api_e.message)
      except AnsibleCMException as custom_e:
        module.fail_json(msg=custom_e.message)

    elif module.params.get('op_type') == 'delete_user':
      try:
        response = deleteUserInSetByIndex(
          node=module.params.get('localNode'),
          id=module.params.get('id'),
          userIndex=str(module.params.get('userIndex')),
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