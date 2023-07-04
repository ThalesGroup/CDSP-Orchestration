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
from ansible_collections.thalesgroup.ciphertrust.plugins.module_utils.cte import createProcessSet, updateProcessSet, addProcessToSet, updateProcessInSetByIndex, deleteProcessInSetByIndex
from ansible_collections.thalesgroup.ciphertrust.plugins.module_utils.exceptions import CMApiException, AnsibleCMException

DOCUMENTATION = '''
---
module: cte_process_set
short_description: Create and manage CTE process-sets
description:
    - Create and edit CTE Process set or add, edit, or remove a process to or from the process set
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
      choices: [create, patch, add_process, patch_process, delete_process]
      required: true
      type: str
    id:
      description:
        - Identifier of the CTE ProcessSet to be patched or deleted
      type: str
    processIndex:
      description:
        - Identifier of the CTE Process within ProcessSet to be patched or deleted
      type: str
    name:
      description:
        - Name of the process set
      type: str
    description:
      description:
        - Description of the process set
      type: str
    processes:
      description:
        - List of processes to be added to the process set
      type: str
    directory:
      description:
        - directory path of the process which shall be associated with the process-set
      type: str
    file:
      description:
        - file name of the process which shall be associated with the process-set
      type: str
    signature:
      description:
        - Signature-set ID or Name which shall be associated with the process-set
      type: str
'''

EXAMPLES = '''
- name: "Create CTE ProcessSet"
  thalesgroup.ciphertrust.cte_process_set:
    localNode:
        server_ip: "IP/FQDN of CipherTrust Manager"
        server_private_ip: "Private IP in case that is different from above"
        server_port: 5432
        user: "CipherTrust Manager Username"
        password: "CipherTrust Manager Password"
        verify: false
    op_type: create
    name: TestProcessSet
    description: "via Ansible"
    processes:
      - signature: TestSignSet
        directory: "/home/testUser"
        file: "*"
      - signature: TestSignSet
        directory: "/home/test"
        file: "test.bin"
  register: process_set

- name: "Add process to ProcessSet"
  thalesgroup.ciphertrust.cte_process_set:
    localNode:
        server_ip: "IP/FQDN of CipherTrust Manager"
        server_private_ip: "Private IP in case that is different from above"
        server_port: 5432
        user: "CipherTrust Manager Username"
        password: "CipherTrust Manager Password"
        verify: false
    op_type: add_process
    id: "{{ process_set['response']['id'] }}"
    processes:
      - signature: TestSignSet
        directory: "/home/testAnother"
        file: "*"
'''

RETURN = '''

'''

_process = dict(
  directory=dict(type='str'),
  file=dict(type='str'),
  signature=dict(type='str'),
)

argument_spec = dict(
    op_type=dict(type='str', options=[
      'create', 
      'patch', 
      'add_process', 
      'patch_process',
      'delete_process',
    ], required=True),
    id=dict(type='str'),
    processIndex=dict(type='int'),
    name=dict(type='str'),
    description=dict(type='str'),
    processes=dict(type='list', element='dict', options=_process),
    directory=dict(type='str'),
    file=dict(type='str'),
    signature=dict(type='str'),
)

def validate_parameters(cte_process_set_module):
    return True

def setup_module_object():
    module = ThalesCipherTrustModule(
        argument_spec=argument_spec,
        required_if=(
            ['op_type', 'create', ['name']],
            ['op_type', 'patch', ['id']],
            ['op_type', 'add_process', ['id']],
            ['op_type', 'patch_process', ['id', 'processIndex']],
            ['op_type', 'delete_process', ['id', 'processIndex']],
        ),
        mutually_exclusive=[],
        supports_check_mode=True,
    )
    return module

def main():

    global module
    
    module = setup_module_object()
    validate_parameters(
        cte_process_set_module=module,
    )

    result = dict(
        changed=False,
    )

    if module.params.get('op_type') == 'create':
      try:
        response = createProcessSet(
          node=module.params.get('localNode'),
          name=module.params.get('name'),
          description=module.params.get('description'),
          processes=module.params.get('processes'),
        )
        result['response'] = response
      except CMApiException as api_e:
        if api_e.api_error_code:
          module.fail_json(msg="status code: " + str(api_e.api_error_code) + " message: " + api_e.message)
      except AnsibleCMException as custom_e:
        module.fail_json(msg=custom_e.message)

    elif module.params.get('op_type') == 'patch':
      try:
        response = updateProcessSet(
          node=module.params.get('localNode'),
          id=module.params.get('id'),
          description=module.params.get('description'),
          processes=module.params.get('processes'),
        )
        result['response'] = response
      except CMApiException as api_e:
        if api_e.api_error_code:
          module.fail_json(msg="status code: " + str(api_e.api_error_code) + " message: " + api_e.message)
      except AnsibleCMException as custom_e:
        module.fail_json(msg=custom_e.message)

    elif module.params.get('op_type') == 'add_process':
      try:
        response = addProcessToSet(
          node=module.params.get('localNode'),
          id=module.params.get('id'),
          processes=module.params.get('processes'),
        )
        result['response'] = response
      except CMApiException as api_e:
        if api_e.api_error_code:
          module.fail_json(msg="status code: " + str(api_e.api_error_code) + " message: " + api_e.message)
      except AnsibleCMException as custom_e:
        module.fail_json(msg=custom_e.message)

    elif module.params.get('op_type') == 'patch_process':
      try:
        response = updateProcessInSetByIndex(
          node=module.params.get('localNode'),
          id=module.params.get('id'),
          processIndex=str(module.params.get('processIndex')),
          directory=module.params.get('directory'),
          file=module.params.get('file'),
          signature=module.params.get('signature'),
        )
        result['response'] = response
      except CMApiException as api_e:
        if api_e.api_error_code:
          module.fail_json(msg="status code: " + str(api_e.api_error_code) + " message: " + api_e.message)
      except AnsibleCMException as custom_e:
        module.fail_json(msg=custom_e.message)

    elif module.params.get('op_type') == 'delete_process':
      try:
        response = deleteProcessInSetByIndex(
          node=module.params.get('localNode'),
          id=module.params.get('id'),
          processIndex=str(module.params.get('processIndex')),
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