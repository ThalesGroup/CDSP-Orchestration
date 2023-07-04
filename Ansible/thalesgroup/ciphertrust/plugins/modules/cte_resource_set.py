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
from ansible_collections.thalesgroup.ciphertrust.plugins.module_utils.cte import createResourceSet, updateResourceSet, addResourceToSet, updateResourceInSetByIndex, deleteResourceInSetByIndex
from ansible_collections.thalesgroup.ciphertrust.plugins.module_utils.exceptions import CMApiException, AnsibleCMException

DOCUMENTATION = '''
---
module: cte_resource_set
short_description: Create and manage CTE resource-sets
description:
    - Create and edit CTE resource set or add, edit, or remove a resource to or from the resource set
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
      choices: [create, patch, add_resource, patch_resource, delete_resource]
      required: true
      type: str
    id:
      description:
        - Identifier of the CTE ResourceSet to be patched or deleted
      type: str
    resourceIndex:
      description:
        - Identifier of the CTE Resource within ResourceSet to be patched or deleted
      type: str
    name:
      description:
        - Name of the resource set
      type: str
    description:
      description:
        - Description of the resource set
      type: str
    classification_tags:
      description:
        - Classification set to be added to the resource set
      type: list
      elements: dict
    resources:
      description:
        - List of resources to be added to the resource set
      type: list
      elements: dict
    type:
      description:
        - Type of the resource set i.e. Directory or Classification. Default value is Directory
      type: str
      choices: [Directory, Classification]
    directory:
      description:
        - directory path of the Resource which shall be associated with the resource-set
      type: str
    file:
      description:
        - file name of the Resource which shall be associated with the resource-set
      type: str
    hdfs:
      description:
        - Whether the specified path is a HDFS path
      type: boolean
    include_subfolders:
      description:
        - Flag to include subfolders in the Resource
      type: boolean
'''

EXAMPLES = '''
- name: "Create CTE ResourceSet"
  thalesgroup.ciphertrust.cte_resource_set:
    localNode:
      server_ip: "IP/FQDN of CipherTrust Manager"
      server_private_ip: "Private IP in case that is different from above"
      server_port: 5432
      user: "CipherTrust Manager Username"
      password: "CipherTrust Manager Password"
      verify: false
    op_type: create
    name: "RS-Ans-001"
    description: "Created via Ansible"
    type: Directory
    resources:
      - directory: "/"
        file: "*"
        include_subfolders: true
        hdfs: false
  register: resource_set

- name: "Add resource to a ResourceSet"
  thalesgroup.ciphertrust.cte_resource_set:
    localNode:
        server_ip: "IP/FQDN of CipherTrust Manager"
        server_private_ip: "Private IP in case that is different from above"
        server_port: 5432
        user: "CipherTrust Manager Username"
        password: "CipherTrust Manager Password"
        verify: false
    op_type: add_resource
    id: "{{ resource_set['response']['id'] }}"
    resources:
      - directory: "/tmp"
        file: "*"
        include_subfolders: true
        hdfs: false
'''

RETURN = '''

'''

_resource = dict(
  directory=dict(type='str'),
  file=dict(type='str'),
  hdfs=dict(type='bool'),
  include_subfolders=dict(type='bool'),
)

_classification_tag_attribute = dict(
  data_type=dict(type='str'),
  name=dict(type='str'),
  operator=dict(type='str', options=['eq', 'lt', 'ne', 'le', 'gt', 'ge']),
  value=dict(type='str'),
)

_classification_tag = dict(
  attributes=dict(type='list', element='dict', options=_classification_tag_attribute),
  description=dict(type='str'),
  name=dict(type='str'),
)

argument_spec = dict(
    op_type=dict(type='str', options=[
      'create', 
      'patch', 
      'add_resource', 
      'patch_resource',
      'delete_resource',
    ], required=True),
    id=dict(type='str'),
    resourceIndex=dict(type='int'),
    name=dict(type='str'),
    description=dict(type='str'),
    classification_tags=dict(type='list', element='dict', options=_classification_tag),
    resources=dict(type='list', element='dict', options=_resource),
    type=dict(type='str', options=['Directory', 'Classification']),
    directory=dict(type='str'),
    file=dict(type='str'),
    hdfs=dict(type='bool'),
    include_subfolders=dict(type='bool'),
)

def validate_parameters(cte_resource_set_module):
    return True

def setup_module_object():
    module = ThalesCipherTrustModule(
        argument_spec=argument_spec,
        required_if=(
            ['op_type', 'create', ['name']],
            ['op_type', 'patch', ['id']],
            ['op_type', 'add_resource', ['id']],
            ['op_type', 'patch_resource', ['id', 'resourceIndex']],
        ),
        mutually_exclusive=[],
        supports_check_mode=True,
    )
    return module

def main():

    global module
    
    module = setup_module_object()
    validate_parameters(
        cte_resource_set_module=module,
    )

    result = dict(
        changed=False,
    )

    if module.params.get('op_type') == 'create':
      try:
        response = createResourceSet(
          node=module.params.get('localNode'),
          name=module.params.get('name'),
          classification_tags=module.params.get('classification_tags'),
          description=module.params.get('description'),
          resources=module.params.get('resources'),
          type=module.params.get('type'),
        )
        result['response'] = response
      except CMApiException as api_e:
        if api_e.api_error_code:
          module.fail_json(msg="status code: " + str(api_e.api_error_code) + " message: " + api_e.message)
      except AnsibleCMException as custom_e:
        module.fail_json(msg=custom_e.message)

    elif module.params.get('op_type') == 'patch':
      try:
        response = updateResourceSet(
          node=module.params.get('localNode'),
          id=module.params.get('id'),
          classification_tags=module.params.get('classification_tags'),
          description=module.params.get('description'),
          resources=module.params.get('resources'),
        )
        result['response'] = response
      except CMApiException as api_e:
        if api_e.api_error_code:
          module.fail_json(msg="status code: " + str(api_e.api_error_code) + " message: " + api_e.message)
      except AnsibleCMException as custom_e:
        module.fail_json(msg=custom_e.message)

    elif module.params.get('op_type') == 'add_resource':
      try:
        response = addResourceToSet(
          node=module.params.get('localNode'),
          id=module.params.get('id'),
          resources=module.params.get('resources'),
        )
        result['response'] = response
      except CMApiException as api_e:
        if api_e.api_error_code:
          module.fail_json(msg="status code: " + str(api_e.api_error_code) + " message: " + api_e.message)
      except AnsibleCMException as custom_e:
        module.fail_json(msg=custom_e.message)

    elif module.params.get('op_type') == 'patch_resource':
      try:
        response = updateResourceInSetByIndex(
          node=module.params.get('localNode'),
          id=module.params.get('id'),
          resourceIndex=str(module.params.get('resourceIndex')),
          directory=module.params.get('directory'),
          file=module.params.get('file'),
          hdfs=module.params.get('hdfs'),
          include_subfolders=module.params.get('include_subfolders'),
        )
        result['response'] = response
      except CMApiException as api_e:
        if api_e.api_error_code:
          module.fail_json(msg="status code: " + str(api_e.api_error_code) + " message: " + api_e.message)
      except AnsibleCMException as custom_e:
        module.fail_json(msg=custom_e.message)

    elif module.params.get('op_type') == 'delete_resource':
      try:
        response = deleteResourceInSetByIndex(
          node=module.params.get('localNode'),
          id=module.params.get('id'),
          resourceIndex=str(module.params.get('resourceIndex')),
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