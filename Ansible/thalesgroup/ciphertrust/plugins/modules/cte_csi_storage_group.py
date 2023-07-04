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
from ansible_collections.thalesgroup.ciphertrust.plugins.module_utils.cte import createCSIStorageGroup, updateCSIStorageGroup, csiGroupAddClient, csiGroupAddGuardPoint, csiGroupRemoveClient, csiGroupUpdateGuardPoint, csiGroupRemoveGuardPoint
from ansible_collections.thalesgroup.ciphertrust.plugins.module_utils.exceptions import CMApiException, AnsibleCMException

DOCUMENTATION = '''
---
module: cte_csi_storage_group
short_description: Manage CTE CSI Storage Group
description:
    - Define and manage CipherTrust Transparent Encryption (CTE) Container Storage Interface (CSI) and also add guard policies and clients to the same.
    - This will allow administrator to apply data protection/reveal based on the client or the guard points.  
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
      choices: [create, patch, add_client, remove_client, add_guard_point, patch_guard_point, remove_guard_point]
      required: true
      type: str
    id:
      description:
        - Identifier of the CTE CSI Storage Group to be patched
      type: str
    client_id:
      description:
        - Identifier of the client added added to the CSI Group
      type: str
    gp_id:
      description:
        - Identifier of the guard point added to the CSI Group
      type: str
    k8s_namespace:
      description:
        - Name of the K8s namespace
      type: str
    k8s_storage_class:
      description:
        - Name of the K8s StorageClass
      type: str
    name:
      description:
        - Name to uniquely identify the CSI storage group. This name will be visible on the CipherTrust Manager
      type: str
    client_profile:
      description:
        - Optional Client Profile for the storage group. If not provided, the default profile will be used
      type: str
    description:
      description:
        - Optional description for the storage group
      type: str
    client_list:
      description: List of identifiers of clients to be associated with the client group. This identifier can be the name or UUID.
      type: list
    policy_list:
      description: List of CSI policy identifiers to be associated with the storage group. This identifier can be the name or UUID.
      type: list
    guard_enabled:
      description: Enable or disable the GuardPolicy. Set to true to enable, false to disable.
      type: boolean
'''

EXAMPLES = '''
- name: "Create CSI Storage Group"
  thalesgroup.ciphertrust.cte_csi_storage_group:
    localNode:
        server_ip: "IP/FQDN of CipherTrust Manager"
        server_private_ip: "Private IP in case that is different from above"
        server_port: 5432
        user: "CipherTrust Manager Username"
        password: "CipherTrust Manager Password"
        verify: false
    op_type: create
    name: AnsibleCSI_SG_1
    k8s_namespace: AnsibleK8s_NS_1
    k8s_storage_class: AnsibleK8s_SC_1
    description: "Test CSIStorageGroup"
    client_profile: DefaultClientProfile
  register: csi_sg

- name: "Edit CSI Storage Group"
  thalesgroup.ciphertrust.cte_csi_storage_group:
    localNode:
        server_ip: "IP/FQDN of CipherTrust Manager"
        server_private_ip: "Private IP in case that is different from above"
        server_port: 5432
        user: "CipherTrust Manager Username"
        password: "CipherTrust Manager Password"
        verify: false
    op_type: create
    id: "{{ csi_sg['response']['id'] }}"
    description: "Test CSIStorageGroup Updated"
    client_profile: DefaultClientProfile

- name: "Add clients to the CSI Storage Group"
  thalesgroup.ciphertrust.cte_csi_storage_group:
    localNode:
        server_ip: "IP/FQDN of CipherTrust Manager"
        server_private_ip: "Private IP in case that is different from above"
        server_port: 5432
        user: "CipherTrust Manager Username"
        password: "CipherTrust Manager Password"
        verify: false
    op_type: add_client
    id: "{{ csi_sg['response']['id'] }}"
    client_list:
      - Client1
      - Client2

- name: "Add guarpolicy to the CSI Storage Group"
  thalesgroup.ciphertrust.cte_csi_storage_group:
    localNode:
        server_ip: "IP/FQDN of CipherTrust Manager"
        server_private_ip: "Private IP in case that is different from above"
        server_port: 5432
        user: "CipherTrust Manager Username"
        password: "CipherTrust Manager Password"
        verify: false
    op_type: add_guard_point
    id: "{{ csi_sg['response']['id'] }}"
    policy_list:
      - CSI_Policy_1
      - CSI_Policy_2
'''

RETURN = '''

'''

argument_spec = dict(
    op_type=dict(type='str', options=[
      'create',
      'patch',
      'add_client',
      'remove_client',
      'add_guard_point',
      'patch_guard_point',
      'remove_guard_point',
    ], required=True),
    id=dict(type='str'),
    client_id=dict(type='str'),
    gp_id=dict(type='str'),
    k8s_namespace=dict(type='str'),
    k8s_storage_class=dict(type='str'),
    name=dict(type='str'),
    client_profile=dict(type='str'),
    description=dict(type='str'),
    client_list=dict(type='list', element='str'),
    policy_list=dict(type='list', element='str'),
    guard_enabled=dict(type='bool'),
)

def validate_parameters(cte_csi_sg_module):
    return True

def setup_module_object():
    module = ThalesCipherTrustModule(
        argument_spec=argument_spec,
        required_if=(
            ['op_type', 'create', ['k8s_namespace', 'k8s_storage_class', 'name']],
            ['op_type', 'patch', ['id']],
            ['op_type', 'add_client', ['id', 'client_list']],
            ['op_type', 'remove_client', ['id', 'client_id']],
            ['op_type', 'add_guard_point', ['id', 'policy_list']],
            ['op_type', 'patch_guard_point', ['id', 'gp_id']],
            ['op_type', 'remove_guard_point', ['id', 'gp_id']],
        ),
        mutually_exclusive=[],
        supports_check_mode=True,
    )
    return module

def main():

    global module
    
    module = setup_module_object()
    validate_parameters(
        cte_csi_sg_module=module,
    )

    result = dict(
        changed=False,
    )

    if module.params.get('op_type') == 'create':
      try:
        response = createCSIStorageGroup(
          node=module.params.get('localNode'),
          name=module.params.get('name'),
          description=module.params.get('description'),
          k8s_namespace=module.params.get('k8s_namespace'),
          k8s_storage_class=module.params.get('k8s_storage_class'),
          client_profile=module.params.get('client_profile'),
        )
        result['response'] = response
      except CMApiException as api_e:
        if api_e.api_error_code:
          module.fail_json(msg="status code: " + str(api_e.api_error_code) + " message: " + api_e.message)
      except AnsibleCMException as custom_e:
        module.fail_json(msg=custom_e.message)

    elif module.params.get('op_type') == 'patch':
      try:
        response = updateCSIStorageGroup(
          node=module.params.get('localNode'),
          id=module.params.get('id'),
          description=module.params.get('description'),
          client_profile=module.params.get('client_profile'),
        )
        result['response'] = response
      except CMApiException as api_e:
        if api_e.api_error_code:
          module.fail_json(msg="status code: " + str(api_e.api_error_code) + " message: " + api_e.message)
      except AnsibleCMException as custom_e:
        module.fail_json(msg=custom_e.message)

    elif module.params.get('op_type') == 'add_client':
      try:
        response = csiGroupAddClient(
          node=module.params.get('localNode'),
          id=module.params.get('id'),
          client_list=module.params.get('client_list'),
        )
        result['response'] = response
      except CMApiException as api_e:
        if api_e.api_error_code:
          module.fail_json(msg="status code: " + str(api_e.api_error_code) + " message: " + api_e.message)
      except AnsibleCMException as custom_e:
        module.fail_json(msg=custom_e.message)

    elif module.params.get('op_type') == 'remove_client':
      try:
        response = csiGroupRemoveClient(
          node=module.params.get('localNode'),
          id=module.params.get('id'),
          client_id=module.params.get('client_id'),
        )
        result['response'] = response
      except CMApiException as api_e:
        if api_e.api_error_code:
          module.fail_json(msg="status code: " + str(api_e.api_error_code) + " message: " + api_e.message)
      except AnsibleCMException as custom_e:
        module.fail_json(msg=custom_e.message)

    elif module.params.get('op_type') == 'add_guard_point':
      try:
        response = csiGroupAddGuardPoint(
          node=module.params.get('localNode'),
          id=module.params.get('id'),
          policy_list=module.params.get('policy_list'),
        )
        result['response'] = response
      except CMApiException as api_e:
        if api_e.api_error_code:
          module.fail_json(msg="status code: " + str(api_e.api_error_code) + " message: " + api_e.message)
      except AnsibleCMException as custom_e:
        module.fail_json(msg=custom_e.message)

    elif module.params.get('op_type') == 'patch_guard_point':
      try:
        response = csiGroupUpdateGuardPoint(
          node=module.params.get('localNode'),
          gp_id=module.params.get('gp_id'),
          guard_enabled=module.params.get('guard_enabled'),
        )
        result['response'] = response
      except CMApiException as api_e:
        if api_e.api_error_code:
          module.fail_json(msg="status code: " + str(api_e.api_error_code) + " message: " + api_e.message)
      except AnsibleCMException as custom_e:
        module.fail_json(msg=custom_e.message)

    elif module.params.get('op_type') == 'remove_guard_point':
      try:
        response = csiGroupRemoveGuardPoint(
          node=module.params.get('localNode'),
          gp_id=module.params.get('gp_id'),
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