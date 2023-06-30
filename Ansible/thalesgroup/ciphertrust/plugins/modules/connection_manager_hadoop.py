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
from ansible_collections.thalesgroup.ciphertrust.plugins.module_utils.connection_management import createConnection, patchConnection, addHadoopNode, updateHadoopNode, deleteHadoopNode
from ansible_collections.thalesgroup.ciphertrust.plugins.module_utils.exceptions import CMApiException, AnsibleCMException

DOCUMENTATION = '''
---
module: connection_manager_hadoop
short_description: Manage connections to the Hadoop servers
description:
    - This is a Thales CipherTrust Manager module for working with the CipherTrust Manager APIs, more specifically with Connection Manager API for Hadoop
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
        choices: [create, patch, add_node, update_node, delete_node]
        required: true
        type: str
    connection_id:
        description: Unique ID of the connection to be updated
        default: none
        type: str
    node_id:
        description: Unique ID of the Hadoop node to be updated or removed
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
    nodes:
        description: Hadoop nodes information
        type: list
        elements: dict
        suboptions:
          hostname:
            description: hostname for Hadoop Server
            type: str
          port:
            description: port for Hadoop Server. Possible values 1-65535
            type: int
          protocol:
            description: http or https protocol to be used for communication with the Hadoop node (https required for hadoop-knox)
            type: str
          path:
            description: path for Hadoop Server
            type: str
          server_certificate:
            description: SSL certificate for Hadoop Server TLS communication
            type: str
    password:
        description: Password for Hadoop server (required for Knox)
        default: none
        type: str
    service:
        description: Name of the third-party service associated with the resource. Examples are aws, azure, gcp, luna network, and hadoop-knox
        default: none
        type: str
    username:
        description: Username for accessing Hadoop server (required for Knox)
        default: none
        type: str
    topology:
        description: Topology deployment of the Knox gateway
        default: none
        type: str
    hostname:
      description: hostname for Hadoop Server
      type: str
    port:
      description: port for Hadoop Server. Possible values 1-65535
      type: int
    protocol:
      description: http or https protocol to be used for communication with the Hadoop node (https required for hadoop-knox)
      type: str
    path:
      description: path for Hadoop Server
      type: str
    server_certificate:
      description: SSL certificate for Hadoop Server TLS communication
      type: str
'''

EXAMPLES = '''
- name: "Create Hadoop Connection"
  thalesgroup.ciphertrust.connection_manager_hadoop:
    localNode:
        server_ip: "IP/FQDN of CipherTrust Manager"
        server_private_ip: "Private IP in case that is different from above"
        server_port: 5432
        user: "CipherTrust Manager Username"
        password: "CipherTrust Manager Password"
        verify: false
    op_type: create
    name: knoxConnection
    service: hadoop-knox
    products:
      - cte
      - "data discovery"
    username: user
    password: pwd
    topology: default
    nodes:
      - hostname: node1
        port: 1234
        protocol: https
        server_certificate: "-----cert-----"


- name: "Update Hadoop Connection"
  thalesgroup.ciphertrust.connection_manager_hadoop:
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

_node = dict(
    hostname=dict(type='str'),
    port=dict(type='int'),
    protocol=dict(type='str'),
    path=dict(type='str'),
    server_certificate=dict(type='str'),
)

argument_spec = dict(
    op_type=dict(type='str', options=['create', 'patch', 'add_node', 'update_node', 'delete_node'], required=True),
    connection_id=dict(type='str'),
    node_id=dict(type='str'),
    nodes=dict(type='list', element='dict', options=_node),
    password=dict(type='str'),
    name=dict(type='str'),
    service=dict(type='str'),
    username=dict(type='str'),
    topology=dict(type='str'),
    description=dict(type='str'),
    meta=dict(type='dict', options=_schema_less),
    products=dict(type='list', element='str'),
    hostname=dict(type='str'),
    port=dict(type='int'),
    protocol=dict(type='str'),
    path=dict(type='str'),
    server_certificate=dict(type='str'),
)

def validate_parameters(domain_module):
    return True

def setup_module_object():
    module = ThalesCipherTrustModule(
        argument_spec=argument_spec,
        required_if=(
            ['op_type', 'patch', ['connection_id']],
            ['op_type', 'create', ['name', 'nodes', 'password', 'service', 'username']],
            ['op_type', 'add_node', ['connection_id', 'hostname', 'port', 'protocol']],
            ['op_type', 'update_node', ['connection_id', 'node_id', 'hostname', 'port', 'protocol']],
            ['op_type', 'delete_node', ['connection_id', 'node_id']],
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
          connection_type='hadoop',
          name=module.params.get('name'),
          nodes=module.params.get('nodes'),
          password=module.params.get('password'),
          service=module.params.get('service'),
          username=module.params.get('username'),
          description=module.params.get('description'),
          meta=module.params.get('meta'),
          products=module.params.get('products'),
          topology=module.params.get('topology'),
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
          connection_type='hadoop',
          connection_id=module.params.get('connection_id'),
          password=module.params.get('password'),
          username=module.params.get('username'),
          description=module.params.get('description'),
          meta=module.params.get('meta'),
          products=module.params.get('products'),
          topology=module.params.get('topology'),
        )
        result['response'] = response
      except CMApiException as api_e:
        if api_e.api_error_code:
          module.fail_json(msg="status code: " + str(api_e.api_error_code) + " message: " + api_e.message)
      except AnsibleCMException as custom_e:
        module.fail_json(msg=custom_e.message)

    elif module.params.get('op_type') == 'add_node':
      try:
        response = addHadoopNode(
          node=module.params.get('localNode'),
          connection_id=module.params.get('connection_id'),
          hostname=module.params.get('hostname'),
          port=module.params.get('port'),
          protocol=module.params.get('protocol'),
          path=module.params.get('path'),
          server_certificate=module.params.get('server_certificate'),
        )
        result['response'] = response
      except CMApiException as api_e:
        if api_e.api_error_code:
          module.fail_json(msg="status code: " + str(api_e.api_error_code) + " message: " + api_e.message)
      except AnsibleCMException as custom_e:
        module.fail_json(msg=custom_e.message)

    elif module.params.get('op_type') == 'update_node':
      try:
        response = updateHadoopNode(
          node=module.params.get('localNode'),
          connection_id=module.params.get('connection_id'),
          node_id=module.params.get('node_id'),
          hostname=module.params.get('hostname'),
          port=module.params.get('port'),
          protocol=module.params.get('protocol'),
          path=module.params.get('path'),
          server_certificate=module.params.get('server_certificate'),
        )
        result['response'] = response
      except CMApiException as api_e:
        if api_e.api_error_code:
          module.fail_json(msg="status code: " + str(api_e.api_error_code) + " message: " + api_e.message)
      except AnsibleCMException as custom_e:
        module.fail_json(msg=custom_e.message)

    elif module.params.get('op_type') == 'delete_node':
      try:
        response = deleteHadoopNode(
          node=module.params.get('localNode'),
          connection_id=module.params.get('connection_id'),
          node_id=module.params.get('node_id'),
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