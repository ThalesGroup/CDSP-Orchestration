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
from ansible_collections.thalesgroup.ciphertrust.plugins.module_utils.connection_management import createConnection, patchConnection, addLunaPartition, deleteLunaPartition, enableSTC, disableSTC, addHSMServer, addLunaSTCPartition
from ansible_collections.thalesgroup.ciphertrust.plugins.module_utils.exceptions import CMApiException, AnsibleCMException

DOCUMENTATION = '''
---
module: connection_manager_luna_hsm
short_description: Manage connections to the Luna Network HSM HA or non-HA
description:
    - This is a Thales CipherTrust Manager module for working with the CipherTrust Manager APIs, more specifically with Connection Manager API for Luna Network HSM
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
        choices: [create, patch, add_partition, delete_partition, add_stc_partition, add_hsm_server, enable_stc, disable_stc]
        required: true
        type: str
    connection_id:
        description: Unique ID of the connection to be updated
        default: none
        type: str
    partition_id:
        description: Unique ID of the Luna Network HSM partition to be updated or removed
        type: str
    name:
        description: Unique connection name
        default: none
        type: str
    description:
        description: Description about the connection
        default: none
        type: str
    meta:
        description: Optional end-user or service data stored with the connection
        required: false
        type: dict
    products:
        description: Array of the CipherTrust products associated with the connection.
        default: none
        type: list
        element: str
    partitions:
        description: One partition for a Non HA connection or a list for an HA group.
        type: list
        elements: dict
        suboptions:
          hostname:
            description: Hostname/IP of the Luna Network HSM Server.
            type: str
          partition_label:
            description: Label of the partition on the Luna Network HSM Server.
            type: str
          serial_number:
            description: Serial number of the partition.
            type: str
    password:
        description: Password associated with the Partition of the Luna Network HSM.
        default: none
        type: str
    is_ha_enabled:
        description: Password associated with the Partition of the Luna Network HSM.
        type: boolean
    partition_identity:
        description: Contents of Luna Network HSM STC Partition Identity(pid) file in base64 form.
        type: str
    label:
        description: Label of the Luna Network HSM STC Partition.
        type: str
    hsm_certificate:
        description: Luna Network HSM Server Certificate.
        type: str
    hostname:
        description: Hostname/IP of the Luna Network HSM Server.
        type: str
    partition_label:
        description: Label of the partition on the Luna Network HSM Server.
        type: str
    serial_number:
        description: Serial number of the partition.
        type: str
'''

EXAMPLES = '''
- name: "Create Luna Network HSM Connection"
  thalesgroup.ciphertrust.connection_manager_luna_hsm:
    localNode:
        server_ip: "IP/FQDN of CipherTrust Manager"
        server_private_ip: "Private IP in case that is different from above"
        server_port: 5432
        user: "CipherTrust Manager Username"
        password: "CipherTrust Manager Password"
        verify: false
    op_type: create
    name: luna-network-connection
    products:
      - cckm
    meta:
        color: blue
    is_ha_enabled: false
    password: pwd
    partitions:
      - hostname: sample-hostname
        partition_label: sample-label
        serial_number: serialNo.
'''

RETURN = '''

'''
_schema_less = dict()

_partition = dict(
    hostname=dict(type='str'),
    partition_label=dict(type='str'),
    serial_number=dict(type='str'),
)

argument_spec = dict(
    op_type=dict(type='str', options=['create', 'patch', 'add_partition', 'delete_partition', 'add_stc_partition', 'add_hsm_server', 'enable_stc', 'disable_stc'], required=True),
    connection_id=dict(type='str'),
    partition_id=dict(type='str'),    
    password=dict(type='str'),
    name=dict(type='str'),
    description=dict(type='str'),
    partitions=dict(type='list', element='dict', options=_partition),
    is_ha_enabled=dict(type='bool'),
    meta=dict(type='dict', options=_schema_less),
    products=dict(type='list', element='str'),
    hostname=dict(type='str'),
    partition_label=dict(type='str'),
    serial_number=dict(type='str'),
    # for add_stc_partition
    partition_identity=dict(type='str'),
    label=dict(type='str'),
    # for add_hsm_server
    hsm_certificate=dict(type='str'),
)

def validate_parameters(domain_module):
    return True

def setup_module_object():
    module = ThalesCipherTrustModule(
        argument_spec=argument_spec,
        required_if=(
            ['op_type', 'patch', ['connection_id']],
            ['op_type', 'create', ['name', 'partitions', 'password']],
            ['op_type', 'add_partition', ['connection_id', 'hostname', 'port', 'protocol']],
            ['op_type', 'delete_partition', ['connection_id', 'partition_id']],
            ['op_type', 'add_stc_partition', ['partition_identity', 'serial_number']],
            ['op_type', 'add_hsm_server', ['hostname', 'hsm_certificate']],
            ['op_type', 'enable_stc', ['connection_id']],
            ['op_type', 'disable_stc', ['connection_id']],
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
          connection_type='luna_nw_hsm',
          name=module.params.get('name'),
          partitions=module.params.get('nodes'),
          password=module.params.get('password'),
          description=module.params.get('description'),
          is_ha_enabled=module.params.get('is_ha_enabled'),
          meta=module.params.get('meta'),
          products=module.params.get('products'),
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
          connection_type='luna_nw_hsm',
          connection_id=module.params.get('connection_id'),
          password=module.params.get('password'),
          description=module.params.get('description'),
          meta=module.params.get('meta'),
          products=module.params.get('products'),
        )
        result['response'] = response
      except CMApiException as api_e:
        if api_e.api_error_code:
          module.fail_json(msg="status code: " + str(api_e.api_error_code) + " message: " + api_e.message)
      except AnsibleCMException as custom_e:
        module.fail_json(msg=custom_e.message)

    elif module.params.get('op_type') == 'add_partition':
      try:
        response = addLunaPartition(
          node=module.params.get('localNode'),
          connection_id=module.params.get('connection_id'),
          hostname=module.params.get('hostname'),
          partition_label=module.params.get('partition_label'),
          serial_number=module.params.get('serial_number'),
        )
        result['response'] = response
      except CMApiException as api_e:
        if api_e.api_error_code:
          module.fail_json(msg="status code: " + str(api_e.api_error_code) + " message: " + api_e.message)
      except AnsibleCMException as custom_e:
        module.fail_json(msg=custom_e.message)

    elif module.params.get('op_type') == 'delete_partition':
      try:
        response = deleteLunaPartition(
          node=module.params.get('localNode'),
          connection_id=module.params.get('connection_id'),
          partition_id=module.params.get('partition_id'),
        )
        result['response'] = response
      except CMApiException as api_e:
        if api_e.api_error_code:
          module.fail_json(msg="status code: " + str(api_e.api_error_code) + " message: " + api_e.message)
      except AnsibleCMException as custom_e:
        module.fail_json(msg=custom_e.message)

    elif module.params.get('op_type') == 'add_stc_partition':
      try:
        response = addLunaSTCPartition(
          node=module.params.get('localNode'),
          partition_identity=module.params.get('partition_identity'),
          serial_number=module.params.get('serial_number'),
          description=module.params.get('description'),
          label=module.params.get('label'),
          meta=module.params.get('meta'),
          products=module.params.get('products'),
        )
        result['response'] = response
      except CMApiException as api_e:
        if api_e.api_error_code:
          module.fail_json(msg="status code: " + str(api_e.api_error_code) + " message: " + api_e.message)
      except AnsibleCMException as custom_e:
        module.fail_json(msg=custom_e.message)

    elif module.params.get('op_type') == 'add_hsm_server':
      try:
        response = addHSMServer(
          node=module.params.get('localNode'),
          hostname=module.params.get('hostname'),
          hsm_certificate=module.params.get('hsm_certificate'),
          description=module.params.get('description'),
          meta=module.params.get('meta'),
          products=module.params.get('products'),
        )
        result['response'] = response
      except CMApiException as api_e:
        if api_e.api_error_code:
          module.fail_json(msg="status code: " + str(api_e.api_error_code) + " message: " + api_e.message)
      except AnsibleCMException as custom_e:
        module.fail_json(msg=custom_e.message)

    elif module.params.get('op_type') == 'enable_stc':
      try:
        response = enableSTC(
          node=module.params.get('localNode'),
          connection_id=module.params.get('connection_id'),
        )
        result['response'] = response
      except CMApiException as api_e:
        if api_e.api_error_code:
          module.fail_json(msg="status code: " + str(api_e.api_error_code) + " message: " + api_e.message)
      except AnsibleCMException as custom_e:
        module.fail_json(msg=custom_e.message)

    elif module.params.get('op_type') == 'disable_stc':
      try:
        response = disableSTC(
          node=module.params.get('localNode'),
          connection_id=module.params.get('connection_id'),
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