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
from ansible_collections.thalesgroup.ciphertrust.plugins.module_utils.cluster import new, csr, sign, join
from ansible_collections.thalesgroup.ciphertrust.plugins.module_utils.exceptions import CMApiException, AnsibleCMException

DOCUMENTATION = '''
---
module: cm_cluster
short_description: Create or join CipherTrust Manager node cluster
description:
    - This is a Thales CipherTrust Manager module for working with the CipherTrust Manager APIs, more specifically with cluster management.
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
    op_type:
        description: Operation to be performed
        choices: [new, join]
        required: true
        type: str
    nodes:
        description: list of CM nodes willing to join the cluster
        type: list
        element: dict
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
        default: []
'''

EXAMPLES = '''
- name: "Create new cluster"
  thalesgroup.ciphertrust.cm_cluster:
    localNode:
        server_ip: "IP/FQDN of CipherTrust Manager"
        server_private_ip: "Private IP in case that is different from above"
        server_port: 5432
        user: "CipherTrust Manager Username"
        password: "CipherTrust Manager Password"
        verify: false
    op_type: new

- name: "Join cluster"
  thalesgroup.ciphertrust.cm_cluster:
    localNode:
        server_ip: "IP/FQDN of CipherTrust Manager"
        server_private_ip: "Private IP in case that is different from above"
        server_port: 5432
        user: "CipherTrust Manager Username"
        password: "CipherTrust Manager Password"
        verify: false
    op_type: join
    nodes:
      - server_ip: "IP/FQDN of CipherTrust Manager"
        server_private_ip: "Private IP in case that is different from above"
        server_port: 5432
        user: "CipherTrust Manager Username"
        password: "CipherTrust Manager Password"
        verify: false
'''

_joining_node = dict(
    server_ip=dict(type='str', required=True),
    server_private_ip=dict(type='str', required=True),
    server_port=dict(type='int', required=True),
    user=dict(type='str', required=True),
    password=dict(type='str', required=True),
    verify=dict(type='bool', required=True),
)
argument_spec = dict(
    op_type=dict(type='str', options=['new', 'join'], required=True),
    nodes=dict(type='list', element='dict', options=_joining_node),
)

def validate_parameters(cluster_module):
    return True

def setup_module_object():
    module = ThalesCipherTrustModule(
        argument_spec=argument_spec,
        required_if=(
            ['op_type', 'join', ['nodes']],
        ),
        mutually_exclusive=[],
        supports_check_mode=True,
    )
    return module

def main():

    global module
    
    module = setup_module_object()
    validate_parameters(
        cluster_module=module,
    )

    result = dict(
        changed=False,
    )

    if module.params.get('op_type') == 'new':
        try:
          response = new(
            node=module.params.get('localNode'),
          )
          result['response'] = response
        except CMApiException as api_e:
          if api_e.api_error_code:
            module.fail_json(msg="status code: " + str(api_e.api_error_code) + " message: " + api_e.message)
        except AnsibleCMException as custom_e:
          module.fail_json(msg=custom_e.message)

    elif module.params.get('op_type') == 'join':
        _joining_nodes = module.params.get('nodes')

        for node in _joining_nodes:
          strCSR = ''
          # ------Section Begins-----"
          # Send request for CSR generation to the new node
          try:
            strCSR = csr(
                master=module.params.get('localNode'),
                node=node,
            )
          except CMApiException as api_e:
            if api_e.api_error_code:
              module.fail_json(msg="status code: " + str(api_e.api_error_code) + " message: " + api_e.message)
          except AnsibleCMException as custom_e:
            module.fail_json(msg=custom_e.message)
          # ------Section Ends-----"

          # ------Section Begins-----"
          # Send request for CSR signing to member node
          cert=''
          caChain=''
          mkek_blob=''

          try:
            output = sign(
                master=module.params.get('localNode'),
                node=node,
                csr=strCSR,
            )
            cert = output["cert"]
            caChain = output["cachain"]
            mkek_blob = output["mkek_blob"]
          except CMApiException as api_e:
            if api_e.api_error_code:
              module.fail_json(msg="status code: " + str(api_e.api_error_code) + " message: " + api_e.message)
          except AnsibleCMException as custom_e:
            module.fail_json(msg=custom_e.message)
          # ------Section Ends-----"

          # ------Section Begins-----"
          # Last but not least, send the join request to new node with signed certificate

          try:
            output = join(
                master=module.params.get('localNode'),
                node=node,
                cert=cert,
                caChain=caChain,
                mkek_blob=mkek_blob,
            )
            result["output"] = output
          except CMApiException as api_e:
            if api_e.api_error_code:
              module.fail_json(msg="status code: " + str(api_e.api_error_code) + " message: " + api_e.message)
          except AnsibleCMException as custom_e:
            module.fail_json(msg=custom_e.message)
          # ------Section Ends-----"

    module.exit_json(**result)

if __name__ == '__main__':
    main()