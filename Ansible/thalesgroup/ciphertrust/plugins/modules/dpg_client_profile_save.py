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
from ansible_collections.thalesgroup.ciphertrust.plugins.module_utils.dpg import createClientProfile, updateClientProfile
from ansible_collections.thalesgroup.ciphertrust.plugins.module_utils.exceptions import CMApiException, AnsibleCMException

DOCUMENTATION = '''
---
module: dpg_client_profile_save
short_description: Manage DPG client profile
description:
    - This is a Thales CipherTrust Manager module for working with the CipherTrust Manager APIs, more specifically with DPG Client Profile API
    - Refer https://thalesdocs.com/ctp/con/dpg/latest/admin/index.html for API documentation
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
    profile_id:
      description:
        - Identifier of the client profile to be patched
      type: str
    name:
      description: Unique name for the client profile.
      type: str
    app_connector_type:
      description: App connector type for which the client profile is created
      choices: [DPG, CADP For Java]
      type: str
    ca_id:
      description: Local CA mapped with client profile
      type: str
      required: false
    cert_duration:
      description: Duration for which client credentials are valid
      type: int
      required: false
    configurations:
      description: Parameters required to initialize connector
      type: dict
    csr_parameters:
      description: Client certificate parameters to be updated
      type: dict
    heartbeat_threshold:
      description: The Threshold by which client's connectivity_status will be moved to Error if not heartbeat is received
      type: int
      required: false
    lifetime:
      description: Validity of registration token
      type: str
      required: false
    max_clients:
      description: Number of clients that can register using a registration token
      type: int
      required: false
    nae_iface_port:
      description: Nae interface mapped with client profile
      type: int
      required: false
    policy_id:
      description: Policy mapped with client profile.
      type: str
      required: false
'''

EXAMPLES = '''
- name: "Create DPG Client Profile"
  thalesgroup.ciphertrust.dpg_client_profile_save:
    localNode:
        server_ip: "IP/FQDN of CipherTrust Manager"
        server_private_ip: "Private IP in case that is different from above"
        server_port: 5432
        user: "CipherTrust Manager Username"
        password: "CipherTrust Manager Password"
        verify: false
    op_type: create

- name: "Patch DPG Client Profile"
  thalesgroup.ciphertrust.dpg_client_profile_save:
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

_tls_to_appserver = dict(
    tls_skip_verify=dict(type='bool'),
    tls_enabled=dict(type='bool'),
)
_auth_method_used = dict(
    scheme_name=dict(type='str', options=['Basic', 'Bearer'], default='Basic'),
    token_field=dict(type='str'),
)
_configuration = dict(
    symmetric_key_cache_enabled=dict(type='bool', default=True),
    symmetric_key_cache_expiry=dict(type='int', default=43200),
    symmetric_key_cache_auto_refresh_interval=dict(type='int', default=0),
    local_crypto_context_expiry=dict(type='int', default=0),
    local_crypto_provider=dict(type='str'),
    persistent_cache_enabled=dict(type='bool', default=False),
    persistent_cache_expiry_keys=dict(type='int', default=43200),
    persistent_cache_max_size=dict(type='int', default=100),
    verify_ssl_certificate=dict(type='bool', default=False),
    syslog_server_ip=dict(type='str'),
    syslog_server_port=dict(type='int'),
    syslog_server_protocol=dict(type='str'),
    syslog_no_of_retries=dict(type='int'),
    syslog_retry_interval=dict(type='int'),
    syslog_retry_limit=dict(type='int'),
    use_persistent_connections=dict(type='bool', default=True),
    size_of_connection_pool=dict(type='int', default=300),
    load_balancing_algorithm=dict(type='str', options=['round-robin', 'random'], default='round-robin'),
    connection_idle_timeout=dict(type='int', default=600000),
    connection_retry_interval=dict(type='int', default=600000),
    cluster_synchronization_delay=dict(type='int', default=170),
    credentials_encrypted=dict(type='bool', default=False),
    asymmetric_key_cache_enabled=dict(type='bool', default=True),
    log_level=dict(type='str', options=['ERROR', 'WARN', 'INFO', 'DEBUG'], default='WARN'),
    log_rotation=dict(type='str', options=['None', 'Daily', 'Weekly', 'Monthly', 'Size'], default='Daily'),
    log_size_limit=dict(type='int', default=100000),
    log_type=dict(type='str', options=['Console', 'File', 'Multi', 'Syslog'], default='Console'),
    key_non_exportable_policy=dict(type='bool', default=False),
    connection_timeout=dict(type='int', default=60000),
    unreachable_server_retry_period=dict(type='int', default=60000),
    connection_read_timeout=dict(type='int', default=7000),
    ssl_handshake_timeout=dict(type='int', default=0),
    heartbeat_interval=dict(type='int', default=300),
    heartbeat_timeout_count=dict(type='int', default=-1),
    tls_to_appserver=dict(type='dict', options=_tls_to_appserver),
    dial_timeout=dict(type='int'),
    dial_keep_alive=dict(type='int'),
    auth_method_used=dict(type='dict', options=_auth_method_used),
)

_csr_param = dict(
    csr_cn=dict(type='str'),
    csr_country=dict(type='str'),
    csr_state=dict(type='str'),
    csr_city=dict(type='str'),
    csr_org_name=dict(type='str'),
    csr_org_unit=dict(type='str'),
    csr_email=dict(type='str'),
)

argument_spec = dict(
    op_type=dict(type='str', options=['create', 'patch'], required=True),
    profile_id=dict(type='str'),
    app_connector_type=dict(type='str', options=['DPG', 'CADP For Java']),
    name=dict(type='str'),
    ca_id=dict(type='str'),
    cert_duration=dict(type='int'),
    configurations=dict(type='dict', options=_configuration, required=False),
    csr_parameters=dict(type='dict', options=_csr_param, required=False),
    heartbeat_threshold=dict(type='int'),
    lifetime=dict(type='str'),
    max_clients=dict(type='int'),
    nae_iface_port=dict(type='int'),
    policy_id=dict(type='str'),
)

def validate_parameters(dpg_client_profile_module):
    return True

def setup_module_object():
    module = ThalesCipherTrustModule(
        argument_spec=argument_spec,
        required_if=(
            ['op_type', 'patch', ['profile_id']],
            ['op_type', 'create', ['app_connector_type', 'name']]
        ),
        mutually_exclusive=[],
        supports_check_mode=True,
    )
    return module

def main():

    global module
    
    module = setup_module_object()
    validate_parameters(
        dpg_client_profile_module=module,
    )

    result = dict(
        changed=False,
    )

    if module.params.get('op_type') == 'create':
      try:
        response = createClientProfile(
          node=module.params.get('localNode'),
          name=module.params.get('name'),
          app_connector_type=module.params.get('app_connector_type'),
          ca_id=module.params.get('ca_id'),
          cert_duration=module.params.get('cert_duration'),
          configurations=module.params.get('configurations'),
          csr_parameters=module.params.get('csr_parameters'),
          heartbeat_threshold=module.params.get('heartbeat_threshold'),
          lifetime=module.params.get('lifetime'),
          max_clients=module.params.get('max_clients'),
          nae_iface_port=module.params.get('nae_iface_port'),
          policy_id=module.params.get('policy_id'),
        )
        result['response'] = response
      except CMApiException as api_e:
        if api_e.api_error_code:
          module.fail_json(msg="status code: " + str(api_e.api_error_code) + " message: " + api_e.message)
      except AnsibleCMException as custom_e:
        module.fail_json(msg=custom_e.message)

    elif module.params.get('op_type') == 'patch':
      try:
        response = updateClientProfile(
          node=module.params.get('localNode'),
          profile_id=module.params.get('profile_id'),
          name=module.params.get('name'),
          app_connector_type=module.params.get('app_connector_type'),
          ca_id=module.params.get('ca_id'),
          configurations=module.params.get('configurations'),
          csr_parameters=module.params.get('csr_parameters'),
          heartbeat_threshold=module.params.get('heartbeat_threshold'),
          lifetime=module.params.get('lifetime'),
          max_clients=module.params.get('max_clients'),
          nae_iface_port=module.params.get('nae_iface_port'),
          policy_id=module.params.get('policy_id'),
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