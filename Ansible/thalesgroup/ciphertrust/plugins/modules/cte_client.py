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
from ansible_collections.thalesgroup.ciphertrust.plugins.module_utils.cte import createClient, patchClient, clientAddGuardPoint, unEnrollClient, deleteClients, deleteClientById, updateClientAuthBinaries, sendLDTPauseCmd, patchGuardPointCTEClient, unGuardPoints, updateGPEarlyAccess
from ansible_collections.thalesgroup.ciphertrust.plugins.module_utils.exceptions import CMApiException, AnsibleCMException

DOCUMENTATION = '''
---
module: cte_client
short_description: Manage CTE clients
description:
    - Create, manage, and perform operations on a CTE client
    - A client is a computer system where the data needs to be protected. A compatible CTE Agent software is installed on the client. The CTE Agent can protect data on the client or devices connected to it. A client can be associated with multiple GuardPoints for encryption of various paths. 
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
      choices: [create, patch, add_guard_point, unenroll, delete, delete_id, auth_binaries, ldt_pause, patch_guard_point, gp_unguard, gp_enable_early_access]
      required: true
      type: str
    id:
      description: CTE Client ID to be patched or updated
      type: str
    name:
      description: Name to uniquely identify the client. This name will be visible on the CipherTrust Manager. Also can be name of the CTE client to be unenrolled.
      type: str
    client_type:
      description: Type of CTE Client. The default value is FS. Valid values are CTE-U and FS.
      choices: [CTE-U, FS]
      type: str
    client_locked:
      description: Whether the CTE client is locked. The default value is false. Enable this option to lock the configuration of the CTE Agent on the client. Set to true to lock the configuration, set to false to unlock. Locking the Agent configuration prevents updates to any policies on the client.
      type: boolean
    communication_enabled:
      description: Whether communication with the client is enabled. The default value is false. Can be set to true only if registration_allowed is true
      type: boolean
    description:
      description: Description to identify the client.
      type: str
    password:
      description: Password for the client. Required when password_creation_method is MANUAL
      type: str
    password_creation_method:
      description: Password creation method for the client. Valid values are MANUAL and GENERATE. The default value is GENERATE.
      choices: [MANUAL, GENERATE]
      type: str
    profile_identifier:
      description: Identifier of the Client Profile to be associated with the client. If not provided, the default profile will be linked.
      type: str
    registration_allowed:
      description: Whether client's registration with the CipherTrust Manager is allowed. The default value is false. Set to true to allow registration.
      type: boolean
    system_locked:
      description: Whether the system is locked. The default value is false. Enable this option to lock the important operating system files of the client. When enabled, patches to the operating system of the client will fail due to the protection of these files.
      type: boolean
    user_space_client:
      description: TBD
      type: str
    client_mfa_enabled:
      description: Whether MFA is enabled on the client
      type: boolean
    del_client:
      description: Whether to mark the client for deletion from the CipherTrust Manager. The default value is false
      type: boolean
    disable_capability:
      description: Client capability to be disabled. Only EKP - Encryption Key Protection can be disabled
      type: str
    dynamic_parameters:
      description: Array of parameters to be updated after the client is registered. Specify the parameters in the name-value pair JSON format strings. Make sure to specify all the parameters even if you want to update one or more parameters.
      type: str
    enable_domain_sharing:
      description: Whether domain sharing is enabled for the client.
      type: boolean
    enabled_capabilities:
      description: Client capabilities to be enabled. Separate values with comma.
      choices: [LDT, EKP, ES]
      type: str
    max_num_cache_log:
      description: Maximum number of logs to cache
      type: int
    max_space_cache_log:
      description: Maximum space for the cached logs
      type: int
    profile_id:
      description: ID of the profile that contains logger, logging, and QOS configuration
      type: str
    shared_domain_list:
      description: List of domains in which the client needs to be shared
      type: list
      elements: str
    guard_paths:
      description: List of GuardPaths to be created.
      type: list
      elements: str
    guard_point_params:
      description: Parameters for creating a GuardPoint.
      type: dict
    client_id_list:
      description: IDs of the clients to be deleted. The IDs could be the name, ID (a UUIDv4), URI, or slug of the clients.
      type: list
      elements: str
    force_del_client:
      description:
        - Deletes the client forcefully from the CipherTrust Manager. Set the value to true.
        - WARNING! Use the force_del_client option with caution. It does not wait for any response from the CTE Agent before deleting the client's entry from the CipherTrust Manager. This action is irreversible.
      type: boolean
    auth_binaries:
      description: Array of authorized binaries in the privilege-filename pair JSON format.
      type: str
    client_auth_binaries_from:
      description: ID of the ClientGroup from which client settings will be inherited.
      type: str
    re_sign:
      description: Whether to re-sign the client settings.
      type: boolean
    paused:
      description: Suspend/resume the rekey operation on an LDT GuardPoint. Set the value to true to pause (suspend) the rekey. Set the value to false to resume rekey.
      type: boolean
    gp_id:
      description: Guard Point ID to be patched or updated within a CTE client
      type: str
    data_classification_enabled:
      description: Whether data classification (tagging) is enabled. Enabled by default if the aligned policy contains ClassificationTags. Supported for Standard and LDT policies.
      type: boolean
    data_lineage_enabled:
      description: Whether data lineage (tracking) is enabled. Enabled only if data classification is enabled. Supported for Standard and LDT policies
      type: boolean
    guard_enabled:
      description: Whether the GuardPoint is enabled.
      type: boolean
    mfa_enabled:
      description: Whether MFA is enabled
      type: boolean
    network_share_credentials_id:
      description: ID/Name of the credentials if the GuardPoint is applied to a network share. Supported for only LDT policies.
      type: str
    guard_point_id_list:
      description: IDs of the GuardPoints to be dissociated from the client. The IDs can be the name, ID (a UUIDv4), URI, or slug of the GuardPoints.
      type: list
      elements: str
    early_access:
      description: Whether to enable early access on the GuardPoint
      type: boolean
'''

EXAMPLES = '''
- name: "Create CTE Client"
  thalesgroup.ciphertrust.cte_client:
    localNode:
        server_ip: "IP/FQDN of CipherTrust Manager"
        server_private_ip: "Private IP in case that is different from above"
        server_port: 5432
        user: "CipherTrust Manager Username"
        password: "CipherTrust Manager Password"
        verify: false
    op_type: create
    name: "CTE-Client-Ans-001"
    description: "Created via Ansible"
    communication_enabled: false
    client_type: FS
  register: client

- name: "Add Guard Point to the CTE Client"
  thalesgroup.ciphertrust.cte_client:
    localNode:
        server_ip: "IP/FQDN of CipherTrust Manager"
        server_private_ip: "Private IP in case that is different from above"
        server_port: 5432
        user: "CipherTrust Manager Username"
        password: "CipherTrust Manager Password"
        verify: false
    op_type: add_guard_point
    guard_paths:
      - "/opt/path1/"
      - "/opt/path2/"
    guard_point_params:
      guard_point_type: directory_auto
      policy_id: TestPolicy
      data_classification_enabled: false
      data_lineage_enabled: false
      early_access: true
      preserve_sparse_regions: true
    id: "{{ client['response']['id'] }}"
'''

RETURN = '''

'''

_guard_point_params = dict(
  guard_point_type=dict(type='str', options=['directory_auto', 'directory_manual', 'rawdevice_manual', 'rawdevice_auto', 'cloudstorage_auto', 'cloudstorage_manual']),
  policy_id=dict(type='str'),
  automount_enabled=dict(type='bool'),
  cifs_enabled=dict(type='bool'),
  data_classification_enabled=dict(type='bool'),
  data_lineage_enabled=dict(type='bool'),
  disk_name=dict(type='str'),
  diskgroup_name=dict(type='str'),
  early_access=dict(type='bool'),
  intelligent_protection=dict(type='bool'),
  is_esg_capable_device=dict(type='bool'),
  is_idt_capable_device=dict(type='bool'),
  mfa_enabled=dict(type='bool'),
  network_share_credentials_id=dict(type='str'),
  preserve_sparse_regions=dict(type='bool'),
)

argument_spec = dict(
    op_type=dict(type='str', options=[
      'create', 
      'patch',
      'add_guard_point',
      'unenroll',
      'delete',
      'delete_id',
      'auth_binaries',
      'ldt_pause',
      'patch_guard_point',
      'gp_unguard',
      'gp_enable_early_access',
    ], required=True),
    id=dict(type='str'),
    name=dict(type='str'),
    client_type=dict(type='str', options=['CTE-U', 'FS']),
    client_locked=dict(type='bool'),
    communication_enabled=dict(type='bool'),    
    description=dict(type='str'),
    password=dict(type='str'),
    password_creation_method=dict(type='str', options=['GENERATE', 'MANUAL']),
    profile_identifier=dict(type='str'),
    registration_allowed=dict(type='bool'),
    system_locked=dict(type='bool'),
    user_space_client=dict(type='bool'),
    # Patch specific attributes
    client_mfa_enabled=dict(type='bool'),
    del_client=dict(type='bool'),
    disable_capability=dict(type='str'),
    dynamic_parameters=dict(type='str'),
    enable_domain_sharing=dict(type='bool'),
    enabled_capabilities=dict(type='str', options=['LDT', 'EKP', "ES"]),
    max_num_cache_log=dict(type='int'),
    max_space_cache_log=dict(type='int'),
    profile_id=dict(type='str'),
    shared_domain_list=dict(type='list', element='str'),
    # Params for adding guard paths to client
    guard_paths=dict(type='list', element='str'),
    guard_point_params=dict(type='dict', options=_guard_point_params),
    # Params for other ops on CTE client
    client_id_list=dict(type='list', element='str'),
    force_del_client=dict(type='bool'),
    auth_binaries=dict(type='str'),
    client_auth_binaries_from=dict(type='str'),
    re_sign=dict(type='bool'),
    paused=dict(type='bool'),
    gp_id=dict(type='str'),
    data_classification_enabled=dict(type='bool'),
    data_lineage_enabled=dict(type='bool'),
    guard_enabled=dict(type='bool'),
    mfa_enabled=dict(type='bool'),
    network_share_credentials_id=dict(type='str'),
    guard_point_id_list=dict(type='list', element='str'),
    early_access=dict(type='bool'),
)

def validate_parameters(cte_client_module):
    return True

def setup_module_object():
    module = ThalesCipherTrustModule(
        argument_spec=argument_spec,
        required_if=(
            ['op_type', 'create', ['name']],
            ['op_type', 'patch', ['id']],
            ['op_type', 'add_guard_point', ['id', 'guard_paths', 'guard_point_params']],
            ['op_type', 'unenroll', ['name']],
            ['op_type', 'delete', ['client_id_list']],
            ['op_type', 'delete_id', ['id']],
            ['op_type', 'auth_binaries', ['id']],
            ['op_type', 'ldt_pause', ['id', 'paused']],
            ['op_type', 'patch_guard_point', ['id', 'gp_id']],
            ['op_type', 'gp_unguard', ['id', 'guard_point_id_list']],
            ['op_type', 'gp_enable_early_access', ['id', 'gp_id', 'early_access']],
        ),
        mutually_exclusive=[],
        supports_check_mode=True,
    )
    return module

def main():

    global module
    
    module = setup_module_object()
    validate_parameters(
        cte_client_module=module,
    )

    result = dict(
        changed=False,
    )

    if module.params.get('op_type') == 'create':
      try:
        response = createClient(
          node=module.params.get('localNode'),
          name=module.params.get('name'),
          description=module.params.get('description'),
          client_locked=module.params.get('client_locked'),
          client_type=module.params.get('client_type'),
          communication_enabled=module.params.get('communication_enabled'),
          password=module.params.get('password'),
          password_creation_method=module.params.get('password_creation_method'),
          profile_identifier=module.params.get('profile_identifier'),
          registration_allowed=module.params.get('registration_allowed'),
          system_locked=module.params.get('system_locked'),
          #user_space_client=module.params.get('user_space_client'),
        )
        result['response'] = response
      except CMApiException as api_e:
        if api_e.api_error_code:
          module.fail_json(msg="status code: " + str(api_e.api_error_code) + " message: " + api_e.message)
      except AnsibleCMException as custom_e:
        module.fail_json(msg=custom_e.message)

    elif module.params.get('op_type') == 'patch':
      try:
        response = patchClient(
          node=module.params.get('localNode'),
          id=module.params.get('id'),
          client_locked=module.params.get('client_locked'),
          client_mfa_enabled=module.params.get('client_mfa_enabled'),
          communication_enabled=module.params.get('communication_enabled'),
          del_client=module.params.get('del_client'),
          description=module.params.get('description'),
          disable_capability=module.params.get('disable_capability'),
          dynamic_parameters=module.params.get('dynamic_parameters'),
          enable_domain_sharing=module.params.get('enable_domain_sharing'),
          enabled_capabilities=module.params.get('enabled_capabilities'),
          max_num_cache_log=module.params.get('max_num_cache_log'),
          max_space_cache_log=module.params.get('max_space_cache_log'),
          password=module.params.get('password'),
          password_creation_method=module.params.get('password_creation_method'),
          profile_id=module.params.get('profile_id'),
          registration_allowed=module.params.get('registration_allowed'),
          shared_domain_list=module.params.get('shared_domain_list'),
          system_locked=module.params.get('system_locked'),
        )
        result['response'] = response
      except CMApiException as api_e:
        if api_e.api_error_code:
          module.fail_json(msg="status code: " + str(api_e.api_error_code) + " message: " + api_e.message)
      except AnsibleCMException as custom_e:
        module.fail_json(msg=custom_e.message)

    elif module.params.get('op_type') == 'add_guard_point':
      try:
        response = clientAddGuardPoint(
          node=module.params.get('localNode'),
          id=module.params.get('id'),
          guard_paths=module.params.get('guard_paths'),
          guard_point_params=module.params.get('guard_point_params'),
        )
        result['response'] = response
      except CMApiException as api_e:
        if api_e.api_error_code:
          module.fail_json(msg="status code: " + str(api_e.api_error_code) + " message: " + api_e.message)
      except AnsibleCMException as custom_e:
        module.fail_json(msg=custom_e.message)

    elif module.params.get('op_type') == 'unenroll':
      try:
        response = unEnrollClient(
          node=module.params.get('localNode'),
          name=module.params.get('name'),
        )
        result['response'] = response
      except CMApiException as api_e:
        if api_e.api_error_code:
          module.fail_json(msg="status code: " + str(api_e.api_error_code) + " message: " + api_e.message)
      except AnsibleCMException as custom_e:
        module.fail_json(msg=custom_e.message)

    elif module.params.get('op_type') == 'delete':
      try:
        response = deleteClients(
          node=module.params.get('localNode'),
          client_id_list=module.params.get('client_id_list'),
        )
        result['response'] = response
      except CMApiException as api_e:
        if api_e.api_error_code:
          module.fail_json(msg="status code: " + str(api_e.api_error_code) + " message: " + api_e.message)
      except AnsibleCMException as custom_e:
        module.fail_json(msg=custom_e.message)

    elif module.params.get('op_type') == 'delete_id':
      try:
        response = deleteClientById(
          node=module.params.get('localNode'),
          id=module.params.get('id'),
          del_client=module.params.get('del_client'),
          force_del_client=module.params.get('force_del_client'),
        )
        result['response'] = response
      except CMApiException as api_e:
        if api_e.api_error_code:
          module.fail_json(msg="status code: " + str(api_e.api_error_code) + " message: " + api_e.message)
      except AnsibleCMException as custom_e:
        module.fail_json(msg=custom_e.message)

    elif module.params.get('op_type') == 'auth_binaries':
      try:
        response = updateClientAuthBinaries(
          node=module.params.get('localNode'),
          id=module.params.get('id'),
          auth_binaries=module.params.get('auth_binaries'),
          client_auth_binaries_from=module.params.get('client_auth_binaries_from'),
          re_sign=module.params.get('re_sign'),
        )
        result['response'] = response
      except CMApiException as api_e:
        if api_e.api_error_code:
          module.fail_json(msg="status code: " + str(api_e.api_error_code) + " message: " + api_e.message)
      except AnsibleCMException as custom_e:
        module.fail_json(msg=custom_e.message)

    elif module.params.get('op_type') == 'ldt_pause':
      try:
        response = sendLDTPauseCmd(
          node=module.params.get('localNode'),
          id=module.params.get('id'),
          paused=module.params.get('paused'),
        )
        result['response'] = response
      except CMApiException as api_e:
        if api_e.api_error_code:
          module.fail_json(msg="status code: " + str(api_e.api_error_code) + " message: " + api_e.message)
      except AnsibleCMException as custom_e:
        module.fail_json(msg=custom_e.message)

    elif module.params.get('op_type') == 'patch_guard_point':
      try:
        response = patchGuardPointCTEClient(
          node=module.params.get('localNode'),
          id=module.params.get('id'),
          gp_id=module.params.get('gp_id'),
          data_classification_enabled=module.params.get('data_classification_enabled'),
          data_lineage_enabled=module.params.get('data_lineage_enabled'),
          guard_enabled=module.params.get('guard_enabled'),
          mfa_enabled=module.params.get('mfa_enabled'),
          network_share_credentials_id=module.params.get('network_share_credentials_id'),
        )
        result['response'] = response
      except CMApiException as api_e:
        if api_e.api_error_code:
          module.fail_json(msg="status code: " + str(api_e.api_error_code) + " message: " + api_e.message)
      except AnsibleCMException as custom_e:
        module.fail_json(msg=custom_e.message)

    elif module.params.get('op_type') == 'gp_unguard':
      try:
        response = unGuardPoints(
          node=module.params.get('localNode'),
          id=module.params.get('id'),
          guard_point_id_list=module.params.get('guard_point_id_list'),
        )
        result['response'] = response
      except CMApiException as api_e:
        if api_e.api_error_code:
          module.fail_json(msg="status code: " + str(api_e.api_error_code) + " message: " + api_e.message)
      except AnsibleCMException as custom_e:
        module.fail_json(msg=custom_e.message)

    elif module.params.get('op_type') == 'gp_enable_early_access':
      try:
        response = updateGPEarlyAccess(
          node=module.params.get('localNode'),
          id=module.params.get('id'),
          gp_id=module.params.get('gp_id'),
          early_access=module.params.get('early_access'),
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