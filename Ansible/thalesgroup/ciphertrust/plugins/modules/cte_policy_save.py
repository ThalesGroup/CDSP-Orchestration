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
from ansible_collections.thalesgroup.ciphertrust.plugins.module_utils.cte import createCTEPolicy, ctePolicyAddRule, updateCTEPolicy, ctePolicyPatchRule, ctePolicyDeleteRule
from ansible_collections.thalesgroup.ciphertrust.plugins.module_utils.exceptions import CMApiException, AnsibleCMException

DOCUMENTATION = '''
---
module: dpg_policy_save
short_description: Manage policies as collection of rules that govern data access and encryption
description:
    - This is a Thales CipherTrust Manager module for working with the CipherTrust Manager APIs, more specifically with CTE Policy API
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
      choices: [create, patch, add_data_transfer_rule, add_ldt_rule, add_key_rule, add_security_rule, patch_data_transfer_rule, patch_ldt_rule, patch_key_rule, patch_security_rule, patch_idt_rule, remove_data_transfer_rule, remove_ldt_rule, remove_key_rule, remove_security_rule]
      required: true
      type: str
    policy_id:
      description:
        - Identifier of the CTE Policy to be patched or rules to be patched or removed
      type: str
    name:
      description: Name of the CTE policy
      type: str
      required: false
    description:
      description: Description of the CTE policy
      type: str
      required: false
    policy_type:
      description: Type of the policy
      choices: [Standard, LDT, IDT, CSI, Cloud_Object_Storage]
      type: str
    data_transform_rules:
      description: Data transformation rules to link with the policy
      type: list
      elements: dict
    idt_key_rules:
      description: IDT rules to link with the policy
      type: list
      elements: dict
    key_rules:
      description: Key rules to link with the policy
      type: list
      elements: dict
    ldt_key_rules:
      description: LDT rules to link with the policy. Supported for LDT policies.
      type: list
      elements: dict
    metadata:
      description: Restrict policy for modification
      type: dict
    never_deny:
      description: Whether to always allow operations in the policy. By default, it is disabled, that is, operations are not allowed. Supported for Standard, LDT, and Cloud_Object_Storage policies. For Learn Mode activations, never_deny is set to true, by default.
      type: bool
    security_rules:
      description: Security rules to link with the policy.
      type: list
      elements: dict
    force_restrict_update:
      description: To remove restriction of policy for modification
      type: bool
    order_number:
      description: Precedence order of the rule in the parent policy
      type: int
    key_id:
      description: Identifier of the key to link with the rule. Supported fields are name, id, slug, alias, uri, uuid, muid, and key_id.
      type: str
    key_type:
      description: Precedence order of the rule in the parent policy
      choices: [name, id, slug, alias, uri, uuid, muid, key_id]
      type: str
    resource_set_id:
      description: ID of the resource set linked with the rule
      type: str
    dataTxRuleId:
      description: An identifier for the CTE Data-Transformation Rule. Can be an ID of type UUIDv4 or a URI
      type: str
    keyRuleId:
      description: An identifier for the CTE Key Rule. Can be an ID of type UUIDv4 or a URI
      type: str
    current_keys:
      description: Properties of the current key
      type: dict
    is_exclusion_rule:
      description: Whether this is an exclusion rule. If enabled, no need to specify the transformation rule.
      type: bool
    transformation_keys:
      description: Properties of the transformation key
      type: dict
    ldtRuleId:
      description: An identifier for the CTE LDT Key Rule. Can be an ID of type UUIDv4 or a URI
      type: str
    action:
      description: Actions applicable to the rule. Examples of actions are read, write, all_ops, and key_op.
      choices: [read, write, all_ops, key_op]
      type: str
    effect:
      description: Effects applicable to the rule. Separate multiple effects by commas.
      choices: [permit, deny, audit, applykey]
      type: str
    exclude_process_set:
      description: Process set to exclude. Supported for Standard and LDT policies.
      type: bool
    exclude_resource_set:
      description: Resource set to exclude. Supported for Standard and LDT policies.
      type: bool
    exclude_user_set:
      description: User set to exclude. Supported for Standard and LDT policies.
      type: bool
    partial_match:
      description: Whether to allow partial match operations. By default, it is enabled. Supported for Standard and LDT policies.
      type: bool
    process_set_id:
      description: ID of the process set to link to the policy.
      type: str
    user_set_id:
      description: ID of the resource set to link to the policy. Supported for Standard and LDT policies
      type: str
    securityRuleId:
      description: An identifier for the CTE Security Rule. Can be an ID of type UUIDv4 or a URI
      type: str
    idtRuleId:
      description: An identifier for the CTE IDT Key Rule. Can be an ID of type UUIDv4 or a URI
      type: str
    current_key:
      description: Identifier of the key to link with the rule. Supported fields are name, id, slug, alias, uri, uuid, muid, and key_id.
      type: str
    current_key_type:
      description: An identifier for the CTE IDT Key Rule. Can be an ID of type UUIDv4 or a URI
      choices: [name, id, slug, alias, uri, uuid, muid, key_id]
      type: str
    transformation_key:
      description: Identifier of the key to link with the rule. Supported fields are name, id, slug, alias, uri, uuid, muid or key_id.
      type: str
    transformation_key_type:
      description: Specify the type of the key. Must be one of name, id, slug, alias, uri, uuid, muid or key_id. If not specified, the type of the key is inferred.
      choices: [name, id, slug, alias, uri, uuid, muid, key_id]
      type: str
'''

EXAMPLES = '''
- name: "Create CTE Policy"
  thalesgroup.ciphertrust.dpg_policy_save:
    localNode:
        server_ip: "IP/FQDN of CipherTrust Manager"
        server_private_ip: "Private IP in case that is different from above"
        server_port: 5432
        user: "CipherTrust Manager Username"
        password: "CipherTrust Manager Password"
        verify: false
    op_type: create
    name: "Policy-Ans-001"
    description: "Created via Ansible"
    never_deny: false
    metadata:
      restrict_update: false
    security_rules:
      - action: key_op
        effect: "permit,applykey"
        partial_match: true
      - resource_set_id: RS-Ans-001
        exclude_resource_set: false
        partial_match: true
        action: all_ops
        effect: "permit,audit,applykey"
    policy_type: Standard
    key_rules:
      - key_id: CTE_standard_pol_key
        resource_set_id: RS-Ans-001
    data_transform_rules:
      - key_id: CTE_standard_pol_key
        resource_set_id: RS-Ans-001
    name: Ansible-CTE-Policy-001
    description: "Created using Ansible"
  register: policy

- name: "Add new data transformation rule to a CTE Policy"
  thalesgroup.ciphertrust.dpg_policy_save:
    localNode:
        server_ip: "IP/FQDN of CipherTrust Manager"
        server_private_ip: "Private IP in case that is different from above"
        server_port: 5432
        user: "CipherTrust Manager Username"
        password: "CipherTrust Manager Password"
        verify: false
    op_type: add_data_transfer_rule
    policy_id: "{{ policy['response']['id'] }}"
    rule_name="datatxrules"
    key_id=key_id: CTE_standard_pol_key
    resource_set_id: RS-Ans-002
  register: datatxrule

- name: "Delete a data transformation rule from a CTE Policy"
  thalesgroup.ciphertrust.dpg_policy_save:
    localNode:
        server_ip: "IP/FQDN of CipherTrust Manager"
        server_private_ip: "Private IP in case that is different from above"
        server_port: 5432
        user: "CipherTrust Manager Username"
        password: "CipherTrust Manager Password"
        verify: false
    op_type: remove_data_transfer_rule
    policy_id: "{{ policy['response']['id'] }}"
    rule_name="datatxrules"
    rule_id="{{ datatxrule['response']['id'] }}"
'''

RETURN = '''

'''

_data_transform_rules = dict(
   key_id=dict(type='str'),
   key_type=dict(type='str', options=['name', 'id', 'slug', 'alias', 'uri', 'uuid', 'muid', 'key_id']),
   resource_set_id=dict(type='str'),
)

_idt_key_rules = dict(
   current_key=dict(type='str'),
   current_key_type=dict(type='str', options=['name', 'id', 'slug', 'alias', 'uri', 'uuid', 'muid', 'key_id']),
   transformation_key=dict(type='str'),
   transformation_key_type=dict(type='str', options=['name', 'id', 'slug', 'alias', 'uri', 'uuid', 'muid', 'key_id']),
)

_key_rules = dict(
   key_id=dict(type='str'),
   key_type=dict(type='str', options=['name', 'id', 'slug', 'alias', 'uri', 'uuid', 'muid', 'key_id']),
   resource_set_id=dict(type='str'),
)

_current_key = dict(
   key_id=dict(type='str'),
   key_type=dict(type='str', options=['name', 'id', 'slug', 'alias', 'uri', 'uuid', 'muid', 'key_id']),
)
_transformation_key = dict(
   key_id=dict(type='str'),
   key_type=dict(type='str', options=['name', 'id', 'slug', 'alias', 'uri', 'uuid', 'muid', 'key_id']),
)

_ldt_key_rules = dict(
   current_key=dict(type='dict', options=_current_key),
   is_exclusion_rule=dict(type='bool'),
   resource_set_id=dict(type='str'),
   transformation_key=dict(type='dict', options=_transformation_key),
)

_metadata = dict(
    restrict_update=dict(type='bool'),
)

_security_rules = dict(
    action=dict(type='str', options=['read', 'write', 'all_ops', 'key_op']),
    effect=dict(type='str', options=['permit', 'deny', 'audit', 'applykey']),
    exclude_process_set=dict(type='bool'),
    exclude_resource_set=dict(type='bool'),
    exclude_user_set=dict(type='bool'),
    partial_match=dict(type='bool'),
    process_set_id=dict(type='str'),
    resource_set_id=dict(type='str'),
    user_set_id=dict(type='str'),
)

argument_spec = dict(
    op_type=dict(type='str', options=[
      'create', 
      'patch', 
      'add_data_transfer_rule', 
      'add_ldt_rule', 
      'add_key_rule', 
      'add_security_rule',
      'patch_data_transfer_rule', 
      'patch_ldt_rule', 
      'patch_key_rule', 
      'patch_security_rule',
      'patch_idt_rule',
      'remove_data_transfer_rule', 
      'remove_ldt_rule', 
      'remove_key_rule', 
      'remove_security_rule',
    ], required=True),
    policy_id=dict(type='str'),
    name=dict(type='str'),
    policy_type=dict(type='str', options=['Standard', 'LDT', 'IDT', 'CSI', 'Cloud_Object_Storage']),
    data_transform_rules=dict(type='list', element='dict', options=_data_transform_rules),
    description=dict(type='str'),
    idt_key_rules=dict(type='list', element='dict', options=_idt_key_rules),
    key_rules=dict(type='list', element='dict', options=_key_rules),
    ldt_key_rules=dict(type='list', element='dict', options=_ldt_key_rules),
    metadata=dict(type='dict', options=_metadata),
    never_deny=dict(type='bool'),
    security_rules=dict(type='list', element='dict', options=_security_rules),
    force_restrict_update=dict(type='bool'),
    order_number=dict(type='int'),
    # params for op_type add_data_transfer_rule
    key_id=dict(type='str'),
    key_type=dict(type='str', options=['name', 'id', 'slug', 'alias', 'uri', 'uuid', 'muid', 'key_id']),
    resource_set_id=dict(type='str'),
    dataTxRuleId=dict(type='str'),
    keyRuleId=dict(type='str'),
    # params for op_type add_ldt_rule
    current_keys=dict(type='dict', options=_current_key),
    is_exclusion_rule=dict(type='bool'),
    transformation_keys=dict(type='dict', options=_transformation_key),
    ldtRuleId=dict(type='str'),
    # params for op_type add_security_rule
    action=dict(type='str', options=['read', 'write', 'all_ops', 'key_op']),
    effect=dict(type='str', options=['permit', 'deny', 'audit', 'applykey']),
    exclude_process_set=dict(type='bool'),
    exclude_resource_set=dict(type='bool'),
    exclude_user_set=dict(type='bool'),
    partial_match=dict(type='bool'),
    process_set_id=dict(type='str'),
    user_set_id=dict(type='str'),
    securityRuleId=dict(type='str'),
    # params for op_type patch_idt_rule
    idtRuleId=dict(type='str'),
    current_key=dict(type='str'),
    current_key_type=dict(type='str', options=['name', 'id', 'slug', 'alias', 'uri', 'uuid', 'muid', 'key_id']),
    transformation_key=dict(type='str'),
    transformation_key_type=dict(type='str', options=['name', 'id', 'slug', 'alias', 'uri', 'uuid', 'muid', 'key_id']),
)

def validate_parameters(cte_policy_module):
    return True

def setup_module_object():
    module = ThalesCipherTrustModule(
        argument_spec=argument_spec,
        required_if=(
            ['op_type', 'patch', ['policy_id']],
            ['op_type', 'add_data_transfer_rule', ['policy_id', 'key_id']],
            ['op_type', 'add_ldt_rule', ['policy_id', 'current_keys']],
            ['op_type', 'add_key_rule', ['policy_id', 'key_id']],
            ['op_type', 'add_security_rule', ['policy_id', 'effect']],
            ['op_type', 'create', ['name', 'policy_type']],
            ['op_type', 'patch_data_transfer_rule', ['policy_id', 'dataTxRuleId']],
            ['op_type', 'patch_ldt_rule', ['policy_id', 'ldtRuleId']],
            ['op_type', 'patch_key_rule', ['policy_id', 'keyRuleId']],
            ['op_type', 'patch_security_rule', ['policy_id', 'securityRuleId']],
            ['op_type', 'patch_idt_rule', ['policy_id', 'idtRuleId']],
            ['op_type', 'remove_data_transfer_rule', ['policy_id', 'dataTxRuleId']],
            ['op_type', 'remove_ldt_rule', ['policy_id', 'ldtRuleId']],
            ['op_type', 'remove_key_rule', ['policy_id', 'keyRuleId']],
            ['op_type', 'remove_security_rule', ['policy_id', 'securityRuleId']],
        ),
        mutually_exclusive=[],
        supports_check_mode=True,
    )
    return module

def main():

    global module
    
    module = setup_module_object()
    validate_parameters(
        cte_policy_module=module,
    )

    result = dict(
        changed=False,
    )

    if module.params.get('op_type') == 'create':
      try:
        response = createCTEPolicy(
          node=module.params.get('localNode'),
          name=module.params.get('name'),
          description=module.params.get('description'),
          policy_type=module.params.get('policy_type'),
          data_transform_rules=module.params.get('data_transform_rules'),
          idt_key_rules=module.params.get('idt_key_rules'),
          key_rules=module.params.get('key_rules'),
          ldt_key_rules=module.params.get('ldt_key_rules'),
          metadata=module.params.get('metadata'),
          never_deny=module.params.get('never_deny'),
          security_rules=module.params.get('security_rules'),
        )
        result['response'] = response
      except CMApiException as api_e:
        if api_e.api_error_code:
          module.fail_json(msg="status code: " + str(api_e.api_error_code) + " message: " + api_e.message)
      except AnsibleCMException as custom_e:
        module.fail_json(msg=custom_e.message)

    elif module.params.get('op_type') == 'patch':
      try:
        response = updateCTEPolicy(
          node=module.params.get('localNode'),
          policy_id=module.params.get('policy_id'),
          description=module.params.get('description'),
          force_restrict_update=module.params.get('force_restrict_update'),
          metadata=module.params.get('metadata'),
          never_deny=module.params.get('never_deny'),
        )
        result['response'] = response
      except CMApiException as api_e:
        if api_e.api_error_code:
          module.fail_json(msg="status code: " + str(api_e.api_error_code) + " message: " + api_e.message)
      except AnsibleCMException as custom_e:
        module.fail_json(msg=custom_e.message)

    elif module.params.get('op_type') == 'add_data_transfer_rule':
      try:
        response = ctePolicyAddRule(
          node=module.params.get('localNode'),
          policy_id=module.params.get('policy_id'),
          rule_name="datatxrules",
          key_id=module.params.get('key_id'),
          key_type=module.params.get('key_type'),
          resource_set_id=module.params.get('resource_set_id'),
        )
        result['response'] = response
      except CMApiException as api_e:
        if api_e.api_error_code:
          module.fail_json(msg="status code: " + str(api_e.api_error_code) + " message: " + api_e.message)
      except AnsibleCMException as custom_e:
        module.fail_json(msg=custom_e.message)

    elif module.params.get('op_type') == 'add_key_rule':
      try:
        response = ctePolicyAddRule(
          node=module.params.get('localNode'),
          policy_id=module.params.get('policy_id'),
          rule_name="keyrules",
          key_id=module.params.get('key_id'),
          key_type=module.params.get('key_type'),
          resource_set_id=module.params.get('resource_set_id'),
        )
        result['response'] = response
      except CMApiException as api_e:
        if api_e.api_error_code:
          module.fail_json(msg="status code: " + str(api_e.api_error_code) + " message: " + api_e.message)
      except AnsibleCMException as custom_e:
        module.fail_json(msg=custom_e.message)

    elif module.params.get('op_type') == 'add_ldt_rule':
      try:
        response = ctePolicyAddRule(
          node=module.params.get('localNode'),
          policy_id=module.params.get('policy_id'),
          rule_name="ldtkeyrules",
          current_key=module.params.get('current_keys'),
          is_exclusion_rule=module.params.get('is_exclusion_rule'),
          resource_set_id=module.params.get('resource_set_id'),
          transformation_key=module.params.get('transformation_keys'),
        )
        result['response'] = response
      except CMApiException as api_e:
        if api_e.api_error_code:
          module.fail_json(msg="status code: " + str(api_e.api_error_code) + " message: " + api_e.message)
      except AnsibleCMException as custom_e:
        module.fail_json(msg=custom_e.message)

    elif module.params.get('op_type') == 'add_security_rule':
      try:
        response = ctePolicyAddRule(
          node=module.params.get('localNode'),
          policy_id=module.params.get('policy_id'),
          rule_name="securityrules",
          effect=module.params.get('effect'),
          action=module.params.get('action'),
          exclude_process_set=module.params.get('exclude_process_set'),
          exclude_resource_set=module.params.get('exclude_resource_set'),
          exclude_user_set=module.params.get('exclude_user_set'),
          partial_match=module.params.get('partial_match'),
          process_set_id=module.params.get('process_set_id'),
          resource_set_id=module.params.get('resource_set_id'),
          user_set_id=module.params.get('user_set_id'),
        )
        result['response'] = response
      except CMApiException as api_e:
        if api_e.api_error_code:
          module.fail_json(msg="status code: " + str(api_e.api_error_code) + " message: " + api_e.message)
      except AnsibleCMException as custom_e:
        module.fail_json(msg=custom_e.message)

    elif module.params.get('op_type') == 'patch_data_transfer_rule':
      try:
        response = ctePolicyPatchRule(
          node=module.params.get('localNode'),
          policy_id=module.params.get('policy_id'),
          rule_name="datatxrules",
          rule_id=module.params.get('dataTxRuleId'),
          key_id=module.params.get('key_id'),
          key_type=module.params.get('key_type'),
          resource_set_id=module.params.get('resource_set_id'),
          order_number=module.params.get('order_number'),
        )
        result['response'] = response
      except CMApiException as api_e:
        if api_e.api_error_code:
          module.fail_json(msg="status code: " + str(api_e.api_error_code) + " message: " + api_e.message)
      except AnsibleCMException as custom_e:
        module.fail_json(msg=custom_e.message)

    elif module.params.get('op_type') == 'patch_key_rule':
      try:
        response = ctePolicyPatchRule(
          node=module.params.get('localNode'),
          policy_id=module.params.get('policy_id'),
          rule_name="keyrules",
          rule_id=module.params.get('keyRuleId'),
          key_id=module.params.get('key_id'),
          key_type=module.params.get('key_type'),
          resource_set_id=module.params.get('resource_set_id'),
          order_number=module.params.get('order_number'),
        )
        result['response'] = response
      except CMApiException as api_e:
        if api_e.api_error_code:
          module.fail_json(msg="status code: " + str(api_e.api_error_code) + " message: " + api_e.message)
      except AnsibleCMException as custom_e:
        module.fail_json(msg=custom_e.message)

    elif module.params.get('op_type') == 'patch_ldt_rule':
      try:
        response = ctePolicyPatchRule(
          node=module.params.get('localNode'),
          policy_id=module.params.get('policy_id'),
          rule_name="ldtkeyrules",
          rule_id=module.params.get('ldtRuleId'),
          order_number=module.params.get('order_number'),
          current_key=module.params.get('current_keys'),
          is_exclusion_rule=module.params.get('is_exclusion_rule'),
          resource_set_id=module.params.get('resource_set_id'),
          transformation_key=module.params.get('transformation_keys'),
        )
        result['response'] = response
      except CMApiException as api_e:
        if api_e.api_error_code:
          module.fail_json(msg="status code: " + str(api_e.api_error_code) + " message: " + api_e.message)
      except AnsibleCMException as custom_e:
        module.fail_json(msg=custom_e.message)

    elif module.params.get('op_type') == 'patch_security_rule':
      try:
        response = ctePolicyPatchRule(
          node=module.params.get('localNode'),
          policy_id=module.params.get('policy_id'),
          rule_name="securityrules",
          rule_id=module.params.get('securityRuleId'),
          order_number=module.params.get('order_number'),
          effect=module.params.get('effect'),
          action=module.params.get('action'),
          exclude_process_set=module.params.get('exclude_process_set'),
          exclude_resource_set=module.params.get('exclude_resource_set'),
          exclude_user_set=module.params.get('exclude_user_set'),
          partial_match=module.params.get('partial_match'),
          process_set_id=module.params.get('process_set_id'),
          resource_set_id=module.params.get('resource_set_id'),
          user_set_id=module.params.get('user_set_id'),
        )
        result['response'] = response
      except CMApiException as api_e:
        if api_e.api_error_code:
          module.fail_json(msg="status code: " + str(api_e.api_error_code) + " message: " + api_e.message)
      except AnsibleCMException as custom_e:
        module.fail_json(msg=custom_e.message)

    elif module.params.get('op_type') == 'patch_idt_rule':
      try:
        response = ctePolicyPatchRule(
          node=module.params.get('localNode'),
          policy_id=module.params.get('policy_id'),
          rule_name="idtkeyrules",
          current_key=module.params.get('current_key'),
          current_key_type=module.params.get('current_key_type'),
          transformation_key=module.params.get('transformation_key'),
          transformation_key_type=module.params.get('transformation_key_type'),
          rule_id=module.params.get('idtRuleId'),
        )
        result['response'] = response
      except CMApiException as api_e:
        if api_e.api_error_code:
          module.fail_json(msg="status code: " + str(api_e.api_error_code) + " message: " + api_e.message)
      except AnsibleCMException as custom_e:
        module.fail_json(msg=custom_e.message)

    elif module.params.get('op_type') == 'remove_data_transfer_rule':
      try:
        response = ctePolicyDeleteRule(
          node=module.params.get('localNode'),
          policy_id=module.params.get('policy_id'),
          rule_name="datatxrules",
          rule_id=module.params.get('dataTxRuleId'),
        )
        result['response'] = response
      except CMApiException as api_e:
        if api_e.api_error_code:
          module.fail_json(msg="status code: " + str(api_e.api_error_code) + " message: " + api_e.message)
      except AnsibleCMException as custom_e:
        module.fail_json(msg=custom_e.message)

    elif module.params.get('op_type') == 'remove_ldt_rule':
      try:
        response = ctePolicyDeleteRule(
          node=module.params.get('localNode'),
          policy_id=module.params.get('policy_id'),
          rule_name="ldtkeyrules",
          rule_id=module.params.get('ldtRuleId'),
        )
        result['response'] = response
      except CMApiException as api_e:
        if api_e.api_error_code:
          module.fail_json(msg="status code: " + str(api_e.api_error_code) + " message: " + api_e.message)
      except AnsibleCMException as custom_e:
        module.fail_json(msg=custom_e.message)

    elif module.params.get('op_type') == 'remove_key_rule':
      try:
        response = ctePolicyDeleteRule(
          node=module.params.get('localNode'),
          policy_id=module.params.get('policy_id'),
          rule_name="keyrules",
          rule_id=module.params.get('keyRuleId'),
        )
        result['response'] = response
      except CMApiException as api_e:
        if api_e.api_error_code:
          module.fail_json(msg="status code: " + str(api_e.api_error_code) + " message: " + api_e.message)
      except AnsibleCMException as custom_e:
        module.fail_json(msg=custom_e.message)

    elif module.params.get('op_type') == 'remove_security_rule':
      try:
        response = ctePolicyDeleteRule(
          node=module.params.get('localNode'),
          policy_id=module.params.get('policy_id'),
          rule_name="securityrules",
          rule_id=module.params.get('securityRuleId'),
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