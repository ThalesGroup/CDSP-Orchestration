#!/usr/bin/python
# -*- coding: utf-8 -*-
#
# (c) 2023 Thales Group. All rights reserved.
# Author: Anurag Jain, Developer Advocate, Thales
#
# Licensed under the MIT License
#

from __future__ import absolute_import, division, print_function
__metaclass__ = type

from ansible_collections.thalesgroup.ctvl.plugins.module_utils.modules import ThalesCTVLModule
from ansible_collections.thalesgroup.ctvl.plugins.module_utils.commons import createCTVLAsset, patchCTVLAsset, deleteCTVLAsset
from ansible_collections.thalesgroup.ctvl.plugins.module_utils.exceptions import CTVLApiException, AnsibleCTVLException

DOCUMENTATION = '''
---
module: users
short_description: Create or update properties of a User on CT-VL
description:
    - This is a Thales CipherTrust Vaultless Tokenization module for working with the CT-VL CharacterSets APIs, create and update a User on the CT-VL platform
version_added: "1.0.0"
author: Anurag Jain, Developer Advocate Thales Group
options:
    server:
        description:
            - this holds the connection parameters required to communicate with an instance of CipherTrust vault less Tokenization server (CT-VL)
            - holds IP/FQDN of the server, username, password, and SSL verify flag 
        required: true
        type: dict
        suboptions:
          url:
            description: CM Server IP or FQDN
            type: str
            required: true
          username:
            description: API user of CT-VL
            type: str
            required: true
          password:
            description: Password for the CT-VL API user
            type: str
            required: true
          verify:
            description: if SSL verification is required
            type: bool
            required: true
            default: false     
    op_type:
        description: Operation to be performed on the CT-VL User
        choices: [create, update, reset_pwd, delete]
        required: true
        type: str
    id:
        description: CT-VL User ID to be updated or password to be reset
        type: str
    username:
        description: 150 characters or fewer. Letters, digits and @/./+/-/_ only.
        type: str
    email:
        description: User’s email
        type: str
    password:
        description: Password for the user
        type: str
    is_active:
        description: Designates whether this user should be treated as active. Unselect this instead of deleting accounts.
        type: bool
    is_staff:
        description: Designates whether the user can log into this admin site.
        type: bool
    is_superuser:
        description: Designates that this user has all permissions without explicitly assigning them.
        type: bool
    groups:
        description: Groups the user belongs to
        type: list
        elements: str
    ldap_user:
        description: Boolean value determining if it’s an AD user
        type: bool
    mask:
        description: Mask assigned to the user
        type: str
    admin_password:
        description: Password of the currently authenticated user (must be a superuser)
        type: str
    new_password:
        description: New password
        type: str
    new_password_confirm:
        description: Confirm new password
        type: str
'''

EXAMPLES = '''
- name: "Create User"
  thalesgroup.ctvl.users:
    server:
        url: "IP/FQDN of CT-VL instance"
        username: "API Username"
        password: "API User Password"
        verify: false
    op_type: create
    username: apiadmin
    email: test@example.com
    password: ChangeIt01!
    is_active: true
    is_staff: true
    is_superuser: true
    groups:
      - group-name
    mask: mask-name

- name: "Update User"
  thalesgroup.ctvl.users:
    server:
        url: "IP/FQDN of CT-VL instance"
        username: "API Username"
        password: "API User Password"
        verify: false
    op_type: update
    id: 2
    username: root
    email: root@example.com
    groups:
      - group_name
      - group2_name

- name: "Reset Password"
  thalesgroup.ctvl.users:
    server:
        url: "IP/FQDN of CT-VL instance"
        username: "API Username"
        password: "API User Password"
        verify: false
    op_type: reset_pwd
    id: 2
    admin_password: ChangeIt01!
    new_password: ChangeItAgain01!
    new_password_confirm: ChangeItAgain01!

- name: "Delete User"
  thalesgroup.ctvl.users:
    server:
        url: "IP/FQDN of CT-VL instance"
        username: "API Username"
        password: "API User Password"
        verify: false
    op_type: delete
    id: 2
'''

RETURN = '''
id:
    description: User ID
    returned: always
    type: int
    sample: 2
username:
    description: 150 characters or fewer. Letters, digits and @/./+/-/_ only.
    returned: changed
    type: str
    sample: 'root'
email:
    description: User’s email
    returned: changed
    type: str
    sample: 'root@example.com'
password:
    description: Password for the user
    type: str
    returned: changed
    sample: 'ChangeIt01!'
is_active:
    description: Designates whether this user should be treated as active. Unselect this instead of deleting accounts.
    type: bool
    returned: changed
    sample: true
is_staff:
    description: Designates whether the user can log into this admin site.
    type: bool
    returned: changed
    sample: true
is_superuser:
    description: Designates that this user has all permissions without explicitly assigning them.
    type: bool
    returned: changed
    sample: false
groups:
    description: Groups the user belongs to
    type: list
    elements: str
    returned: changed
    sample: ["roots"]
ldap_user:
    description: Boolean value determining if it’s an AD user
    type: bool
    returned: changed
    sample: false
mask:
    description: Mask assigned to the user
    type: str
    returned: changed
    sample: 'X'
admin_password:
    description: Password of the currently authenticated user (must be a superuser)
    type: str
    returned: changed
    sample: 'ChangeIt01!'
new_password:
    description: New password
    type: str
    returned: changed
    sample: 'ChangeItAgain01!'
new_password_confirm:
    description: Confirm new password
    type: str
    returned: changed
    sample: 'ChangeItAgain01!'
'''

argument_spec = dict(
    op_type=dict(type='str', options=['create', 'update', 'reset_pwd', 'delete'], required=True),
    id=dict(type='int'),
    username=dict(type='str'),
    email=dict(type='str'),
    password=dict(type='str'),
    is_active=dict(type='bool'),
    is_staff=dict(type='bool'),
    is_superuser=dict(type='bool'),
    groups=dict(type='list', element='str'),
    ldap_user=dict(type='bool'),
    mask=dict(type='str'),
    admin_password=dict(type='str'),
    new_password=dict(type='str'),
    new_password_confirm=dict(type='str'),
)

def validate_parameters(users_module):
    return True

def setup_module_object():
    module = ThalesCTVLModule(
        argument_spec=argument_spec,
        required_if=(
            ['op_type', 'update', ['id', 'username', 'email']],
            ['op_type', 'create', ['username', 'email']],
            ['op_type', 'reset_pwd', ['id', 'admin_password', 'new_password', 'new_password_confirm']],
            ['op_type', 'delete', ['id']],
        ),
        mutually_exclusive=[],
        supports_check_mode=True,
    )
    return module

def main():

    global module
    
    module = setup_module_object()
    validate_parameters(
        users_module=module,
    )

    result = dict(
        changed=False,
    )

    if module.params.get('op_type') == 'create':
      try:
        response = createCTVLAsset(
          server=module.params.get('server'),
          type='user',
          username=module.params.get('username'),
          email=module.params.get('email'),
          password=module.params.get('password'),
          is_active=module.params.get('is_active'),
          is_staff=module.params.get('is_staff'),
          is_superuser=module.params.get('is_superuser'),
          groups=module.params.get('groups'),
          ldap_user=module.params.get('ldap_user'),
          mask=module.params.get('mask'),
        )
        result['response'] = response
      except CTVLApiException as api_e:
        if api_e.api_error_code:
          module.fail_json(msg="status code: " + str(api_e.api_error_code) + " message: " + api_e.message)
      except AnsibleCTVLException as custom_e:
        module.fail_json(msg=custom_e.message)

    elif module.params.get('op_type') == 'update':
      try:
        response = patchCTVLAsset(
          server=module.params.get('server'),
          type='user',
          id=module.params.get('id'),
          username=module.params.get('username'),
          email=module.params.get('email'),
          password=module.params.get('password'),
          is_active=module.params.get('is_active'),
          is_staff=module.params.get('is_staff'),
          is_superuser=module.params.get('is_superuser'),
          groups=module.params.get('groups'),
          ldap_user=module.params.get('ldap_user'),
          mask=module.params.get('mask'),
        )
        result['response'] = response
      except CTVLApiException as api_e:
        if api_e.api_error_code:
          module.fail_json(msg="status code: " + str(api_e.api_error_code) + " message: " + api_e.message)
      except AnsibleCTVLException as custom_e:
        module.fail_json(msg=custom_e.message)

    elif module.params.get('op_type') == 'reset_pwd':
      try:
        response = patchCTVLAsset(
          server=module.params.get('server'),
          type='user',
          id=module.params.get('id'),
          admin_password=module.params.get('admin_password'),
          new_password=module.params.get('new_password'),
          new_password_confirm=module.params.get('new_password_confirm'),
        )
        result['response'] = response
      except CTVLApiException as api_e:
        if api_e.api_error_code:
          module.fail_json(msg="status code: " + str(api_e.api_error_code) + " message: " + api_e.message)
      except AnsibleCTVLException as custom_e:
        module.fail_json(msg=custom_e.message)

    elif module.params.get('op_type') == 'delete':
      try:
        response = deleteCTVLAsset(
          server=module.params.get('server'),
          type='user',
          id=module.params.get('id'),
        )
        result['response'] = response
      except CTVLApiException as api_e:
        if api_e.api_error_code:
          module.fail_json(msg="status code: " + str(api_e.api_error_code) + " message: " + api_e.message)
      except AnsibleCTVLException as custom_e:
        module.fail_json(msg=custom_e.message)

    else:
        module.fail_json(msg="invalid op_type")
        
    module.exit_json(**result)

if __name__ == '__main__':
    main()