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
from ansible_collections.thalesgroup.ciphertrust.plugins.module_utils.users import create, patch, changepw, patch_self
from ansible_collections.thalesgroup.ciphertrust.plugins.module_utils.exceptions import CMApiException, AnsibleCMException

module = None

DOCUMENTATION = '''
---
module: usermgmt_users_save
short_description: Create and manage users in CipherTrust Manager
description:
    - This is a Thales CipherTrust Manager module for working with the CipherTrust Manager APIs, more specifically with user management API
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
        choices: [create, patch, changepw, patch_self]
        required: true
        type: str
    cm_user_id:
        description: CM user ID of the user that needs to be patched. Only required if the op_type is patch
        type: str
    allowed_auth_methods:
        description: 
          - List of login authentication methods allowed to the user.
          - Default value - ["password"] i.e. Password Authentication is allowed by default.
          - Setting it to empty, i.e [], means no authentication method is allowed to the user.
          - If both enable_cert_auth and allowed_auth_methods are provided in the request, enable_cert_auth is ignored.
        type: list
    app_metadata:
        description: A schema-less object, which can be used by applications to store information about the resource. app_metadata is typically used by applications to store information which the end-users are not themselves allowed to change, like group membership or security roles.
        required: false
        type: dict
        default: null
    certificate_subject_dn:
        description: The Distinguished Name of the user in certificate
        required: false
        type: str
    connection:
        description: This attribute is required to create a user, but is not included in user resource responses. Can be the name of a connection or "local_account" for a local user, defaults to "local_account".
        required: false
        type: str
        default: null
    email:
        description: E-mail of the user
        required: false
        type: str
    enable_cert_auth:
        description: 
          - Deprecated
          - Use allowed_auth_methods instead.
          - If both enable_cert_auth and allowed_auth_methods are provided in the request, enable_cert_auth is ignored.
          - Enable certificate based authentication flag. If set to true, the user will be able to login using certificate.
        required: false
        type: bool
    is_domain_user:
        description: This flag can be used to create the user in a non-root domain where user management is allowed.
        required: false
        type: bool
    login_flags:
        description: Flags for controlling user's login behavior.
        required: false
        type: dict
        suboptions:
          prevent_ui_login:
            description: 
              - If true, user is not allowed to login from Web UI. 
              - Default - false
            required: false
            type: bool
    name:
        description: Full name of the user.
        required: false
        type: str
    password:
        description: 
          - The password used to secure the users account. Allowed passwords are defined by the password policy.
          - Password is optional when "certificate_subject_dn" is set and "user_certificate" is in allowed_auth_methods.In all other cases, password is required
          - It is not included in user resource responses.
        required: false
        type: str
    password_change_required:
        description: Password change required flag. If set to true, user will be required to change their password on next successful login.
        required: false
        type: bool
    user_id:
        description: The user_id is the ID of an existing root domain user. This field is used only when adding an existing root domain user to a different domain.
        required: false
        type: str
    user_metadata:
        description: A schema-less object, which can be used by applications to store information about the resource. user_metadata is typically used by applications to store information about the resource which the end-users are allowed to modify, such as user preferences.
        required: false
        type: dict
        default: null
    username:
        description: 
          - The login name of the user. This is the identifier used to login. 
          - This attribute is required to create a user, but is omitted when getting or listing user resources. It cannot be updated. 
          - This attribute may also be used (instead of the user_id) when adding an existing root domain user to a different domain.
          - Mandatory for create operation
        type: str
    failed_logins_count:
        description: Set it to 0 to unlock a locked user account.
        required: false
        type: int
    new_password:
        description: 
          - the new password
          - mandatory for changepw op_type
        type: str
    auth_domain:
        description: 
          - The domain where user needs to be authenticated. This is the domain where user is created. Defaults to the root domain.
          - required only for changew op_type, not mandatory though
        type: str
'''

EXAMPLES = '''
- name: "Create new user"
    thalesgroup.ciphertrust.usermgmt_users_save:
      localNode: 
        server_ip: "IP/FQDN of CipherTrust Manager"
        server_private_ip: "Private IP in case that is different from above"
        server_port: 5432
        user: "CipherTrust Manager Username"
        password: "CipherTrust Manager Password"
        verify: false
      op_type: "create"
      username: "john.doe"
      password: "oldPassword12!"
      email: "john.doe@example.com"
      name: "John Doe"

- name: "Update user info"
    thalesgroup.ciphertrust.usermgmt_users_save:
      localNode: 
        server_ip: "IP/FQDN of CipherTrust Manager"
        server_private_ip: "Private IP in case that is different from above"
        server_port: 5432
        user: "CipherTrust Manager Username"
        password: "CipherTrust Manager Password"
        verify: false
      op_type: "patch"
      cm_user_id: "local|UUID"
      username: "john.doe"
      email: "aj@example.com"
      name: "New Name"

- name: "Change user password"
    thalesgroup.ciphertrust.usermgmt_users_save:
      localNode: 
        server_ip: "IP/FQDN of CipherTrust Manager"
        server_private_ip: "Private IP in case that is different from above"
        server_port: 5432
        user: "CipherTrust Manager Username"
        password: "CipherTrust Manager Password"
        verify: false
      op_type: "changepw"
      username: "john.doe"
      password: "oldPassword12!"
      new_password: "newPassword12!"

- name: "Update self"
    thalesgroup.ciphertrust.usermgmt_users_save:
      localNode: 
        server_ip: "IP/FQDN of CipherTrust Manager"
        server_private_ip: "Private IP in case that is different from above"
        server_port: 5432
        user: "CipherTrust Manager Username"
        password: "CipherTrust Manager Password"
        verify: false
      op_type: "patch_self"
      name: "CM Admin"
'''

RETURN = '''

'''

_metadata = dict()
_login_flags = dict(
    prevent_ui_login=dict(type='bool', required=False, default=False),
)

argument_spec = dict(
    op_type=dict(type='str', options=['create', 'patch', 'changepw', 'patch_self'], required=True),
    cm_user_id=dict(type='str'),
    allowed_auth_methods=dict(type='list', element='str', required=False, default=['password']),
    app_metadata=dict(type='dict', options=_metadata, required=False),
    certificate_subject_dn=dict(type='str', required=False),
    connection=dict(type='str', required=False, default='local_account'),
    email=dict(type='str', required=False),
    enable_cert_auth=dict(type='bool', required=False),
    is_domain_user=dict(type='bool', required=False),
    login_flags=dict(type='dict', options=_login_flags, required=False),
    name=dict(type='str', required=False),
    password=dict(type='str', required=False),
    password_change_required=dict(type='bool', required=False),
    user_id=dict(type='str', required=False),
    user_metadata=dict(type='dict', options=_metadata, required=False),
    username=dict(type='str'), # Not needed in self update, else needed
    failed_logins_count=dict(type='int'), # Needed only for patch operation
    new_password=dict(type='str'), # Needed only for change pwd operation
    auth_domain=dict(type='str'), # Needed only for change pwd operation
)

def validate_parameters(user_module):
    return True

def setup_module_object():
    module = ThalesCipherTrustModule(
        argument_spec=argument_spec,
        required_if=(
            ['op_type', 'create', ['username']],
            ['op_type', 'patch', ['cm_user_id', 'username']],
            ['op_type', 'changepw', ['password', 'new_password', 'username']],
        ),
        mutually_exclusive=[],
        supports_check_mode=True,

    )
    return module

def main():
    
    module = setup_module_object()
    validate_parameters(
        user_module=module,
    )

    result = dict(
        changed=False,
    )

    if module.params.get('op_type') == 'create':
        try:
          response = create(
            node=module.params.get('localNode'),
            allowed_auth_methods=module.params.get('allowed_auth_methods'),
            app_metadata=module.params.get('app_metadata'),
            certificate_subject_dn=module.params.get('certificate_subject_dn'),
            connection=module.params.get('connection'),
            email=module.params.get('email'),
            enable_cert_auth=module.params.get('enable_cert_auth'),
            login_flags=module.params.get('login_flags'),
            prevent_ui_login_bool=module.params.get('prevent_ui_login'),
            name=module.params.get('name'),
            password=module.params.get('password'),
            password_change_required=module.params.get('password_change_required'),
            user_id=module.params.get('user_id'),
            user_metadata=module.params.get('user_metadata'),
            username=module.params.get('username'),
          )
          result['response'] = response
        except CMApiException as api_e:
          if api_e.api_error_code:
            module.fail_json(msg="status code: " + str(api_e.api_error_code) + " message: " + api_e.message)
        except AnsibleCMException as custom_e:
          module.fail_json(msg=custom_e.message)
    elif module.params.get('op_type') == 'patch':
        try:
          response = patch(
            node=module.params.get('localNode'),
            cm_user_id=module.params.get('cm_user_id'),
            allowed_auth_methods=module.params.get('allowed_auth_methods'),
            certificate_subject_dn=module.params.get('certificate_subject_dn'),
            email=module.params.get('email'),
            enable_cert_auth_bool=module.params.get('enable_cert_auth'),
            failed_logins_count=module.params.get('failed_logins_count'),
            login_flags=module.params.get('login_flags'),
            name=module.params.get('name'),
            password=module.params.get('password'),
            password_change_required=module.params.get('password_change_required'),
            user_metadata=module.params.get('user_metadata'),
            username=module.params.get('username'),
          )
          result['response'] = response
        except CMApiException as api_e:
          if api_e.api_error_code:
            module.fail_json(msg="status code: " + str(api_e.api_error_code) + " message: " + api_e.message)
        except AnsibleCMException as custom_e:
          module.fail_json(msg=custom_e.message)
    elif module.params.get('op_type') == 'changepw':
        try:
          response = changepw(
            node=module.params.get('localNode'),
            password=module.params.get('password'),
            username=module.params.get('username'),
            new_password=module.params.get('new_password'),
            auth_domain=module.params.get('auth_domain'),
          )
          result['response'] = response
        except CMApiException as api_e:
          if api_e.api_error_code:
            module.fail_json(msg="status code: " + str(api_e.api_error_code) + " message: " + api_e.message)
        except AnsibleCMException as custom_e:
          module.fail_json(msg=custom_e.message)
    else:
        try:
          response = patch_self(
            node=module.params.get('localNode'),
            email=module.params.get('email'),
            name=module.params.get('name'),
            user_metadata=module.params.get('user_metadata'),
          )
          result['response'] = response
        except CMApiException as api_e:
          if api_e.api_error_code:
            module.fail_json(msg="status code: " + str(api_e.api_error_code) + " message: " + api_e.message)
        except AnsibleCMException as custom_e:
          module.fail_json(msg=custom_e.message)
          
    module.exit_json(**result)

if __name__ == '__main__':
    main()
