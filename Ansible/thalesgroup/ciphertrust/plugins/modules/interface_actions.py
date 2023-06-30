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
from ansible_collections.thalesgroup.ciphertrust.plugins.module_utils.interfaces import addCertificateToInterface, enableInterface, disableInterface, restoreDefaultTlsCiphers, createCsr, autogenServerCert, useCertificate
from ansible_collections.thalesgroup.ciphertrust.plugins.module_utils.exceptions import CMApiException, AnsibleCMException

DOCUMENTATION = '''
---
module: interface_actions
short_description: Perform operations on CipherTrust Manager interface
description:
    - This is a Thales CipherTrust Manager module for working with the CipherTrust Manager APIs, more specifically with interface actions API
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
      choices: [put_certificate, enable, disable, restore-default-tls-ciphers, csr, auto-gen-server-cert, use-certificate]
      required: true
      type: str
  interface_id:
      description:
          - Identifier of the interface to be updated
      required: true
      type: str
  certificate:
    description: 
      - The certificate and key data in PEM format or base64 encoded PKCS12 format. A chain chain of certs may be included - it must be in ascending order (server to root ca).
      - required if op_type is put_certificate
    type: str
    default: none
    required: false
  format:
    description: 
      - The format of the certificate data (PEM or PKCS12).
      - required if op_type is put_certificate
    type: str
    default: none
    required: false
  generate:
    description: 
      - Create a new self-signed certificate
    type: str
    default: none
    required: false
  password:
    description: 
      - Password to the encrypted key
    type: str
    default: none
    required: false
  cn:
    description: 
      - Common name
      - required if op_type is csr
    type: str
    default: none
    required: false
  dns_names:
    description: Subject Alternative Names (SAN) DNS names
    type: list
    elements: str
    default: none
    required: false
  email_addresses:
    description: Subject Alternative Names (SAN) Email addresses
    type: list
    elements: str
    default: none
    required: false
  ip_addresses:
    description: Subject Alternative Names (SAN) IP addresses
    type: list
    elements: str
    default: none
    required: false
  names:
    description: Name fields like O, OU, L, ST, C
    type: list
    elements: dict
    default: []
    required: false
  copy_from:
    description: 
      - Source interface name
      - required if op_type is use-certificate
    type: str
    default: none
    required: false
'''

EXAMPLES = '''
- name: "Add Cert to Interface"
  thalesgroup.ciphertrust.interface_actions:
    localNode:
        server_ip: "IP/FQDN of CipherTrust Manager"
        server_private_ip: "Private IP in case that is different from above"
        server_port: 5432
        user: "CipherTrust Manager Username"
        password: "CipherTrust Manager Password"
        verify: false
    op_type: put_certificate
    interface_id: "interface_identifier"
    certificate: "cert_key_data"
    format: PEM

- name: "Enable Interface"
  thalesgroup.ciphertrust.interface_actions:
    localNode:
        server_ip: "IP/FQDN of CipherTrust Manager"
        server_private_ip: "Private IP in case that is different from above"
        server_port: 5432
        user: "CipherTrust Manager Username"
        password: "CipherTrust Manager Password"
        verify: false
    op_type: enable
    interface_id: "interface_identifier"

- name: "Disable Interface"
  thalesgroup.ciphertrust.interface_actions:
    localNode:
        server_ip: "IP/FQDN of CipherTrust Manager"
        server_private_ip: "Private IP in case that is different from above"
        server_port: 5432
        user: "CipherTrust Manager Username"
        password: "CipherTrust Manager Password"
        verify: false
    op_type: disable
    interface_id: "interface_identifier"

- name: "Restore default TLS Ciphers"
  thalesgroup.ciphertrust.interface_actions:
    localNode:
        server_ip: "IP/FQDN of CipherTrust Manager"
        server_private_ip: "Private IP in case that is different from above"
        server_port: 5432
        user: "CipherTrust Manager Username"
        password: "CipherTrust Manager Password"
        verify: false
    op_type: restore-default-tls-ciphers
    interface_id: "interface_identifier"

- name: "Create CSR"
  thalesgroup.ciphertrust.interface_actions:
    localNode:
        server_ip: "IP/FQDN of CipherTrust Manager"
        server_private_ip: "Private IP in case that is different from above"
        server_port: 5432
        user: "CipherTrust Manager Username"
        password: "CipherTrust Manager Password"
        verify: false
    op_type: csr
    interface_id: "interface_identifier"
    cn: "csr_cn"

- name: "Auto Generate Server Certificate"
  thalesgroup.ciphertrust.interface_actions:
    localNode:
        server_ip: "IP/FQDN of CipherTrust Manager"
        server_private_ip: "Private IP in case that is different from above"
        server_port: 5432
        user: "CipherTrust Manager Username"
        password: "CipherTrust Manager Password"
        verify: false
    op_type: auto-gen-server-cert
    interface_id: "interface_identifier"

- name: "Use certificate"
  thalesgroup.ciphertrust.interface_actions:
    localNode:
        server_ip: "IP/FQDN of CipherTrust Manager"
        server_private_ip: "Private IP in case that is different from above"
        server_port: 5432
        user: "CipherTrust Manager Username"
        password: "CipherTrust Manager Password"
        verify: false
    op_type: use-certificate
    interface_id: "interface_identifier"
    copy_from: "Name_Source_Interface"
'''

RETURN = '''

'''

_name = dict(
  C=dict(type='str', required=False),
  L=dict(type='str', required=False),
  O=dict(type='str', required=False),
  OU=dict(type='str', required=False),
  ST=dict(type='str', required=False),
)

argument_spec = dict(
  op_type=dict(type='str', options=['put_certificate', 'enable', 'disable', 'restore-default-tls-ciphers', 'csr', 'auto-gen-server-cert', 'use-certificate'], required=True),
  interface_id=dict(type='str', required=True),
  certificate=dict(type='str'),
  format=dict(type='str', options=['PEM', 'PKCS12']),
  generate=dict(type='bool', required=False),
  password=dict(type='str', required=False),
  cn=dict(type='str'),
  dns_names=dict(type='list', element='str', required=False),
  email_addresses=dict(type='list', element='str', required=False),
  ip_addresses=dict(type='list', element='str', required=False),
  names=dict(type='list', element='dict', options=_name, required=False),
  copy_from=dict(type='str'),
)

def validate_parameters(user_module):
    return True

def setup_module_object():
    module = ThalesCipherTrustModule(
        argument_spec=argument_spec,
        required_if=(
            ['op_type', 'put_certificate', ['certificate']],
            ['op_type', 'put_certificate', ['format']],
            ['op_type', 'csr', ['cn']],
            ['op_type', 'use-certificate', ['copy_from']],
        ),
        mutually_exclusive=[],
        supports_check_mode=True,
    )
    return module

def main():

    global module
    
    module = setup_module_object()
    validate_parameters(
        user_module=module,
    )

    result = dict(
        changed=False,
    )

    if module.params.get('op_type') == 'put_certificate':
      try:
        response = addCertificateToInterface(
          node=module.params.get('localNode'),
          interface_id=module.params.get('interface_id'),
          certificate=module.params.get('certificate'),
          cert_format=module.params.get('format'),
          generate=module.params.get('generate'),
          password=module.params.get('password'),
        )
        result['response'] = response
      except CMApiException as api_e:
        if api_e.api_error_code:
          module.fail_json(msg="status code: " + str(api_e.api_error_code) + " message: " + api_e.message)
      except AnsibleCMException as custom_e:
        module.fail_json(msg=custom_e.message)

    elif module.params.get('op_type') == 'enable':
      try:
        response = enableInterface(
          node=module.params.get('localNode'),
          interface_id=module.params.get('interface_id'),
        )
        result['response'] = response
      except CMApiException as api_e:
        if api_e.api_error_code:
          module.fail_json(msg="status code: " + str(api_e.api_error_code) + " message: " + api_e.message)
      except AnsibleCMException as custom_e:
        module.fail_json(msg=custom_e.message)

    elif module.params.get('op_type') == 'disable':
      try:
        response = disableInterface(
          node=module.params.get('localNode'),
          interface_id=module.params.get('interface_id'),
        )
        result['response'] = response
      except CMApiException as api_e:
        if api_e.api_error_code:
          module.fail_json(msg="status code: " + str(api_e.api_error_code) + " message: " + api_e.message)
      except AnsibleCMException as custom_e:
        module.fail_json(msg=custom_e.message)

    elif module.params.get('op_type') == 'restore-default-tls-ciphers':
      try:
        response = restoreDefaultTlsCiphers(
          node=module.params.get('localNode'),
          interface_id=module.params.get('interface_id'),
        )
        result['response'] = response
      except CMApiException as api_e:
        if api_e.api_error_code:
          module.fail_json(msg="status code: " + str(api_e.api_error_code) + " message: " + api_e.message)
      except AnsibleCMException as custom_e:
        module.fail_json(msg=custom_e.message)

    elif module.params.get('op_type') == 'csr':
      try:
        response = createCsr(
          node=module.params.get('localNode'),
          interface_id=module.params.get('interface_id'),
          cn=module.params.get('cn'),
          dns_names=module.params.get('dns_names'),
          email_addresses=module.params.get('email_addresses'),
          ip_addresses=module.params.get('ip_addresses'),
          names=module.params.get('names'),
        )
        result['response'] = response
      except CMApiException as api_e:
        if api_e.api_error_code:
          module.fail_json(msg="status code: " + str(api_e.api_error_code) + " message: " + api_e.message)
      except AnsibleCMException as custom_e:
        module.fail_json(msg=custom_e.message)

    elif module.params.get('op_type') == 'auto-gen-server-cert':
      try:
        response = autogenServerCert(
          node=module.params.get('localNode'),
          interface_id=module.params.get('interface_id'),
        )
        result['response'] = response
      except CMApiException as api_e:
        if api_e.api_error_code:
          module.fail_json(msg="status code: " + str(api_e.api_error_code) + " message: " + api_e.message)
      except AnsibleCMException as custom_e:
        module.fail_json(msg=custom_e.message)

    elif module.params.get('op_type') == 'use-certificate':
      try:
        response = useCertificate(
          node=module.params.get('localNode'),
          interface_id=module.params.get('interface_id'),
          copy_from=module.params.get('copy_from'),
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