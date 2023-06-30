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
from ansible_collections.thalesgroup.ciphertrust.plugins.module_utils.keys2 import destroy, archive, recover, revoke, reactivate, export, clone
from ansible_collections.thalesgroup.ciphertrust.plugins.module_utils.exceptions import CMApiException, AnsibleCMException

DOCUMENTATION = '''
---
module: vault_keys2_op
short_description: Perform operations on keys
description:
    - This is a Thales CipherTrust Manager module for working with the CipherTrust Manager APIs, more specifically with key operations API
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
    key_version:
        description:
          - Query Parameter
          - Key version
          - Defaults to the latest version
          - Valid only if id_type is "name"
        required: false
        type: int
    id_type:
        description:
          - Query Parameter
          - Type of identifier for the key
        required: false
        choices: [name, id, uri, alias]
        type: str
    includeMaterial:
        description:
          - Query Parameter
          - weather to include the key material if the op_type is clone
          - applicable only if op_type is clone
        required: false
        type: bool
        default: false
    op_type:
        description: Operation to be performed
        choices: [destroy, archive, recover, revoke, reactivate, export, clone]
        required: true
        type: str
    cm_key_id:
        description: 
          - CM ID of the key that needs to be patched.
        type: str
        required: true
        default: null
    reason:
        description: 
          - The reason the key is being revoked. Choices are Unspecified, KeyCompromise, CACompromise, AffiliationChanged, Superseded, CessationOfOperation or PrivilegeWithdrawn
          - The reason the key is being reactivated. Choices are DeactivatedToActive, ActiveProtectStopToActive or DeactivatedToActiveProtectStop
          - Required if op_type is either revoke or reactivate
        type: str
        default: null
    compromiseOccurrenceDate:
        description: 
          - Date/time when the object was first believed to be compromised, if known. 
          - Only valid if the revocation reason is CACompromise or KeyCompromise, otherwise ignored.
          - Defaults to key's creation time.
        type: str
        required: false
        default: null
    message:
        description: 
          - Message explaining revocation.
          - Message explaining reactivation.
        type: str
        required: false
        default: null
    combineXts:
        description: 
          - If set to true, then full material of XTS/CBC-CS1 key will be exported.
          - Only applicable for op_type "export"
        type: bool
        default: false
        required: false
    encoding:
        description: 
          - Specifies the encoding used for the material field.
          - For wrapping scenarios and PKCS12 format, the only valid option is base64. In case of "Symmetric Keys" when 'format' parameter has 'base64' value and 'encoding' parameter also contains some value. The encoding parameter takes the priority. Options for Symmetric Keys are hex or base64
          - Only applicable for op_type "export"
        type: str
        required: false
        default: null
    keyFormat:
        description: 
          - The format of the returned key material. If the algorithm is 'rsa' or 'ec'. The value can be one of 'pkcs1', 'pkcs8' , 'pkcs12', or 'jwe'. The default value is 'pkcs8'. If algorithm is ‘rsa’ and format is 'pkcs12', the key material will contain the base64-encoded value of the PFX file. The value 'base64' is used for symmetric keys, for which the format of the returned key material is base64-encoded if wrapping is applied (i.e., either 'wrapKeyName' or 'wrapPublicKey' is specified),otherwise, the format is hex-encoded, unless 'base64' is given. If the "format" is 'jwe' then the "material" for the symmetric key, asymmetric key or certificate will be wrapped in JWE format. "wrapKeyName"(should be a public key) or "wrapPublicKey" and "wrapJWE" parameters are required for 'jwe' format. The value 'opaque' is supported for symmetric keys with 'opaque' format only.
          - Only applicable for op_type "export"
        type: str
        choices: [pkcs1, pkcs8, pkcs12, jwe]
        required: false
        default: null
    macSignKeyIdentifier:
        description: 
          - This parameter specifies the identifier of the key used for generating the MAC or signature("macSignBytes") of the key whose key material is to be exported
          - The "wrappingMethod" should be "mac/sign" to generate the MAC/signature.
          - To generate a MAC, the key should be a HMAC key.
          - To generate a signature, the key should be an RSA private key.
          - Only applicable for op_type "export"
        type: str
        required: false
        default: null
    macSignKeyIdentifierType:
        description: 
          - This parameter specifies the identifier of the key("macSignKeyIdentifier") used for generating MAC or signature of the key material. The "wrappingMethod" should be "mac/sign" to verify the mac/signature("macSignBytes") of the key material("material")
          - Only applicable for op_type "export"
        type: str
        choices: [name, id, alias]
        required: false
        default: null
    padded:
        description:
          - This parameter determines the padding for the wrap algorithm while exporting a symmetric key
          - If true, the RFC 5649(AES Key Wrap with Padding) is followed and if false, RFC 3394(AES Key Wrap) is followed for wrapping the material for the symmetric key.
          - If a certificate is being exported with the "wrappingMethod" set to "encrypt", the "padded" parameter must be set to true.
          - This parameter defaults to false.
          - Only applicable for op_type "export"
        type: bool
        default: false
        required: false
    password:
        description:
          - For pkcs12 format, if the pkcs12passwordLink is not present in the Key (RSA keys), specify either password or secretDataLink. This should be the base64 encoded value of the password.
          - Only applicable for op_type "export"
        type: str
        default: null
        required: false
    pemWrap:
        description:
          - If the parameter is set to true, it wraps the PEM encoding of the private key (asymmetric) otherwise, the DER encoding of the key is wrapped.
          - Only valid when private keys (asymmetric) and certificates are to be wrapped for "mac/sign" and "encrypt" values for "wrappingMethod" parameter.
          - This parameter defaults to false.
          - Only applicable for op_type "export"
        type: bool
        default: false
        required: false
    secretDataEncoding:
        description: 
          - For pkcs12 format, this field specifies the encoding method used for the secretDataLink material. Ignore this field if secretData is created from REST and is in plain format. Specify the value of this field as HEX format if secretData is created from KMIP.
          - Only applicable for op_type "export"
        type: str
        required: false
        default: null
    secretDataLink:
        description: 
          - For pkcs12 format, either secretDataLink or password should be specified. The value can be either ID or name of Secret Data.
          - Only applicable for op_type "export"
        type: str
        required: false
        default: null
    signingAlgo:
        description: 
          - This parameter specifies the algorithm to be used for generating the signature for the verification of the "macSignBytes" during import of key material. The "wrappingMethod" should be "mac/sign" to verify the signature("macSignBytes") of the key material("material").
          - Only applicable for op_type "export"
        choices: [RSA, RSA-PSS]
        type: str
        required: false
        default: null
    wrapHKDF:
        description: 
          - Information which is used to wrap a Key using HKDF.
          - Only applicable for op_type "export"
        type: dict
        suboptions:
          hashAlgorithm:
            description: Hash Algorithm is used for HKDF Wrapping.
            type: str
            choices: [hmac-sha1, hmac-sha224, hmac-sha256, hmac-sha384, hmac-sha512]
            required: false
            default: null
          info:
            description: Info is an optional hex value for HKDF based derivation.
            type: str
            required: false
            default: null
          okmLen:
            description: The desired output key material length in integer.
            type: str
            required: false
            default: null
          salt:
            description: Salt is an optional hex value for HKDF based derivation.
            type: str
            required: false
            default: null
        required: false
        default: null
    wrapJWE:
        description: 
          - Information which is used to wrap a Key using JWE. (JWT ID (JTI) provides a unique identifier for the JWT. JTI will be automatically included in JWE if it is available in JWT identity token.)
          - Only applicable for op_type "export"
        type: dict
        suboptions:
          contentEncryptionAlgorithm:
            description: Content Encryption Algorithm is symmetric encryption algorithm used to encrypt the data , default is AES_256_GCM.
            type: str
            choices: [AES_128_CBC_HMAC_SHA_256, AES_192_CBC_HMAC_SHA_384, AES_256_CBC_HMAC_SHA_512, AES_128_GCM, AES_192_GCM, AES_256_GCM]
            required: false
            default: AES_256_GCM
          jwtIdentifier:
            description: JWT identifier (JTI) is unique identifier for the JWT used by SFDC for cache key replay detection.
            type: str
            required: false
            default: null
          keyEncryptionAlgorithm:
            description: Key Encryption Algorithm is used to encrypt the Content Encryption Key (CEK), default is RSA_OAEP_SHA1. Algorithm should correspond to type of public key provided for wrapping.
            type: str
            choices: [RSA1_5, RSA_OAEP_SHA1, RSA_OAEP_SHA256, ECDH_ES, ECDH_ES_AES_128_KEY_WRAP, ECDH_ES_AES_192_KEY_WRAP, ECDH_ES_AES_256_KEY_WRAP]
            default: RSA_OAEP_SHA1
            required: false
          keyIdentifier:
            description: Key identifier to be used as "kid" parameter in JWE material and JWE header. Defaults to key id.
            type: str
            required: false
            default: null
        required: false
        default: null
    wrapKeyIDType:
        description: 
          - IDType specifies how the wrapKeyName should be interpreted.
          - Only applicable for op_type "export"
        type: str
        choices: [name, id, alias]
        required: false
        default: null
    wrapKeyName:
        description:
          - The key material will be wrapped with material of the specified key name. The "material" property in the response will be base64 encoded ciphertext. If the "wrappingMethod" field is set to "encrypt", then the wrapping key must be an AES key, RSA private key or RSA public key. For the export of symmetric keys with the "encrypt" method, the three key types are allowed but for the export of a private key if the "wrapRSAAES" parameters are not set, the wrapping key has to be an AES key with a size of 256 bits. If "wrapRSAAES" parameters are set, then the wrapping key has to either be an RSA private or public key. You can set either "wrapKeyName" parameter or "wrapPublicKey" at a time. The wrapping key should be active with a protect stop date that is not expired.
          - Only applicable for op_type "export"
        type: str
        required: false
        default: null
    wrapPBE:
        description: 
          - WrapPBE produces a derived key from a password and other parameters like salt, iteration count, hashing algorithm and derived key length. PBE is currently only supported to wrap symmetric keys (AES), private Keys and certificates.
          - Only applicable for op_type "export"
        type: dict
        suboptions:
          hashAlgorithm:
            description: Underlying hashing algorithm that acts as a pseudorandom function to generate derive keys.
            type: str
            choices: [hmac-sha1, hmac-sha224, hmac-sha256, hmac-sha384, hmac-sha512, hmac-sha512/224, hmac-sha512/256, hmac-sha3-224, hmac-sha3-256, hmac-sha3-384, hmac-sha3-512]
            required: false
            default: null
          dklen:
            description: Intended length in octets of the derived key. dklen must be in range of 14 bytes to 512 bytes.
            type: int
            required: false
            default: null
          iteration:
            description: Iteration count increase the cost of producing keys from a password. Iteration must be in range of 1 to 1,00,00,000.
            type: int
            required: false
            default: null
          password:
            description: Base password to generate derive keys. It cannot be used in conjunction with passwordidentifier. password must be in range of 8 bytes to 128 bytes.
            type: str
            required: false
            default: null
          passwordIdentifier:
            description: Secret password identifier for password. It cannot be used in conjunction with password.
            type: str
            required: false
            default: null
          passwordIdentifierType:
            description: Type of the Passwordidentifier. If not set then default value is name.
            type: str
            choices: [id, name, slug]
            required: false
            default: null
          purpose:
            description: User defined purpose. If specified will be prefixed to pbeSalt. pbePurpose must not be greater than 128 bytes.
            type: str
            required: false
            default: null
          salt:
            description: A Hex encoded string. pbeSalt must be in range of 16 bytes to 512 bytes.
            type: str
            required: false
            default: null
        required: false
        default: null
    wrapPublicKey:
        description: 
          - If the algorithm is 'aes','tdes','hmac-*', 'seed' or 'aria', this value will be used to encrypt the returned key material. This value is ignored for other algorithms. Value must be an RSA public key, PEM-encoded public key in either PKCS1 or PKCS8 format, or a PEM-encoded X.509 certificate. If set, the returned 'material' value will be a Base64 encoded PKCS#1 v1.5 encrypted key. View "wrapPublicKey" in export parameters for more information. Only applicable if 'includeMaterial' is true.
          - Only applicable for op_type "export"
        type: str
        required: false
        default: null
    wrapPublicKeyPadding:
        description:
          - WrapPublicKeyPadding specifies the type of padding scheme that needs to be set when importing the Key using the specified wrapkey. Accepted values are "pkcs1", "oaep", "oaep256", "oaep384", "oaep512", and will default to "pkcs1" when 'wrapPublicKeyPadding' is not set and 'WrapPublicKey' is set.
          - While creating a new key, wrapPublicKeyPadding parameter should be specified only if 'includeMaterial' is true. In this case, key will get created and in response wrapped material using specified wrapPublicKeyPadding and other wrap parameters will be returned.
          - Only applicable for op_type "export"
        type: str
        choices: [pkcs1, oaep, oaep256, oaep384, oaep512]
        required: false
        default: null
    wrapRSAAES:
        description: 
          - Information which is used to wrap/unwrap asymmetric keys using RSA AES KWP method. This method internally requires AES key size to generate a temporary AES key and RSA padding. To use WrapRSAAES, algorithm "RSA/RSAAESKEYWRAPPADDING" must be specified in WrappingEncryptionAlgo.
          - Only applicable for op_type "export"
        type: dict
        suboptions:
          aesKeySize:
            description: Size of AES key for RSA AES KWP. 
            type: int
            choices: [128, 192, 256]
            required: false
            default: 256
          padding:
            description: Padding specifies the type of padding scheme that needs to be set when exporting the Key using RSA AES wrap
            type: str
            choices: [oaep, oaep256, oaep384, oaep512]
            required: false
            default: oaep256
        required: false
        default: null
    wrappingEncryptionAlgo:
        description:
          - It indicates the Encryption Algorithm information for wrapping the key. Format is Algorithm/Mode/Padding. For example AES/AESKEYWRAP. Here AES is Algorithm, AESKEYWRAP is Mode & Padding is not specified. AES/AESKEYWRAP is RFC-3394 & AES/AESKEYWRAPPADDING is RFC-5649. For wrapping private key, only AES/AESKEYWRAPPADDING is allowed. RSA/RSAAESKEYWRAPPADDING is used to wrap/unwrap asymmetric keys using RSA AES KWP method. Refer "WrapRSAAES" to provide optional parameters.
          - Only applicable for op_type "export"
        type: str
        choices: [AES/AESKEYWRAP, AES/AESKEYWRAPPADDING, RSA/RSAAESKEYWRAPPADDING]
        required: false
        default: null
    wrappingHashAlgo:
        description:
          - This parameter specifies the hashing algorithm used if "wrappingMethod" corresponds to "mac/sign". In case of MAC operation, the hashing algorithm used will be inferred from the type of HMAC key("macSignKeyIdentifier").
          - In case of SIGN operation, the possible values are sha1, sha224, sha256, sha384 or sha512
          - Only applicable for op_type "export"
        type: str
        required: false
        default: null
    wrappingMethod:
        description:
          - This parameter specifies the wrapping method used to wrap/mac/sign the key material.
          - Only applicable for op_type "export"
        type: str
        choices: [encrypt, mac/sign, pbe]
        required: false
        default: null
    newKeyName:
        description:
          - Key name for the new cloned key.
          - Only applicable for op_type "clone"
        type: str
        required: false
        default: null
    meta:
        description:
          - Optional end-user or service data stored with the key
          - Only applicable for op_type "clone"
        type: dict
        required: false
        default: null
    idSize:
        description:
          - Size of the ID for the key
          - Only applicable for op_type "clone"
        type: int
        required: false
        default: null

'''

EXAMPLES = '''
- name: "Create Key"
  thalesgroup.ciphertrust.vault_keys2_create:
    localNode:
        server_ip: "IP/FQDN of CipherTrust Manager"
        server_private_ip: "Private IP in case that is different from above"
        server_port: 5432
        user: "CipherTrust Manager Username"
        password: "CipherTrust Manager Password"
        verify: false
    op_type: create
    name: "key_name"
    algorithm: aes
    size: 256
    usageMask: 3145740
'''

RETURN = '''

'''

_wrap_HKDF=dict(
    hashAlgorithm=dict(type='str', choices=['hmac-sha1', 'hmac-sha224', 'hmac-sha256', 'hmac-sha384', 'hmac-sha512'], required=False),
    info=dict(type='str', required=False),
    okmLen=dict(type='int', required=False),
    salt=dict(type='str', required=False),
)
_wrap_JWE=dict(
    contentEncryptionAlgorithm=dict(type='str', choices=['AES_128_CBC_HMAC_SHA_256', 'AES_192_CBC_HMAC_SHA_384', 'AES_256_CBC_HMAC_SHA_512', 'AES_128_GCM', 'AES_192_GCM', 'AES_256_GCM'], default='AES_256_GCM', required=False),
    jwtIdentifier=dict(type='str', required=False),
    keyEncryptionAlgorithm=dict(type='str', choices=['RSA1_5', 'RSA_OAEP_SHA1', 'RSA_OAEP_SHA256', 'ECDH_ES', 'ECDH_ES_AES_128_KEY_WRAP', 'ECDH_ES_AES_192_KEY_WRAP', 'ECDH_ES_AES_256_KEY_WRAP'], default='RSA_OAEP_SHA1', required=False),
    keyIdentifier=dict(type='str', required=False),
)
_wrap_PBE=dict(
    dklen=dict(type='int', required=False),
    hashAlgorithm=dict(type='str', choices=['hmac-sha1', 'hmac-sha224', 'hmac-sha256', 'hmac-sha384', 'hmac-sha512', 'hmac-sha512/224', 'hmac-sha512/256', 'hmac-sha3-224', 'hmac-sha3-256', 'hmac-sha3-384', 'hmac-sha3-512'], required=False),
    iteration=dict(type='int', required=False),
    password=dict(type='str', required=False),
    passwordIdentifier=dict(type='str', required=False),
    passwordIdentifierType=dict(type='str', choices=['name', 'id', 'slug'], required=False),
    purpose=dict(type='str', required=False),
    salt=dict(type='str', required=False),
)
_wrap_RSAAES=dict(
    aesKeySize=dict(type='int', choices=[128, 192, 256], default=256, required=False),
    padding=dict(type='str', choices=['oaep', 'oaep256', 'oaep384', 'oaep512'], default='oaep256', required=False),
)
_schema_less = dict()

argument_spec = dict(
    key_version=dict(type='int', required=False),
    id_type=dict(type='str', options=['name', 'id', 'uri', 'alias'], required=False),
    includeMaterial=dict(type='bool', default=False, required=False),
    op_type=dict(type='str', options=['destroy', 'archive', 'recover', 'revoke', 'reactivate', 'export', 'clone'], required=True),
    cm_key_id=dict(type='str', required=True),
    reason=dict(type='str', choices=['Unspecified', 'KeyCompromise', 'CACompromise', 'AffiliationChanged', 'Superseded', 'CessationOfOperation', 'PrivilegeWithdrawn', 'DeactivatedToActive', 'ActiveProtectStopToActive', 'DeactivatedToActiveProtectStop']),
    compromiseOccurrenceDate=dict(type='str', required=False),
    message=dict(type='str', required=False),
    combineXts=dict(type='bool', required=False, default=False),
    encoding=dict(type='str', required=False),
    keyFormat=dict(type='str', choices=['pkcs1', 'pkcs8', 'pkcs12', 'jwe'], required=False),
    macSignKeyIdentifier=dict(type='str', required=False),
    macSignKeyIdentifierType=dict(type='str', choices=['name', 'id', 'alias'], required=False),
    padded=dict(type='bool', required=False, default=False),
    password=dict(type='str', required=False),
    pemWrap=dict(type='bool', required=False, default=False),
    secretDataEncoding=dict(type='str', required=False),
    secretDataLink=dict(type='str', required=False),
    signingAlgo=dict(type='str', choice=['RSA-PSS', 'RSA'], required=False),
    wrapHKDF=dict(type='dict', options=_wrap_HKDF, required=False),
    wrapJWE=dict(type='dict', options=_wrap_JWE, required=False),
    wrapKeyIDType=dict(type='str', choices=['name', 'id', 'alias'], required=False),
    wrapKeyName=dict(type='str', required=False),
    wrapPBE=dict(type='dict', options=_wrap_PBE, required=False),
    wrapPublicKey=dict(type='str', required=False),
    wrapPublicKeyPadding=dict(type='str', choices=['pkcs1', 'oaep', 'oaep256', 'oaep384', 'oaep512'], required=False),
    wrapRSAAES=dict(type='dict', options=_wrap_RSAAES, required=False),
    wrappingEncryptionAlgo=dict(type='str', choices=['AES/AESKEYWRAP', 'AES/AESKEYWRAPPADDING', 'RSA/RSAAESKEYWRAPPADDING'], required=False),
    wrappingHashAlgo=dict(type='str', required=False),
    wrappingMethod=dict(type='str', choices=['encrypt', 'mac/sign', 'pbe'], required=False),
    newKeyName=dict(type='str', required=False),
    meta=dict(type='dict', options=_schema_less, required=False),
    idSize=dict(type='int', required=False),
)

def validate_parameters(user_module):
    return True

def setup_module_object():
    module = ThalesCipherTrustModule(
      argument_spec=argument_spec,
      required_if=(
        ['op_type', 'revoke', ['reason']],
        ['op_type', 'reactivate', ['reason']],
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

    if module.params.get('op_type') == 'destroy':
      try:
        response = destroy(
            node=module.params.get('localNode'),
            cm_key_id=module.params.get('cm_key_id'),
            key_version=module.params.get('key_version'),
            id_type=module.params.get('id_type'),
        )
        result['response'] = response
      except CMApiException as api_e:
        if api_e.api_error_code:
          module.fail_json(msg="status code: " + str(api_e.api_error_code) + " message: " + api_e.message)
      except AnsibleCMException as custom_e:
        module.fail_json(msg=custom_e.message)

    elif module.params.get('op_type') == 'archive':
      try:
        response = archive(
            node=module.params.get('localNode'),
            cm_key_id=module.params.get('cm_key_id'),
            key_version=module.params.get('key_version'),
            id_type=module.params.get('id_type'),
        )
        result['response'] = response
      except CMApiException as api_e:
        if api_e.api_error_code:
          module.fail_json(msg="status code: " + str(api_e.api_error_code) + " message: " + api_e.message)
      except AnsibleCMException as custom_e:
        module.fail_json(msg=custom_e.message)
        
    elif module.params.get('op_type') == 'recover':
      try:
        response = recover(
            node=module.params.get('localNode'),
            cm_key_id=module.params.get('cm_key_id'),
            key_version=module.params.get('key_version'),
            id_type=module.params.get('id_type'),
        )
        result['response'] = response
      except CMApiException as api_e:
        if api_e.api_error_code:
          module.fail_json(msg="status code: " + str(api_e.api_error_code) + " message: " + api_e.message)
      except AnsibleCMException as custom_e:
        module.fail_json(msg=custom_e.message)
        
    elif module.params.get('op_type') == 'revoke':
      try:
        response = revoke(
            node=module.params.get('localNode'),
            cm_key_id=module.params.get('cm_key_id'),
            key_version=module.params.get('key_version'),
            id_type=module.params.get('id_type'),
            reason=module.params.get('reason'),
            compromiseOccurrenceDate=module.params.get('compromiseOccurrenceDate'),
            message=module.params.get('message'),
        )
        result['response'] = response
      except CMApiException as api_e:
        if api_e.api_error_code:
          module.fail_json(msg="status code: " + str(api_e.api_error_code) + " message: " + api_e.message)
      except AnsibleCMException as custom_e:
        module.fail_json(msg=custom_e.message)
        
    elif module.params.get('op_type') == 'reactivate':
      try:
        response = reactivate(
            node=module.params.get('localNode'),
            cm_key_id=module.params.get('cm_key_id'),
            key_version=module.params.get('key_version'),
            id_type=module.params.get('id_type'),
            reason=module.params.get('reason'),
            message=module.params.get('message'),
        )
        result['response'] = response
      except CMApiException as api_e:
        if api_e.api_error_code:
          module.fail_json(msg="status code: " + str(api_e.api_error_code) + " message: " + api_e.message)
      except AnsibleCMException as custom_e:
        module.fail_json(msg=custom_e.message)
        
    elif module.params.get('op_type') == 'export':
      try:
        response = export(
            node=module.params.get('localNode'),
            cm_key_id=module.params.get('cm_key_id'),
            key_version=module.params.get('key_version'),
            id_type=module.params.get('id_type'),
            combineXts=module.params.get('combineXts'),
            encoding=module.params.get('encoding'),
            keyFormat=module.params.get('keyFormat'),
            macSignKeyIdentifier=module.params.get('macSignKeyIdentifier'),
            macSignKeyIdentifierType=module.params.get('macSignKeyIdentifierType'),
            padded=module.params.get('padded'),
            password=module.params.get('password'),
            pemWrap=module.params.get('pemWrap'),
            secretDataEncoding=module.params.get('secretDataEncoding'),
            secretDataLink=module.params.get('secretDataLink'),
            signingAlgo=module.params.get('signingAlgo'),
            wrapHKDF=module.params.get('wrapHKDF'),
            wrapJWE=module.params.get('wrapJWE'),
            wrapKeyIDType=module.params.get('wrapKeyIDType'),
            wrapKeyName=module.params.get('wrapKeyName'),
            wrapPBE=module.params.get('wrapPBE'),
            wrapPublicKey=module.params.get('wrapPublicKey'),
            wrapPublicKeyPadding=module.params.get('wrapPublicKeyPadding'),
            wrapRSAAES=module.params.get('wrapRSAAES'),
            wrapSymmetricKeyName=module.params.get('wrapSymmetricKeyName'),
            wrappingEncryptionAlgo=module.params.get('wrappingEncryptionAlgo'),
            wrappingHashAlgo=module.params.get('wrappingHashAlgo'),
            wrappingMethod=module.params.get('wrappingMethod'),
        )
        result['response'] = response
      except CMApiException as api_e:
        if api_e.api_error_code:
          module.fail_json(msg="status code: " + str(api_e.api_error_code) + " message: " + api_e.message)
      except AnsibleCMException as custom_e:
        module.fail_json(msg=custom_e.message)
        
    elif module.params.get('op_type') == 'clone':
      try:
        response = clone(
            node=module.params.get('localNode'),
            cm_key_id=module.params.get('cm_key_id'),
            key_version=module.params.get('key_version'),
            id_type=module.params.get('id_type'),
            includeMaterial=module.params.get('includeMaterial'),
            idSize=module.params.get('idSize'),
            meta=module.params.get('meta'),
            newKeyName=module.params.get('newKeyName'),
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