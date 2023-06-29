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

import json
import ast

from ansible_collections.thalesgroup.ciphertrust.plugins.module_utils.cm_api import POSTData, POSTWithoutData, DeleteWithoutData
from ansible_collections.thalesgroup.ciphertrust.plugins.module_utils.exceptions import CMApiException, AnsibleCMException

# CCKM Azure Vault Management Functions
def performAZVaultOperation(**kwargs):
  request = {}

  for key, value in kwargs.items():
    if key not in ['node', 'id', 'vault_op'] and value != None:
      request[key] = value

  if kwargs['vault_op'] == "disable-rotation-job":
    try:
      response = POSTWithoutData(
        cm_node=kwargs["node"],
        cm_api_endpoint="cckm/azure/vaults/" + kwargs['id'] + "/" + kwargs['vault_op'],
      )          
      return ast.literal_eval(str(response))
    except CMApiException as api_e:
      raise
    except AnsibleCMException as custom_e:
      raise
  elif kwargs['vault_op'] == "enable-rotation-job" or kwargs['vault_op'] == "update-acls":
    payload = json.dumps(request)
    try:
      response = POSTData(
        payload=payload,
        cm_node=kwargs["node"],
        cm_api_endpoint="cckm/azure/vaults/" + kwargs['id'] + "/" + kwargs['vault_op'],
        id="id",
      )        
      return ast.literal_eval(str(response))
    except CMApiException as api_e:
      raise
    except AnsibleCMException as custom_e:
      raise
  elif kwargs['vault_op'] == "remove-vault":
    try:
      response = DeleteWithoutData(
        cm_node=kwargs["node"],
        cm_api_endpoint="cckm/azure/vaults/" + kwargs['id'] + "/" + kwargs['vault_op'],
      )          
      return ast.literal_eval(str(response))
    except CMApiException as api_e:
      raise
    except AnsibleCMException as custom_e:
      raise
  else:
    raise AnsibleCMException(message="Unsupported vault_op")

# CCKM Azure Certificate Management Functions
def performAZCertificateOperation(**kwargs):
  request = {}

  for key, value in kwargs.items():
    if key not in ['node', 'id', 'certificate_op_type'] and value != None:
      request[key] = value

  payload = json.dumps(request)

  if kwargs['certificate_op_type'] == "restore":
    try:
      response = POSTData(
        payload=payload,
        cm_node=kwargs["node"],
        cm_api_endpoint="cckm/azure/certificates/" + kwargs['id'] + "/" + kwargs['certificate_op_type'],
        id="id",
      )          
      return ast.literal_eval(str(response))
    except CMApiException as api_e:
      raise
    except AnsibleCMException as custom_e:
      raise
  elif kwargs['certificate_op_type'] == "soft-delete" or kwargs['certificate_op_type'] == "hard-delete" or kwargs['certificate_op_type'] == "recover":
    try:
      response = POSTWithoutData(
        cm_node=kwargs["node"],
        cm_api_endpoint="cckm/azure/certificates/" + kwargs['id'] + "/" + kwargs['certificate_op_type'],
      )          
      return ast.literal_eval(str(response))
    except CMApiException as api_e:
      raise
    except AnsibleCMException as custom_e:
      raise
  else:
    raise AnsibleCMException(message="Unsupported certificate_op_type")

def importCertToAZ(**kwargs):
  request = {}

  for key, value in kwargs.items():
    if key not in ['node'] and value != None:
      request[key] = value

  payload = json.dumps(request)

  try:
    response = POSTData(
      payload=payload,
      cm_node=kwargs["node"],
      cm_api_endpoint="cckm/azure/certificates/import",
      id="id",
    )          
    return ast.literal_eval(str(response))
  except CMApiException as api_e:
    raise
  except AnsibleCMException as custom_e:
    raise

# CCKM Azure Certificate Management Functions
def performAZKeyOperation(**kwargs):
  request = {}

  for key, value in kwargs.items():
    if key not in ['node', 'id', 'key_op_type'] and value != None:
      request[key] = value

  payload = json.dumps(request)

  if kwargs['key_op_type'] == "restore" or kwargs['key_op_type'] == "enable-rotation-job":
    try:
      response = POSTData(
        payload=payload,
        cm_node=kwargs["node"],
        cm_api_endpoint="cckm/azure/keys/" + kwargs['id'] + "/" + kwargs['key_op_type'],
        id="id",
      )          
      return ast.literal_eval(str(response))
    except CMApiException as api_e:
      raise
    except AnsibleCMException as custom_e:
      raise
  else:
    try:
      response = POSTWithoutData(
        cm_node=kwargs["node"],
        cm_api_endpoint="cckm/azure/keys/" + kwargs['id'] + "/" + kwargs['key_op_type'],
      )          
      return ast.literal_eval(str(response))
    except CMApiException as api_e:
      raise
    except AnsibleCMException as custom_e:
      raise

def uploadKeyOnAZ(**kwargs):
  request = {}

  for key, value in kwargs.items():
    if key not in ['node'] and value != None:
      request[key] = value

  payload = json.dumps(request)

  try:
    response = POSTData(
      payload=payload,
      cm_node=kwargs["node"],
      cm_api_endpoint="cckm/azure/upload-key",
      id="id",
    )          
    return ast.literal_eval(str(response))
  except CMApiException as api_e:
    raise
  except AnsibleCMException as custom_e:
    raise