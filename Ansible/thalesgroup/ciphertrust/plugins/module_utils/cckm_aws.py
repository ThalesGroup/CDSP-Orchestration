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

from ansible_collections.thalesgroup.ciphertrust.plugins.module_utils.cm_api import POSTData, POSTWithoutData
from ansible_collections.thalesgroup.ciphertrust.plugins.module_utils.exceptions import CMApiException, AnsibleCMException

# CCKM AWS CKS Management Functions
def performCKSOperation(**kwargs):
  request = {}

  for key, value in kwargs.items():
    if key not in ['node', 'id', 'cks_op'] and value != None:
      request[key] = value

  if kwargs['cks_op_type'] == "block" or kwargs['cks_op_type'] == "unblock" or kwargs['cks_op_type'] == "disconnect" or kwargs['cks_op_type'] == "rotate-credential":
    try:
      response = POSTWithoutData(
        cm_node=kwargs["node"],
        cm_api_endpoint="cckm/aws/custom-key-stores/" + kwargs['id'] + "/" + kwargs['cks_op_type'],
      )          
      return ast.literal_eval(str(response))
    except CMApiException as api_e:
      raise
    except AnsibleCMException as custom_e:
      raise
  elif kwargs['cks_op_type'] == "create-aws-key" or kwargs['cks_op_type'] == "connect" or kwargs['cks_op_type'] == "link":
    payload = json.dumps(request)
    try:
      response = POSTData(
        payload=payload,
        cm_node=kwargs["node"],
        cm_api_endpoint="cckm/aws/custom-key-stores/" + kwargs['id'] + "/" + kwargs['cks_op_type'],
        id="id",
      )        
      return ast.literal_eval(str(response))
    except CMApiException as api_e:
      raise
    except AnsibleCMException as custom_e:
      raise
  else:
    raise AnsibleCMException(message="invalid operation on custom key store")

def performHYOKKeyOperation(**kwargs):
  request = {}

  for key, value in kwargs.items():
    if key not in ['node', 'id', 'hyok_op_type'] and value != None:
      request[key] = value

  if kwargs['hyok_op_type'] == "block" or kwargs['hyok_op_type'] == "unblock":
    try:
      response = POSTWithoutData(
        cm_node=kwargs["node"],
        cm_api_endpoint="cckm/aws/keys/" + kwargs['id'] + "/" + kwargs['hyok_op_type'],
      )          
      return ast.literal_eval(str(response))
    except CMApiException as api_e:
      raise
    except AnsibleCMException as custom_e:
      raise
  elif kwargs['hyok_op_type'] == "link":
    payload = json.dumps(request)
    try:
      response = POSTData(
        payload=payload,
        cm_node=kwargs["node"],
        cm_api_endpoint="cckm/aws/keys/" + kwargs['id'] + "/" + kwargs['hyok_op_type'],
        id="id",
      )        
      return ast.literal_eval(str(response))
    except CMApiException as api_e:
      raise
    except AnsibleCMException as custom_e:
      raise
  else:
    raise AnsibleCMException(message="invalid operation on HYOK key")

# CCKM AWS Key Management Functions
def performKeyOperation(**kwargs):
  request = {}

  for key, value in kwargs.items():
    if key not in ['node', 'id', 'key_op_type'] and value != None:
      request[key] = value

  if kwargs['key_op_type'] == "disable-rotation-job" or kwargs['key_op_type'] == "delete-material" or kwargs['key_op_type'] == "enable" or kwargs['key_op_type'] == "disable" or kwargs['key_op_type'] == "cancel-deletion" or kwargs['key_op_type'] == "enable-auto-rotation" or kwargs['key_op_type'] == "disable-auto-rotation":
    try:
      response = POSTWithoutData(
        cm_node=kwargs["node"],
        cm_api_endpoint="cckm/aws/keys/" + kwargs['id'] + "/" + kwargs['key_op_type'],
      )          
      return ast.literal_eval(str(response))
    except CMApiException as api_e:
      raise
    except AnsibleCMException as custom_e:
      raise
  elif kwargs['key_op_type'] == "enable-rotation-job" or kwargs['key_op_type'] == "import-material" or kwargs['key_op_type'] == "rotate" or kwargs['key_op_type'] == "schedule-deletion" or kwargs['key_op_type'] == "policy" or kwargs['key_op_type'] == "update-description" or kwargs['key_op_type'] == "add-tags" or kwargs['key_op_type'] == "remove-tags" or kwargs['key_op_type'] == "add-alias" or kwargs['key_op_type'] == "delete-alias" or kwargs['key_op_type'] == "replicate-key" or kwargs['key_op_type'] == "update-primary-region":
    payload = json.dumps(request)
    try:
      response = POSTData(
        payload=payload,
        cm_node=kwargs["node"],
        cm_api_endpoint="cckm/aws/keys/" + kwargs['id'] + "/" + kwargs['key_op_type'],
        id="id",
      )        
      return ast.literal_eval(str(response))
    except CMApiException as api_e:
      raise
    except AnsibleCMException as custom_e:
      raise

def uploadKeyToAWS(**kwargs):
  request = {}

  for key, value in kwargs.items():
    if key not in ['node'] and value != None:
      request[key] = value

  payload = json.dumps(request)

  try:
    response = POSTData(
      payload=payload,
      cm_node=kwargs["node"],
      cm_api_endpoint="cckm/aws/upload-key",
      id="id",
    )          
    return ast.literal_eval(str(response))
  except CMApiException as api_e:
    raise
  except AnsibleCMException as custom_e:
    raise

def verifyKeyAlias(**kwargs):
  request = {}

  for key, value in kwargs.items():
    if key not in ['node'] and value != None:
      request[key] = value

  payload = json.dumps(request)

  try:
    response = POSTData(
      payload=payload,
      cm_node=kwargs["node"],
      cm_api_endpoint="cckm/aws/alias/verify",
      id="id",
    )          
    return ast.literal_eval(str(response))
  except CMApiException as api_e:
    raise
  except AnsibleCMException as custom_e:
    raise

# CCKM AWS Key Management Functions
def updateACLs(**kwargs):
  request = {}

  for key, value in kwargs.items():
    if key not in ['node', 'id'] and value != None:
      request[key] = value

  payload = json.dumps(request)

  try:
    response = POSTData(
      payload=payload,
      cm_node=kwargs["node"],
      cm_api_endpoint="cckm/aws/kms/" + kwargs['id'] + "/update-acls",
      id="id",
    )          
    return ast.literal_eval(str(response))
  except CMApiException as api_e:
    raise
  except AnsibleCMException as custom_e:
    raise