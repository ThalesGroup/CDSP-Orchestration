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

from ansible_collections.thales.ciphertrust.plugins.module_utils.cm_api import POSTData, POSTWithoutData
from ansible_collections.thales.ciphertrust.plugins.module_utils.exceptions import CMApiException, AnsibleCMException

# CCKM AWS CKS Management Functions
def performCKSOperation(**kwargs):
  request = {}

  for key, value in kwargs.items():
    if key not in ['node', 'id', 'cks_op'] and value != None:
      request[key] = value

  if kwargs['cks_op'] == "block" or kwargs['cks_op'] == "unblock" or kwargs['cks_op'] == "disconnect" or kwargs['cks_op'] == "rotate-credential":
    try:
      response = POSTWithoutData(
        cm_node=kwargs["node"],
        cm_api_endpoint="cckm/aws/custom-key-stores/" + kwargs['id'] + "/" + kwargs['cks_op'],
      )          
      return ast.literal_eval(str(response))
    except CMApiException as api_e:
      raise
    except AnsibleCMException as custom_e:
      raise
  elif kwargs['cks_op'] == "create-aws-key" or kwargs['cks_op'] == "connect" or kwargs['cks_op'] == "link":
    payload = json.dumps(request)
    try:
      response = POSTData(
        payload=payload,
        cm_node=kwargs["node"],
        cm_api_endpoint="cckm/aws/custom-key-stores/" + kwargs['id'] + "/" + kwargs['cks_op'],
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
    if key not in ['node', 'id', 'hyok_key_op'] and value != None:
      request[key] = value

  if kwargs['hyok_key_op'] == "block" or kwargs['hyok_key_op'] == "unblock":
    try:
      response = POSTWithoutData(
        cm_node=kwargs["node"],
        cm_api_endpoint="cckm/aws/keys/" + kwargs['id'] + "/" + kwargs['hyok_key_op'],
      )          
      return ast.literal_eval(str(response))
    except CMApiException as api_e:
      raise
    except AnsibleCMException as custom_e:
      raise
  elif kwargs['hyok_key_op'] == "link":
    payload = json.dumps(request)
    try:
      response = POSTData(
        payload=payload,
        cm_node=kwargs["node"],
        cm_api_endpoint="cckm/aws/keys/" + kwargs['id'] + "/" + kwargs['hyok_key_op'],
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
    if key not in ['node', 'id', 'aws_key_action'] and value != None:
      request[key] = value

  if kwargs['aws_key_action'] == "disable-rotation-job" or kwargs['aws_key_action'] == "delete-material" or kwargs['aws_key_action'] == "enable" or kwargs['aws_key_action'] == "disable" or kwargs['aws_key_action'] == "cancel-deletion" or kwargs['aws_key_action'] == "enable-auto-rotation" or kwargs['aws_key_action'] == "disable-auto-rotation":
    try:
      response = POSTWithoutData(
        cm_node=kwargs["node"],
        cm_api_endpoint="cckm/aws/keys/" + kwargs['id'] + "/" + kwargs['aws_key_action'],
      )          
      return ast.literal_eval(str(response))
    except CMApiException as api_e:
      raise
    except AnsibleCMException as custom_e:
      raise
  elif kwargs['aws_key_action'] == "enable-rotation-job" or kwargs['aws_key_action'] == "import-material" or kwargs['aws_key_action'] == "rotate" or kwargs['aws_key_action'] == "schedule-deletion" or kwargs['aws_key_action'] == "policy" or kwargs['aws_key_action'] == "update-description" or kwargs['aws_key_action'] == "add-tags" or kwargs['aws_key_action'] == "remove-tags" or kwargs['aws_key_action'] == "add-alias" or kwargs['aws_key_action'] == "delete-alias" or kwargs['aws_key_action'] == "replicate-key" or kwargs['aws_key_action'] == "update-primary-region":
    payload = json.dumps(request)
    try:
      response = POSTData(
        payload=payload,
        cm_node=kwargs["node"],
        cm_api_endpoint="cckm/aws/keys/" + kwargs['id'] + "/" + kwargs['aws_key_action'],
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