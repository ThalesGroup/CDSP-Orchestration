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
def performGCPEKMOperation(**kwargs):
  request = {}

  for key, value in kwargs.items():
    if key not in ['node', 'id', 'ekm_op_type'] and value != None:
      request[key] = value

  try:
    response = POSTWithoutData(
    cm_node=kwargs["node"],
    cm_api_endpoint="cckm/ekm/endpoints/" + kwargs['id'] + "/" + kwargs['ekm_op_type'],
    )          
    return ast.literal_eval(str(response))
  except CMApiException as api_e:
    raise
  except AnsibleCMException as custom_e:
    raise

def performGCPKeyRingOperation(**kwargs):
  request = {}

  for key, value in kwargs.items():
    if key not in ['node', 'id', 'keyring_op_type'] and value != None:
      request[key] = value
  
  payload = json.dumps(request)

  if kwargs['key_op_type'] == "update-acls":
    try:
      response = POSTData(
        payload=payload,
        cm_node=kwargs["node"],
        cm_api_endpoint="cckm/google/key-rings/" + kwargs['id'] + "/update-acls",
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
        cm_api_endpoint="cckm/google/key-rings/" + kwargs['id'] + "/remove-key-ring",
      )          
      return ast.literal_eval(str(response))
    except CMApiException as api_e:
      raise
    except AnsibleCMException as custom_e:
      raise

def performKeyOperation(**kwargs):
  request = {}

  for key, value in kwargs.items():
    if key not in ['node', 'id', 'key_op_type'] and value != None:
      request[key] = value
  
  payload = json.dumps(request)

  if kwargs['key_op_type'] == "create-version":
    try:
      response = POSTData(
        payload=payload,
        cm_node=kwargs["node"],
        cm_api_endpoint="cckm/google/keys/" + kwargs['id'] + "/versions",
        id="id",
      )          
      return ast.literal_eval(str(response))
    except CMApiException as api_e:
      raise
    except AnsibleCMException as custom_e:
      raise
  elif kwargs['key_op_type'] == "enable-auto-rotation":
    try:
      response = POSTData(
        payload=payload,
        cm_node=kwargs["node"],
        cm_api_endpoint="cckm/google/keys/" + kwargs['id'] + "/enable-auto-rotation",
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
        cm_api_endpoint="cckm/google/keys/" + kwargs['id'] + "/" + kwargs['key_op_type'],
      )          
      return ast.literal_eval(str(response))
    except CMApiException as api_e:
      raise
    except AnsibleCMException as custom_e:
      raise

def performKeyVersionOperation(**kwargs):
  request = {}

  for key, value in kwargs.items():
    if key not in ['node', 'id', 'key_version_op_type', 'version_id'] and value != None:
      request[key] = value
  
  try:
    response = POSTWithoutData(
      cm_node=kwargs["node"],
      cm_api_endpoint="cckm/google/keys/" + kwargs['id'] + "/versions/" + kwargs['version_id'] + "/" + kwargs['key_version_op_type'],
    )          
    return ast.literal_eval(str(response))
  except CMApiException as api_e:
    raise
  except AnsibleCMException as custom_e:
    raise

def uploadKeyGCP(**kwargs):
  request = {}

  for key, value in kwargs.items():
    if key not in ['node'] and value != None:
      request[key] = value

  payload = json.dumps(request)

  try:
    response = POSTData(
      payload=payload,
      cm_node=kwargs["node"],
      cm_api_endpoint="cckm/google/upload-key",
      id="id",
    )          
    return ast.literal_eval(str(response))
  except CMApiException as api_e:
    raise
  except AnsibleCMException as custom_e:
    raise

def updateAllKeyVersions(**kwargs):
  request = {}

  for key, value in kwargs.items():
    if key not in ['node'] and value != None:
      request[key] = value

  payload = json.dumps(request)

  try:
    response = POSTData(
      payload=payload,
      cm_node=kwargs["node"],
      cm_api_endpoint="cckm/google/update-all-versions-jobs",
      id="id",
    )          
    return ast.literal_eval(str(response))
  except CMApiException as api_e:
    raise
  except AnsibleCMException as custom_e:
    raise

def performGCPWorkspaceEndpointOperation(**kwargs):
  request = {}

  for key, value in kwargs.items():
    if key not in ['node', 'id', 'endpoint_op_type'] and value != None:
      request[key] = value
  
  payload = json.dumps(request)

  if kwargs['endpoint_op_type'] == "wrapprivatekey":
    try:
      response = POSTData(
        payload=payload,
        cm_node=kwargs["node"],
        cm_api_endpoint="cckm/GoogleWorkspaceCSE/endpoints/" + kwargs['id'] + "/wrapprivatekey",
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
        cm_api_endpoint="cckm/GoogleWorkspaceCSE/endpoints/" + kwargs['id'] + "/" + kwargs['endpoint_op_type'],
      )          
      return ast.literal_eval(str(response))
    except CMApiException as api_e:
      raise
    except AnsibleCMException as custom_e:
      raise