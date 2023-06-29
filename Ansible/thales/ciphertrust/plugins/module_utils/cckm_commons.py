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

from ansible_collections.thalesgroup.ciphertrust.plugins.module_utils.cm_api import POSTData, PATCHData, POSTWithoutData
from ansible_collections.thalesgroup.ciphertrust.plugins.module_utils.exceptions import CMApiException, AnsibleCMException

def addCCKMCloudAsset(**kwargs):
  request = {}
  for key, value in kwargs.items():
    if key not in ['node', 'cloud_type', 'asset_type'] and value != None:
      request[key] = value

  payload = json.dumps(request)
  
  endpoint = ''  
  resource_type=kwargs['asset_type']
  cloud=kwargs['cloud_type']

  if cloud == "az": 
    if resource_type == "vault":
      endpoint = 'cckm/azure/add-vaults'
    elif resource_type == "certificate":
      endpoint = 'cckm/azure/certificates'
    elif resource_type == "key":
      endpoint = 'cckm/azure/keys'
    elif resource_type == "secret":
      endpoint = 'cckm/azure/secrets'
    else:
      raise AnsibleCMException(message="invalid asset type")
  elif cloud == "aws":
    if resource_type == "cks":
      endpoint = 'cckm/aws/custom-key-stores'
    elif resource_type == "virtual-key":
      endpoint = 'cckm/virtual/keys'
    elif resource_type == "hyok-key":
      endpoint = 'cckm/aws/create-hyok-key'
    elif resource_type == "key":
      endpoint = 'cckm/aws/keys'
    elif resource_type == "template":
      endpoint = 'cckm/aws/templates'
    elif resource_type == "kms":
      endpoint = 'cckm/aws/kms'
    else:
      raise AnsibleCMException(message="invalid asset type")
  elif cloud == "gcp":
    if resource_type == "ekm":
      endpoint = 'cckm/ekm/endpoints'
    elif resource_type == "project":
      endpoint = 'cckm/google/projects'
    elif resource_type == "key":
      endpoint = 'cckm/google/keys'
    elif resource_type == "keyring":
      endpoint = 'cckm/google/add-key-rings'
    elif resource_type == "workspace":
      endpoint = 'cckm/GoogleWorkspaceCSE/issuers'
    elif resource_type == "workspace_endpoint":
      endpoint = 'cckm/GoogleWorkspaceCSE/endpoints'
    else:
      raise AnsibleCMException(message="invalid asset type")
  else:
      raise AnsibleCMException(message="Cloud provider not supported")

  try:
    response = POSTData(
      payload=payload,
      cm_node=kwargs["node"],
      cm_api_endpoint=endpoint,
      id="id",
    )          
    return ast.literal_eval(str(response))
  except CMApiException as api_e:
    raise
  except AnsibleCMException as custom_e:
    raise

def editCCKMCloudAsset(**kwargs):
  request = {}
  for key, value in kwargs.items():
    if key not in ['node', 'id', 'cloud_type', 'asset_type'] and value != None:
      request[key] = value

  payload = json.dumps(request)
  
  endpoint = ''  
  resource_type=kwargs['asset_type']
  cloud=kwargs['cloud_type']

  if cloud == "az": 
    if resource_type == "vault":
      endpoint = "cckm/azure/vaults/" + kwargs['id']
    elif resource_type == "certificate":
      endpoint = "cckm/azure/certificates/" + kwargs['id']
    elif resource_type == "key":
      endpoint = "cckm/azure/keys/" + kwargs['id']
    elif resource_type == "secret":
      endpoint = "cckm/azure/secrets/" + kwargs['id']
    else:
      raise AnsibleCMException(message="invalid asset type")
  elif cloud == "aws":
    if resource_type == "cks":
      endpoint = 'cckm/aws/custom-key-stores/' + kwargs['id']
    elif resource_type == "virtual-key":
      endpoint = 'cckm/virtual/keys/' + kwargs['id']
    elif resource_type == "template":
      endpoint = 'cckm/aws/templates/' + kwargs['id']
    elif resource_type == "kms":
      endpoint = 'cckm/aws/kms/' + kwargs['id']
    else:
      raise AnsibleCMException(message="invalid asset type")
  elif cloud == "gcp":
    if resource_type == "ekm":
      endpoint = 'cckm/ekm/endpoints/' + kwargs['id']
    elif resource_type == "key":
      endpoint = 'cckm/google/keys/' + kwargs['id']
    elif resource_type == "keyring":
      endpoint = 'cckm/google/key-rings' + kwargs['id']
    elif resource_type == "workspace_endpoint":
      endpoint = 'cckm/GoogleWorkspaceCSE/endpoints' + kwargs['id']
    else:
      raise AnsibleCMException(message="invalid asset type")
  else:
      raise AnsibleCMException(message="Cloud provider not supported")

  try:
    response = PATCHData(
      payload=payload,
      cm_node=kwargs["node"],
      cm_api_endpoint=endpoint,
    )          
    return ast.literal_eval(str(response))
  except CMApiException as api_e:
    raise
  except AnsibleCMException as custom_e:
    raise

def createSyncJob(**kwargs):
  request = {}

  for key, value in kwargs.items():
    if key not in ['node', 'cloud_type', 'asset_type'] and value != None:
      request[key] = value

  payload = json.dumps(request)

  endpoint = ''  
  resource_type=kwargs['asset_type']
  cloud=kwargs['cloud_type']

  if cloud == "az":
    if resource_type == "certificate":
      endpoint = "cckm/azure/certificates/synchronization-jobs"
    elif resource_type == "key":
      endpoint = "cckm/azure/synchronization-jobs"
    elif resource_type == "secret":
      endpoint = "cckm/azure/secrets/synchronization-jobs"
    else:
      raise AnsibleCMException(message="invalid asset type")
  elif cloud == "aws":
    if resource_type == "cks":
      endpoint = 'cckm/aws/custom-key-stores/synchronization-jobs'
    elif resource_type == "key":
      endpoint = 'cckm/aws/synchronization-jobs'
    else:
      raise AnsibleCMException(message="invalid asset type")
  elif cloud == "gcp":
    if resource_type == "key":
      endpoint = 'cckm/google/synchronization-jobs'
    else:
      raise AnsibleCMException(message="invalid asset type")
  else:
      raise AnsibleCMException(message="Cloud provider not supported")

  try:
    response = POSTData(
      payload=payload,
      cm_node=kwargs["node"],
      cm_api_endpoint=endpoint,
      id="id",
    )          
    return ast.literal_eval(str(response))
  except CMApiException as api_e:
    raise
  except AnsibleCMException as custom_e:
    raise

def cancelSyncJob(**kwargs):
  request = {}

  for key, value in kwargs.items():
    if key not in ['node', 'id', 'cloud_type', 'asset_type'] and value != None:
      request[key] = value

  endpoint = ''  
  resource_type=kwargs['asset_type']
  cloud=kwargs['cloud_type']

  if cloud == "az":
    if resource_type == "certificate":
      endpoint = "cckm/azure/certificates/synchronization-jobs/" + kwargs['id'] + "/cancel"
    elif resource_type == "key":
      endpoint = "cckm/azure/synchronization-jobs/" + kwargs['id'] + "/cancel"
    elif resource_type == "secret":
      endpoint = "cckm/azure/secrets/synchronization-jobs/" + kwargs['id'] + "/cancel"
    else:
      raise AnsibleCMException(message="invalid asset type")
  elif cloud == "aws":
    if resource_type == "cks":
      endpoint = "cckm/aws/custom-key-stores/synchronization-jobs/" + kwargs['id'] + "/cancel"
    elif resource_type == "key":
      endpoint = "cckm/aws/synchronization-jobs/" + kwargs['id'] + "/cancel"
    else:
      raise AnsibleCMException(message="invalid asset type")
  elif cloud == "gcp":
    if resource_type == "key":
      endpoint = "cckm/google/synchronization-jobs" + kwargs['id'] + "/cancel"
    else:
      raise AnsibleCMException(message="invalid asset type")
  else:
      raise AnsibleCMException(message="Cloud provider not supported")

  try:
    response = POSTWithoutData(
      cm_node=kwargs["node"],
      cm_api_endpoint=endpoint,
    )          
    return ast.literal_eval(str(response))
  except CMApiException as api_e:
    raise
  except AnsibleCMException as custom_e:
    raise