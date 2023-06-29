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

import os
import requests
import urllib3
import json
import ast

from ansible_collections.thalesgroup.ciphertrust.plugins.module_utils.cm_api import POSTData, GETData, POSTWithoutData, GETIdByQueryParam
from ansible_collections.thalesgroup.ciphertrust.plugins.module_utils.exceptions import CMApiException, AnsibleCMException

def is_json(myjson):
  try:
    json.loads(myjson)
  except ValueError as e:
    return False
  return True

def getLockdata(node):
    result = dict()

    try:
      response = GETData(
              cm_node=node,
              cm_api_endpoint="licensing/lockdata",
          )
      if response == '4xx':
          result['error'] = 'Failed to fetch data'
      else:
          result['data'] = response

      return result
    except:
      result['failed'] = True

def getTrialLicenseId(**kwargs):
  result = dict()
  request = {}

  try:
    response = GETIdByQueryParam(
      cm_node=kwargs["node"],
      cm_api_endpoint="licensing/trials",
    )

    #_json_response = json.loads(ast.literal_eval(str(response)))

    resources = response["resources"]
    __id = resources[0]["id"]
    __status = resources[0]["status"]
    result["id"] = __id
    result["status"] = __status

    return result
    
  except CMApiException as api_e:
    raise
  except AnsibleCMException as custom_e:
    raise

def addLicense(**kwargs):
  result = dict()
  request = {}

  for key, value in kwargs.items():
    if key != "node" and value != None:
      request[key] = value

  payload = json.dumps(request)

  try:
    response = POSTData(
      payload=payload,
      cm_node=kwargs["node"],
      cm_api_endpoint="vault/keys2",
    )
        
    return ast.literal_eval(str(response))
  except CMApiException as api_e:
    raise
  except AnsibleCMException as custom_e:
    raise

def activateTrial(**kwargs):
  result = dict()
  
  url = "licensing/trials/" + kwargs['trialId'] + "/activate"

  try:
    response = POSTWithoutData(
      cm_node=kwargs['node'],
      cm_api_endpoint=url,
    )
    return ast.literal_eval(str(response))
  except CMApiException as api_e:
    raise
  except AnsibleCMException as custom_e:
    raise

def deactivateTrial(**kwargs):
  result = dict()
  
  url = "licensing/trials/" + kwargs['trialId'] + "/deactivate"

  try:
    response = POSTWithoutData(
      cm_node=kwargs['node'],
      cm_api_endpoint=url,
    )
    return ast.literal_eval(str(response))
  except CMApiException as api_e:
    raise
  except AnsibleCMException as custom_e:
    raise