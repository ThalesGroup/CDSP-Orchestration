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

from ansible_collections.thales.ciphertrust.plugins.module_utils.cm_api import POSTData, PATCHData, POSTWithoutData, DeleteWithoutData
from ansible_collections.thales.ciphertrust.plugins.module_utils.exceptions import CMApiException, AnsibleCMException

def is_json(myjson):
  try:
    json.loads(myjson)
  except ValueError as e:
    return False
  return True

def create(**kwargs):
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
      cm_api_endpoint="usermgmt/groups",
      id="name",
    )          
    return ast.literal_eval(str(response))
  except CMApiException as api_e:
    raise
  except AnsibleCMException as custom_e:
    raise

def patch(**kwargs):
  result = dict()
  request = {}

  for key, value in kwargs.items():
    if key not in ["node", "old_name"] and value != None:
      request[key] = value

  payload = json.dumps(request)

  try:
    response = PATCHData(
      payload=payload,
      cm_node=kwargs['node'],
      cm_api_endpoint="usermgmt/groups/" + kwargs['old_name'],
    )
    return ast.literal_eval(str(response))
  except CMApiException as api_e:
    raise
  except AnsibleCMException as custom_e:
    raise

def addUserToGroup(**kwargs):
  url = "usermgmt/groups/" + kwargs['name'] + "/users/" + kwargs['object_id']

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

def addClientToGroup(**kwargs):
  url = "client-management/groups/" + kwargs['name'] + "/clients/" + kwargs['object_id']

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

def deleteUserFromGroup(**kwargs):
  url = "usermgmt/groups/" + kwargs['name'] + "/users/" + kwargs['object_id']

  try:
    response = DeleteWithoutData(
      cm_node=kwargs['node'],
      cm_api_endpoint=url,
    )
    return str(response)
  except CMApiException as api_e:
    raise
  except AnsibleCMException as custom_e:
    raise

def deleteClientFromGroup(**kwargs):
  url = "client-management/groups/" + kwargs['name'] + "/clients/" + kwargs['object_id']

  try:
    response = DeleteWithoutData(
      cm_node=kwargs['node'],
      cm_api_endpoint=url,
    )
    return str(response)
  except CMApiException as api_e:
    raise
  except AnsibleCMException as custom_e:
    raise