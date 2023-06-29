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

from ansible_collections.thalesgroup.ciphertrust.plugins.module_utils.cm_api import POSTData, POSTWithoutData, PATCHData
from ansible_collections.thalesgroup.ciphertrust.plugins.module_utils.exceptions import CMApiException, AnsibleCMException

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
              cm_api_endpoint="vault/keys2",
              id="id",
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
        if key not in ["node", "cm_key_id"] and value != None:
            request[key] = value

    payload = json.dumps(request)

    try:
      response = PATCHData(
              payload=payload,
              cm_node=kwargs['node'],
              cm_api_endpoint="vault/keys2/" + kwargs['cm_key_id'],
          )
      return ast.literal_eval(str(response))
    except CMApiException as api_e:
      raise
    except AnsibleCMException as custom_e:
      raise

def version_create(**kwargs):
    result = dict()
    request = {}

    for key, value in kwargs.items():
        if key not in ["node", "cm_key_id"] and value != None:
            request[key] = value

    payload = json.dumps(request)

    try:
      response = POSTData(
              payload=payload,
              cm_node=kwargs['node'],
              cm_api_endpoint="vault/keys2/" + kwargs['cm_key_id'] + "/versions",
              id="id",
          )
      return ast.literal_eval(str(response))
    except CMApiException as api_e:
      raise
    except AnsibleCMException as custom_e:
      raise

# destroy, archive, recover, revoke, reactivate, export, clone
def destroy(**kwargs):
    result = dict()
    request = {}
    queryString = "?"

    if kwargs['key_version'] != None:
        queryString = queryString + "version=" + kwargs['key_version']

    if kwargs['id_type'] != None:
        if queryString == "?":
            queryString = queryString + "type=" + kwargs['id_type']
        else:
            queryString = queryString + "&type=" + kwargs['id_type']

    if queryString == "?":
        url = "vault/keys2/" + kwargs['cm_key_id'] + "/destroy"
    else:
        url = "vault/keys2/" + kwargs['cm_key_id'] + "/destroy" + queryString

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

def archive(**kwargs):
    result = dict()
    request = {}
    queryString = "?"

    if kwargs['key_version'] != None:
        queryString = queryString + "version=" + kwargs['key_version']

    if kwargs['id_type'] != None:
        if queryString == "?":
            queryString = queryString + "type=" + kwargs['id_type']
        else:
            queryString = queryString + "&type=" + kwargs['id_type']

    if queryString == "?":
        url = "vault/keys2/" + kwargs['cm_key_id'] + "/archive"
    else:
        url = "vault/keys2/" + kwargs['cm_key_id'] + "/archive" + queryString

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

def recover(**kwargs):
    result = dict()
    request = {}
    queryString = "?"

    if kwargs['key_version'] != None:
        queryString = queryString + "version=" + kwargs['key_version']

    if kwargs['id_type'] != None:
        if queryString == "?":
            queryString = queryString + "type=" + kwargs['id_type']
        else:
            queryString = queryString + "&type=" + kwargs['id_type']

    if queryString == "?":
        url = "vault/keys2/" + kwargs['cm_key_id'] + "/recover"
    else:
        url = "vault/keys2/" + kwargs['cm_key_id'] + "/recover" + queryString

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

def revoke(**kwargs):
    result = dict()
    request = {}
    queryString = "?"

    for key, value in kwargs.items():
        if key not in ["node", "cm_key_id", "key_version", "id_type"] and value != None:
            request[key] = value

    payload = json.dumps(request)

    if kwargs['key_version'] != None:
        queryString = queryString + "version=" + kwargs['key_version']

    if kwargs['id_type'] != None:
        if queryString == "?":
            queryString = queryString + "type=" + kwargs['id_type']
        else:
            queryString = queryString + "&type=" + kwargs['id_type']

    if queryString == "?":
        url = "vault/keys2/" + kwargs['cm_key_id'] + "/revoke"
    else:
        url = "vault/keys2/" + kwargs['cm_key_id'] + "/revoke" + queryString

    try:
      response = POSTData(
              payload=payload,
              cm_node=kwargs["node"],
              cm_api_endpoint=url,
              id="id",
          )
          
      return ast.literal_eval(str(response))
    except CMApiException as api_e:
      raise
    except AnsibleCMException as custom_e:
      raise

def reactivate(**kwargs):
    result = dict()
    request = {}
    queryString = "?"

    for key, value in kwargs.items():
        if key not in ["node", "cm_key_id", "key_version", "id_type"] and value != None:
            request[key] = value

    payload = json.dumps(request)

    if kwargs['key_version'] != None:
        queryString = queryString + "version=" + kwargs['key_version']

    if kwargs['id_type'] != None:
        if queryString == "?":
            queryString = queryString + "type=" + kwargs['id_type']
        else:
            queryString = queryString + "&type=" + kwargs['id_type']

    if queryString == "?":
        url = "vault/keys2/" + kwargs['cm_key_id'] + "/reactivate"
    else:
        url = "vault/keys2/" + kwargs['cm_key_id'] + "/reactivate" + queryString

    try:
      response = POSTData(
              payload=payload,
              cm_node=kwargs["node"],
              cm_api_endpoint=url,
              id="id",
          )
          
      return ast.literal_eval(str(response))
    except CMApiException as api_e:
      raise
    except AnsibleCMException as custom_e:
      raise


def export(**kwargs):
    result = dict()
    request = {}
    queryString = "?"

    for key, value in kwargs.items():
        if key not in ["node", "cm_key_id", "key_version", "id_type"] and value != None:
            request[key] = value
        if key == "keyFormat":
            request["format"] = value

    payload = json.dumps(request)

    if kwargs['key_version'] != None:
        queryString = queryString + "version=" + kwargs['key_version']

    if kwargs['id_type'] != None:
        if queryString == "?":
            queryString = queryString + "type=" + kwargs['id_type']
        else:
            queryString = queryString + "&type=" + kwargs['id_type']

    if queryString == "?":
        url = "vault/keys2/" + kwargs['cm_key_id'] + "/export"
    else:
        url = "vault/keys2/" + kwargs['cm_key_id'] + "/export" + queryString

    try:
      response = POSTData(
              payload=payload,
              cm_node=kwargs["node"],
              cm_api_endpoint=url,
          )
          
      return ast.literal_eval(str(response))
    except CMApiException as api_e:
      raise
    except AnsibleCMException as custom_e:
      raise

def clone(**kwargs):
    result = dict()
    request = {}
    queryString = "?"

    for key, value in kwargs.items():
        if key not in ["node", "cm_key_id", "key_version", "id_type", "includeMaterial"] and value != None:
            request[key] = value

    payload = json.dumps(request)

    if kwargs['key_version'] != None:
        queryString = queryString + "version=" + kwargs['key_version']

    if kwargs['id_type'] != None:
        if queryString == "?":
            queryString = queryString + "type=" + kwargs['id_type']
        else:
            queryString = queryString + "&type=" + kwargs['id_type']
    
    if kwargs['includeMaterial'] != None:
        if queryString == "?":
            queryString = queryString + "includeMaterial=" + kwargs['includeMaterial']
        else:
            queryString = queryString + "&includeMaterial=" + kwargs['includeMaterial']

    if queryString == "?":
        url = "vault/keys2/" + kwargs['cm_key_id'] + "/clone"
    else:
        url = "vault/keys2/" + kwargs['cm_key_id'] + "/clone" + queryString

    try:
      response = POSTData(
              payload=payload,
              cm_node=kwargs["node"],
              cm_api_endpoint=url,
          )
          
      return ast.literal_eval(str(response))
    except CMApiException as api_e:
      raise
    except AnsibleCMException as custom_e:
      raise