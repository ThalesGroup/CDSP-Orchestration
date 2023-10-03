#!/usr/bin/python
# -*- coding: utf-8 -*-
#
# (c) 2023 Thales Group. All rights reserved.
# Author: Anurag Jain, Developer Advocate, Thales
#
# Licensed under the MIT License
#

from __future__ import absolute_import, division, print_function
__metaclass__ = type

import json
import ast

from ansible_collections.thalesgroup.ctvl.plugins.module_utils.ctvl_api import POSTData, PATCHData, DeleteByID
from ansible_collections.thalesgroup.ctvl.plugins.module_utils.exceptions import CTVLApiException, AnsibleCTVLException

def createCTVLAsset(**kwargs):
  request = {}
  for key, value in kwargs.items():
    if key not in ['server', 'type'] and value != None:
      request[key] = value

  payload = request
  
  endpoint = ''  
  identifier = ''
  type=kwargs['type']
  
  if type == "key": 
    endpoint = 'keys/'
    identifier = 'idkey'
  elif type == "token_group":
    endpoint = 'tokengroups'
    identifier = 'idtenant'
  elif type == "token_template":
    endpoint = 'tokentemplates'
    identifier = 'idtokentemplate'
  elif type == "mask":
    endpoint = 'masks'
    identifier = 'idmask'
  elif type == "charset":
    endpoint = 'charsets'
    identifier = 'idtokencharset'
  elif type == "group":
    endpoint = 'groups'
    identifier = 'id'
  elif type == "user":
    endpoint = "users"
    identifier = 'id'
  elif type == "token":
    endpoint = 'tokenize'
    identifier = 'token'
  elif type == "data":
    endpoint = "detokenize"
    identifier = 'data'
  else:
    raise AnsibleCTVLException(message="invalid CTVL asset type")

  try:
    response = POSTData(
      payload=payload,
      ctvl_server=kwargs["server"],
      ctvl_api_endpoint=endpoint,
      id=identifier,
    )          
    return ast.literal_eval(str(response))
  except CTVLApiException as api_e:
    raise
  except AnsibleCTVLException as custom_e:
    raise

def patchCTVLAsset(**kwargs):
  request = {}
  for key, value in kwargs.items():
    if key not in ['server', 'id', 'type'] and value != None:
      request[key] = value

  payload = json.dumps(request)
  
  endpoint = ''  
  type=kwargs['type']

  if type == "key":
    endpoint = "key/" + kwargs['id']
  elif type == "token_group":
    endpoint = "tokengroups/" + kwargs['id']
  elif type == "token_template":
    endpoint = "tokentemplates/" + kwargs['id']
  elif type == "mask":
    endpoint = "masks/" + kwargs['id']
  elif type == "charset":
    endpoint = "charsets/" + kwargs['id']
  elif type == "group":
    endpoint = "groups/" + kwargs['id']
  elif type == "user":
    endpoint = "users/" + kwargs['id']
  else:
    raise AnsibleCTVLException(message="invalid asset type")

  try:
    response = PATCHData(
      payload=payload,
      ctvl_server=kwargs["server"],
      ctvl_api_endpoint=endpoint,
    )          
    return ast.literal_eval(str(response))
  except CTVLApiException as api_e:
    raise
  except AnsibleCTVLException as custom_e:
    raise
  

# Delete resource on CT-VL by the ID of the resource
def deleteCTVLAsset(**kwargs):
  request = {}
  for key, value in kwargs.items():
    if key not in ['server', 'id', 'type'] and value != None:
      request[key] = value

  #payload = json.dumps(request)
  
  endpoint = ''  
  type=kwargs['type']

  if type == "key":
    endpoint = "key/" + kwargs['id']
  elif type == "token_group":
    endpoint = "tokengroups/" + kwargs['id']
  elif type == "token_template":
    endpoint = "tokentemplates/" + kwargs['id']
  elif type == "mask":
    endpoint = "masks/" + kwargs['id']
  elif type == "charset":
    endpoint = "charsets/" + kwargs['id']
  elif type == "group":
    endpoint = "groups/" + kwargs['id']
  elif type == "user":
    endpoint = "users/" + kwargs['id']
  else:
    raise AnsibleCTVLException(message="invalid asset type")

  try:
    response = DeleteByID(
      key=kwargs['id'],
      ctvl_server=kwargs["server"],
      ctvl_api_endpoint=endpoint,
    )          
    return ast.literal_eval(str(response))
  except CTVLApiException as api_e:
    raise
  except AnsibleCTVLException as custom_e:
    raise