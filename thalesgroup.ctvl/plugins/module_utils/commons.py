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

from ansible_collections.thalesgroup.ctvl.plugins.module_utils.ctvl_api import POSTData, PATCHData
from ansible_collections.thalesgroup.ctvl.plugins.module_utils.exceptions import CTVLApiException, AnsibleCTVLException

def createCTVLAsset(**kwargs):
  request = {}
  for key, value in kwargs.items():
    if key not in ['server', 'type'] and value != None:
      request[key] = value

  payload = json.dumps(request)
  
  endpoint = ''  
  identifier = ''
  type=kwargs['type']
  
  if type == "key": 
    endpoint = 'keys'
    identifier = 'idkey'
  elif type == "token_group":
    endpoint = 'tokengroups'
    identifier = 'idtenant'
  elif type == "token_template":
    endpoint = 'tokentemplates'
    identifier = 'idtokentemplate'
  else:
    raise AnsibleCTVLException(message="invalid CTVL asset type")

  try:
    response = POSTData(
      payload=payload,
      ctvl_server=kwargs["server"],
      ctvl_api_endpoint=endpoint,
      ssl_verify=kwargs['ssl_verify'],
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
  else:
    raise AnsibleCTVLException(message="invalid asset type")

  try:
    response = PATCHData(
      payload=payload,
      ctvl_server=kwargs["server"],
      ctvl_api_endpoint=endpoint,
      ssl_verify=kwargs['ssl_verify'],
    )          
    return ast.literal_eval(str(response))
  except CTVLApiException as api_e:
    raise
  except AnsibleCTVLException as custom_e:
    raise