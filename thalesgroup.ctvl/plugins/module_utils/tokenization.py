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

from ansible_collections.thalesgroup.ctvl.plugins.module_utils.ctvl_api import POSTDataWithBasicAuth
from ansible_collections.thalesgroup.ctvl.plugins.module_utils.exceptions import CTVLApiException, AnsibleCTVLException

def tokenize(**kwargs):
  request = {}
  for key, value in kwargs.items():
    if key not in ['server'] and value != None:
      request[key] = value

  payload = request
  
  endpoint = 'tokenize'
  identifier = 'token'

  try:
    response = POSTDataWithBasicAuth(
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

def detokenize(**kwargs):
  request = {}
  for key, value in kwargs.items():
    if key not in ['server'] and value != None:
      request[key] = value

  payload = request
  
  endpoint = 'detokenize'  
  identifier = 'data'

  try:
    response = POSTDataWithBasicAuth(
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