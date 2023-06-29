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

from ansible_collections.thalesgroup.ciphertrust.plugins.module_utils.cm_api import POSTData
from ansible_collections.thalesgroup.ciphertrust.plugins.module_utils.exceptions import CMApiException, AnsibleCMException

def is_json(myjson):
  try:
    json.loads(myjson)
  except ValueError as e:
    return False
  return True

# Utils function to create a new single node cluster
# Node information is required as an argument to this method
def new(**kwargs):
  result = dict()
  request = {}

  node = kwargs['node']
  cm = ast.literal_eval(node)
  
  request["localNodeHost"] = cm["server_private_ip"]
  request["localNodePort"] = cm["server_port"]
  request["publicAddress"] = cm["server_ip"]
  payload = json.dumps(request)

  try:
    response = POSTData(
          payload=payload,
          cm_node=kwargs['node'],
          cm_api_endpoint="cluster/new",
      )
    return 'Cluster creation initiated successfully!'
  except CMApiException as api_e:
    raise
  except AnsibleCMException as custom_e:
    raise

def csr(**kwargs):
  master = kwargs['master']
  node = kwargs['node']

  master_cm = ast.literal_eval(master)
  node_cm = ast.literal_eval(node)
  
  request = {}
  request["localNodeHost"] = node_cm["server_private_ip"]
  request["publicAddress"] = master_cm["server_ip"]
  payload = json.dumps(request)

  try:
      response = POSTData(
          payload=payload,
          cm_node=node,
          cm_api_endpoint="cluster/csr"
      )
      return response["csr"]
  except CMApiException as api_e:
    raise
  except AnsibleCMException as custom_e:
    raise

def sign(**kwargs):
  master = kwargs['master']
  node = kwargs['node']
  csr = kwargs['csr']

  master_cm = ast.literal_eval(master)
  node_cm = ast.literal_eval(node)

  result=dict()
  request = {}
  request["csr"] = csr
  request["shared_hsm_partition"] = False
  request["newNodeHost"] = node_cm["server_private_ip"]
  request["publicAddress"] = master_cm["server_ip"]
  payload = json.dumps(request)

  try:
      response = POSTData(
          payload=payload,
          cm_node=master,
          cm_api_endpoint="nodes"
      )
      return response
  except CMApiException as api_e:
    raise
  except AnsibleCMException as custom_e:
    raise

def join(master, node, cert, caChain, mkek_blob):
  master = kwargs['master']
  node = kwargs['node']
  cert = kwargs['cert']
  caChain = kwargs['caChain']
  mkek_blob = kwargs['mkek_blob']
  
  master_cm = ast.literal_eval(master)
  node_cm = ast.literal_eval(node)
  
  result = dict()
  request = {}

  request["cert"] = cert
  request["cachain"] = caChain
  request["localNodeHost"] = node_cm["server_private_ip"]
  request["localNodePort"] = 5432
  request["localNodePublicAddress"] = node_cm["server_ip"]
  request["memberNodeHost"] = master_cm["server_private_ip"]
  request["memberNodePort"] = 5432
  request["mkek_blob"] = mkek_blob
  request["blocking"] = False

  payload = json.dumps(request)

  try:
      response = POSTData(
              payload=payload,
              cm_node=node,
              cm_api_endpoint="cluster/join"
          )
      return response
  except CMApiException as api_e:
    raise
  except AnsibleCMException as custom_e:
    raise