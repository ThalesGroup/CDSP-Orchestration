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
import re

from ansible_collections.thalesgroup.ciphertrust.plugins.module_utils.exceptions import CMApiException, AnsibleCMException

def is_json(myjson):
  try:
    json.loads(myjson)
  except ValueError as e:
    return False
  return True

def getJwt(host, username, password):
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
    auth_url='https://'+host+'/api/v1/auth/tokens'
    auth_payload = {
        "grant_type":"password",
        "username":username,
        "password":password,
    }
    response = requests.post(auth_url, json=auth_payload, verify=False)
    return response.json()["jwt"]

# This will never return the ID
# There will be a separate call to be made to get the ID
def POSTDataOld(payload=None, cm_node=None, cm_api_endpoint=None):
    # Create the session object
    node = ast.literal_eval(cm_node)
    cmSessionObject = CMAPIObject(
            cm_api_user=node["user"],
            cm_api_pwd=node["password"],
            cm_url=node["server_ip"],
            cm_api_endpoint=cm_api_endpoint,
            verify=False,
        )
    # execute the post API call to create the resource on CM 
    try:
      response = requests.post(
        cmSessionObject["url"], 
        headers=cmSessionObject["headers"], 
        json = json.loads(payload), 
        verify=False)
      if "codeDesc" in response.json():
          codeDesc=response.json()["codeDesc"]
          if 'NCERRKeyAlreadyExists' in codeDesc:
              return '4xx'
          if 'NCERRConflict' in codeDesc:
              return '4xx'
      else:
          return response.json()
    except requests.exceptions.RequestException as err:
        raise

# Returns the whole response object
def POSTData(payload=None, cm_node=None, cm_api_endpoint=None, id=None):
    # Create the session object
    node = ast.literal_eval(cm_node)
    pattern_2xx = re.compile(r'20[0-9]')
    pattern_4xx = re.compile(r'40[0-9]')
    cmSessionObject = CMAPIObject(
            cm_api_user=node["user"],
            cm_api_pwd=node["password"],
            cm_url=node["server_ip"],
            cm_api_endpoint=cm_api_endpoint,
            verify=False,
        )
    # execute the post API call to create the resource on CM 
    try:
      _data = requests.post(
        cmSessionObject["url"], 
        headers=cmSessionObject["headers"], 
        json = json.loads(payload), 
        verify=False)

      response = _data.json()

      if id is not None and id in response:
        __ret = {
          "id": response[id],
          "data": response,
          "message": "Resource created successfully"
        }
      else:
        if "codeDesc" in json.dumps(response):
            raise CMApiException(message="Error creating resource < " + response["codeDesc"] + " >", api_error_code=_data.status_code)
        else:
            if id is None:
                if pattern_2xx.search(str(response)) or pattern_2xx.search(str(_data.status_code)):
                  __ret = {
                    "message": "Resource created successfully",
                    "description": str(response)
                  }
                elif pattern_4xx.search(str(response)) or pattern_4xx.search(str(_data.status_code)):
                    raise CMApiException(message="Error creating resource " + str(response), api_error_code=_data.status_code)
                else:
                    raise CMApiException(message="Error creating resource " + str(response), api_error_code=_data.status_code)
            else:
                raise CMApiException(message="Error creating resource " + str(response), api_error_code=_data.status_code)

      return __ret
    except requests.exceptions.HTTPError as errh:
      raise AnsibleCMException(message="HTTPError: cm_api >> " + errh)
    except requests.exceptions.ConnectionError as errc:
      raise AnsibleCMException(message="ConnectionError: cm_api >> " + errc)
    except requests.exceptions.Timeout as errt:
      raise AnsibleCMException(message="TimeoutError: cm_api >> " + errt)
    except requests.exceptions.RequestException as err:
      raise AnsibleCMException(message="ErrorPath: cm_api >> " + err)

# Added to support PUT operation
def PUTData(payload=None, cm_node=None, cm_api_endpoint=None):
    # Create the session object
    node = ast.literal_eval(cm_node)
    pattern_2xx = re.compile(r'20[0-9]')
    pattern_4xx = re.compile(r'40[0-9]')
    cmSessionObject = CMAPIObject(
      cm_api_user=node["user"],
      cm_api_pwd=node["password"],
      cm_url=node["server_ip"],
      cm_api_endpoint=cm_api_endpoint,
      verify=False,
    )
    # execute the put API call to update resource on CM 
    try:
      response = requests.put(
        cmSessionObject["url"], 
        headers=cmSessionObject["headers"], 
        json = json.loads(payload), 
        verify=False)

      if is_json(str(response)): 
        if "codeDesc" in response.json:
          raise CMApiException(message="Error updating resource < " + response["codeDesc"] + " >", api_error_code=response.status_code)
        else:
          __ret = {
            "message": "Resource updated successfully",
          }
      else:
        if pattern_2xx.search(str(response)):
          __ret = {
            "message": "Resource updated successfully",
            "description": str(response)
          }
        elif pattern_4xx.search(str(response)):
          raise CMApiException(message="Error updating resource " + str(response), api_error_code=response.status_code)
        else:
          raise CMApiException(message="Error updating resource " + str(response), api_error_code=response.status_code)

      return __ret
    except requests.exceptions.HTTPError as errh:
      raise AnsibleCMException(message="HTTPError: cm_api >> " + errh)
    except requests.exceptions.ConnectionError as errc:
      raise AnsibleCMException(message="ConnectionError: cm_api >> " + errc)
    except requests.exceptions.Timeout as errt:
      raise AnsibleCMException(message="TimeoutError: cm_api >> " + errt)
    except requests.exceptions.RequestException as err:
      raise AnsibleCMException(message="ErrorPath: cm_api >> " + err)


def POSTWithoutData(cm_node=None, cm_api_endpoint=None):
    # Create the session object
    node = ast.literal_eval(cm_node)
    pattern_2xx = re.compile(r'20[0-9]')
    pattern_4xx = re.compile(r'40[0-9]')
    cmSessionObject = CMAPIObject(
            cm_api_user=node["user"],
            cm_api_pwd=node["password"],
            cm_url=node["server_ip"],
            cm_api_endpoint=cm_api_endpoint,
            verify=False,
        )
    # execute the post API call to create the resource on CM 
    try:
      response = requests.post(
        cmSessionObject["url"], 
        headers=cmSessionObject["headers"], 
        verify=False)

      if is_json(str(response)): 
        if "codeDesc" in response.json:
          raise CMApiException(message="Error creating resource < " + response["codeDesc"] + " >", api_error_code=response.status_code)
        else:
          __ret = {
            "message": "Resource created successfully",
          }
      else:
        if pattern_2xx.search(str(response)):
          __ret = {
            "message": "Resource created successfully",
            "description": str(response)
          }
        elif pattern_4xx.search(str(response)):
          raise CMApiException(message="Error creating resource " + str(response), api_error_code=response.status_code)
        else:
          raise CMApiException(message="Error creating resource " + str(response), api_error_code=response.status_code)

      return __ret
    except requests.exceptions.HTTPError as errh:
      raise AnsibleCMException(message="HTTPError: cm_api >> " + errh)
    except requests.exceptions.ConnectionError as errc:
      raise AnsibleCMException(message="ConnectionError: cm_api >> " + errc)
    except requests.exceptions.Timeout as errt:
      raise AnsibleCMException(message="TimeoutError: cm_api >> " + errt)
    except requests.exceptions.RequestException as err:
      raise AnsibleCMException(message="ErrorPath: cm_api >> " + err)

def PATCHData(payload=None, cm_node=None, cm_api_endpoint=None):
    # Create the session object
    node = ast.literal_eval(cm_node)
    pattern_2xx = re.compile(r'20[0-9]')
    pattern_4xx = re.compile(r'40[0-9]')
    cmSessionObject = CMAPIObject(
            cm_api_user=node["user"],
            cm_api_pwd=node["password"],
            cm_url=node["server_ip"],
            cm_api_endpoint=cm_api_endpoint,
            verify=False,
        )
    # execute the patch API call to update the resource on CM 
    try:
      response = requests.patch(
        cmSessionObject["url"], 
        headers=cmSessionObject["headers"], 
        json = json.loads(payload), 
        verify=False)

      if is_json(str(response)): 
        if "codeDesc" in response.json:
          raise CMApiException(message="Error creating resource < " + response["codeDesc"] + " >", api_error_code=response.status_code)
        else:
          __ret = {
            "message": "Resource updated successfully",
          }
      else:
        if pattern_2xx.search(str(response)):
          __ret = {
            "message": "Resource updated successfully",
            "status_code": str(response)
          }
        elif pattern_4xx.search(str(response)):
          raise CMApiException(message="Error creating resource " + str(response), api_error_code=response.status_code)
        else:
          raise CMApiException(message="Error creating resource " + str(response), api_error_code=response.status_code)           

      return __ret
    except requests.exceptions.HTTPError as errh:
      raise AnsibleCMException(message="HTTPError: cm_api >> " + errh)
    except requests.exceptions.ConnectionError as errc:
      raise AnsibleCMException(message="ConnectionError: cm_api >> " + errc)
    except requests.exceptions.Timeout as errt:
      raise AnsibleCMException(message="TimeoutError: cm_api >> " + errt)
    except requests.exceptions.RequestException as err:
      raise AnsibleCMException(message="ErrorPath: cm_api >> " + err)

def DELETEByNameOrId(key=None, cm_node=None, cm_api_endpoint=None):
    # Create the session object
    node = ast.literal_eval(cm_node)
    pattern_2xx = re.compile(r'20[0-9]')
    pattern_4xx = re.compile(r'40[0-9]')
    cmSessionObject = CMAPIObject(
      cm_api_user=node["user"],
      cm_api_pwd=node["password"],
      cm_url=node["server_ip"],
      cm_api_endpoint=cm_api_endpoint,
      verify=False,
    )
    # execute the delete API call to delete the resource on CM
    try:
      response = requests.delete(cmSessionObject["url"] + "/" + key, headers=cmSessionObject["headers"], verify=False)
      if is_json(str(response)): 
        if "codeDesc" in response.json:
          raise CMApiException(message="Error deleting resource < " + response["codeDesc"] + " >", api_error_code=response.status_code)
        else:
          __ret = {
            "message": "Resource deletion successful",
          }
      else:
        if pattern_2xx.search(str(response)):
          __ret = {
            "message": "Resource deletion successful",
            "status_code": str(response)
          }
        elif pattern_4xx.search(str(response)):
          raise CMApiException(message="Error deleting resource " + str(response), api_error_code=response.status_code)
        else:
          raise CMApiException(message="Error deleting resource " + str(response), api_error_code=response.status_code)

      return __ret
    except requests.exceptions.HTTPError as errh:
      raise AnsibleCMException(message="HTTPError: cm_api >> " + errh)
    except requests.exceptions.ConnectionError as errc:
      raise AnsibleCMException(message="ConnectionError: cm_api >> " + errc)
    except requests.exceptions.Timeout as errt:
      raise AnsibleCMException(message="TimeoutError: cm_api >> " + errt)
    except requests.exceptions.RequestException as err:
      raise AnsibleCMException(message="ErrorPath: cm_api >> " + err)

def DeleteWithoutData(cm_node=None, cm_api_endpoint=None):
    # Create the session object
    node = ast.literal_eval(cm_node)
    pattern_2xx = re.compile(r'20[0-9]')
    pattern_4xx = re.compile(r'40[0-9]')
    cmSessionObject = CMAPIObject(
            cm_api_user=node["user"],
            cm_api_pwd=node["password"],
            cm_url=node["server_ip"],
            cm_api_endpoint=cm_api_endpoint,
            verify=False,
        )
    # execute the delete API call to delete the resource on CM
    try:
      response = requests.delete(cmSessionObject["url"], headers=cmSessionObject["headers"], verify=False)

      if is_json(str(response)):
          if "codeDesc" in response.json():
            raise CMApiException(message="Error creating resource < " + response["codeDesc"] + " >", api_error_code=response.status_code)
          else:
              return 'Resource deleted successfully'
      else:
          if pattern_2xx.search(str(response)):
              return 'Resource deleted successfully'
          elif pattern_4xx.search(str(response)):
            raise CMApiException(message="Error deleting resource " + str(response), api_error_code=response.status_code)
          else:
            raise CMApiException(message="Error deleting resource " + str(response), api_error_code=response.status_code)

    except requests.exceptions.HTTPError as errh:
      raise AnsibleCMException(message="HTTPError: cm_api >> " + errh)
    except requests.exceptions.ConnectionError as errc:
      raise AnsibleCMException(message="ConnectionError: cm_api >> " + errc)
    except requests.exceptions.Timeout as errt:
      raise AnsibleCMException(message="TimeoutError: cm_api >> " + errt)
    except requests.exceptions.RequestException as err:
      raise AnsibleCMException(message="ErrorPath: cm_api >> " + err)
    except json.decoder.JSONDecodeError as jsonErr:
        return jsonErr

def GETData(cm_node=None, cm_api_endpoint=None):
  # Create the session object
  node = ast.literal_eval(cm_node)
  cmSessionObject = CMAPIObject(
    cm_api_user=node["user"],
    cm_api_pwd=node["password"],
    cm_url=node["server_ip"],
    cm_api_endpoint=cm_api_endpoint,
    verify=False,
  )

  try:
    _data = requests.get(
      cmSessionObject["url"], 
      headers=cmSessionObject["headers"], 
      verify=False)

    response = _data.json()
    
    if response["resources"] == None:
      raise CMApiException(message="Error fetching data " + str(response), api_error_code=_data.status_code)

    if len(response["resources"]) > 0:
      __ret = {
        "id": response["resources"][0][id]
      }
    else:
      raise CMApiException(message="No records found", api_error_code=_data.status_code)

    return __ret
  except requests.exceptions.HTTPError as errh:
    raise AnsibleCMException(message="HTTPError: cm_api >> " + errh)
  except requests.exceptions.ConnectionError as errc:
    raise AnsibleCMException(message="ConnectionError: cm_api >> " + errc)
  except requests.exceptions.Timeout as errt:
    raise AnsibleCMException(message="TimeoutError: cm_api >> " + errt)
  except requests.exceptions.RequestException as err:
    raise AnsibleCMException(message="ErrorPath: cm_api >> " + err)

# Below method is outdated...need to be cleaned up later
def GETIdByName(name=None, cm_node=None, cm_api_endpoint=None):
    # Create the session object
    cmSessionObject = CMAPIObject(
            cm_api_user=cm_node["user"],
            cm_api_pwd=cm_node["password"],
            cm_url=cm_node["server_ip"],
            cm_api_endpoint=cm_api_endpoint,
            verify=False,
        )
    # execute the delete API call to delete the resource on CM
    ret=dict()
    try:
        response = requests.get(cmSessionObject["url"] + "/?skip=0&limit=1&name=" + name, headers=cmSessionObject["headers"], verify=False)
        if len(response.json()["resources"]) > 0:
            ret["id"]=response.json()["resources"][0]["id"]
            ret["status"]='2xx'
            return ret
        else:
            ret["status"]='4xx'
            ret["id"]=''
            return ret
    except requests.exceptions.RequestException as err:
        raise

def GETIdByQueryParam(param=None, value=None, cm_node=None, cm_api_endpoint=None, id=None):
    # Create the session object
    node = ast.literal_eval(cm_node)
    cmSessionObject = CMAPIObject(
      cm_api_user=node["user"],
      cm_api_pwd=node["password"],
      cm_url=node["server_ip"],
      cm_api_endpoint=cm_api_endpoint,
      verify=False,
    )

    url = ''
    if param == None:
      url = cmSessionObject["url"]
    else:
      url = cmSessionObject["url"] + "/?skip=0&limit=1&" + param + "=" + value

    try:
      _data = requests.get(
        url,
        headers=cmSessionObject["headers"], 
        verify=False)

      response = _data.json()
      
      if response["resources"] == None:
        raise CMApiException(message="Error fetching data " + str(response), api_error_code=_data.status_code)

      if len(response["resources"]) > 0:
        if id == None:
          return response
        else:
          __ret = {
            "id": response["resources"][0][id]
          }
      else:
        raise CMApiException(message="No matching records found", api_error_code=_data.status_code)

      return __ret
    except requests.exceptions.HTTPError as errh:
      raise AnsibleCMException(message="HTTPError: cm_api >> " + errh)
    except requests.exceptions.ConnectionError as errc:
      raise AnsibleCMException(message="ConnectionError: cm_api >> " + errc)
    except requests.exceptions.Timeout as errt:
      raise AnsibleCMException(message="TimeoutError: cm_api >> " + errt)
    except requests.exceptions.RequestException as err:
      raise AnsibleCMException(message="ErrorPath: cm_api >> " + err)

def CMAPIObject(cm_api_user=None, cm_api_pwd=None, cm_url=None, cm_api_endpoint=None, verify=None):
    """Create a Ciphertrust Manager (CM) client"""
    session=dict()
    session["url"] = 'https://' + cm_url + '/api/v1/' + cm_api_endpoint
    session["headers"] = {"Content-Type": "application/json; charset=utf-8","Authorization": "Bearer " + getJwt(cm_url, cm_api_user, cm_api_pwd),}
    return session