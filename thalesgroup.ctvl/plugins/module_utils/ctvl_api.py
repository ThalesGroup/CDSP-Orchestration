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

import requests
import urllib3
import json
import ast
import re
import sys

from ansible_collections.thalesgroup.ctvl.plugins.module_utils.exceptions import CTVLApiException, AnsibleCTVLException

def is_json(json):
  try:
    json.loads(json)
  except ValueError as e:
    return False
  return True

def getJwt(url, username, password):
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
    auth_url='https://' + url + '/api/api-token-auth/'
    auth_payload = json.dumps({
        "username": username,
        "password": password,
    })
    headers = {
        'Content-Type': 'application/json'
    }
    response = requests.request("POST", url=auth_url, headers=headers, data=auth_payload, verify=False)
    print(response, file=sys.stderr)
    return response.json()["token"]

def CTVLAPIObject(username=None, password=None, url=None, api_endpoint=None, verify=None):
    """Create a CTVL API client"""
    session=dict()
    session["url"] = 'https://' + url + '/api/' + api_endpoint
    session["headers"] = {
       "Content-Type": "application/json; charset=utf-8",
       "Authorization": "Bearer " + getJwt(url, username, password),
    }
    return session

# Returns the whole response object
def POSTData(payload=None, ctvl_server=None, ctvl_api_endpoint=None, id=None):
    # Create the session object
    node = ast.literal_eval(ctvl_server)
    pattern_2xx = re.compile(r'20[0-9]')
    pattern_4xx = re.compile(r'40[0-9]')
    session = CTVLAPIObject(
        username=node["username"],
        password=node["password"],
        url=node["url"],
        api_endpoint=ctvl_api_endpoint,
        verify=node["ssl_verify"],
    )
    # execute the post API call to create the resource on CM 
    try:
      _data = requests.request(
        "POST",
        url=session["url"], 
        headers=session["headers"], 
        data = json.dumps(payload), 
        verify=session["verify"]
      )

      print(_data, file=sys.stderr)
      response = _data.json()      

      if id is not None and id in response:
        __ret = {
          "id": response[id],
          "data": response,
          "message": "Resource created successfully"
        }
      else:
        if "codeDesc" in json.dumps(response):
            raise CTVLApiException(message="Error creating resource < " + response["codeDesc"] + " >", api_error_code=_data.status_code)
        else:
            if id is None:
                if pattern_2xx.search(str(response)) or pattern_2xx.search(str(_data.status_code)):
                  __ret = {
                    "message": "Resource created successfully",
                    "description": str(response)
                  }
                elif pattern_4xx.search(str(response)) or pattern_4xx.search(str(_data.status_code)):
                    raise CTVLApiException(message="Error creating resource " + str(response), api_error_code=_data.status_code)
                else:
                    raise CTVLApiException(message="Error creating resource " + str(response), api_error_code=_data.status_code)
            else:
                raise CTVLApiException(message="Error creating resource " + str(response), api_error_code=_data.status_code)

      return __ret
    except requests.exceptions.HTTPError as errh:
      raise AnsibleCTVLException(message="HTTPError: cm_api >> " + errh)
    except requests.exceptions.ConnectionError as errc:
      raise AnsibleCTVLException(message="ConnectionError: cm_api >> " + errc)
    except requests.exceptions.Timeout as errt:
      raise AnsibleCTVLException(message="TimeoutError: cm_api >> " + errt)
    except requests.exceptions.RequestException as err:
      raise AnsibleCTVLException(message="ErrorPath: cm_api >> " + err)

def PATCHData(payload=None, ctvl_server=None, ctvl_api_endpoint=None):
    # Create the session object
    node = ast.literal_eval(ctvl_server)
    pattern_2xx = re.compile(r'20[0-9]')
    pattern_4xx = re.compile(r'40[0-9]')
    session = CTVLAPIObject(
        username=node["username"],
        password=node["password"],
        url=node["url"],
        api_endpoint=ctvl_api_endpoint,
        verify=node["ssl_verify"],
    )
    # execute the patch API call to update the resource on CM 
    try:
      response = requests.put(
        session["url"], 
        headers=session["headers"], 
        json = json.loads(payload), 
        verify=session["verify"]
      )

      if is_json(str(response)): 
        if "codeDesc" in response.json:
          raise CTVLApiException(message="Error updating resource < " + response["codeDesc"] + " >", api_error_code=response.status_code)
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
          raise CTVLApiException(message="Error updating resource " + str(response), api_error_code=response.status_code)
        else:
          raise CTVLApiException(message="Error updating resource " + str(response), api_error_code=response.status_code)           

      return __ret
    except requests.exceptions.HTTPError as errh:
      raise AnsibleCTVLException(message="HTTPError: cm_api >> " + errh)
    except requests.exceptions.ConnectionError as errc:
      raise AnsibleCTVLException(message="ConnectionError: cm_api >> " + errc)
    except requests.exceptions.Timeout as errt:
      raise AnsibleCTVLException(message="TimeoutError: cm_api >> " + errt)
    except requests.exceptions.RequestException as err:
      raise AnsibleCTVLException(message="ErrorPath: cm_api >> " + err)
    
def DeleteByID(key=None, ctvl_server=None, ctvl_api_endpoint=None):
    # Create the session object
    node = ast.literal_eval(ctvl_server)
    pattern_2xx = re.compile(r'20[0-9]')
    pattern_4xx = re.compile(r'40[0-9]')
    cmSessionObject = CTVLAPIObject(
      username=node["username"],
      password=node["password"],
      url=node["url"],
      api_endpoint=ctvl_api_endpoint,
      verify=node["ssl_verify"],
    )
    # execute the delete API call to delete the resource on CM
    try:
      response = requests.delete(cmSessionObject["url"] + "/" + key, headers=cmSessionObject["headers"], verify=False)
      if is_json(str(response)): 
        if "codeDesc" in response.json:
          raise CTVLApiException(message="Error deleting resource < " + response["codeDesc"] + " >", api_error_code=response.status_code)
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
          raise CTVLApiException(message="Error deleting resource " + str(response), api_error_code=response.status_code)
        else:
          raise CTVLApiException(message="Error deleting resource " + str(response), api_error_code=response.status_code)

      return __ret
    except requests.exceptions.HTTPError as errh:
      raise AnsibleCTVLException(message="HTTPError: cm_api >> " + errh)
    except requests.exceptions.ConnectionError as errc:
      raise AnsibleCTVLException(message="ConnectionError: cm_api >> " + errc)
    except requests.exceptions.Timeout as errt:
      raise AnsibleCTVLException(message="TimeoutError: cm_api >> " + errt)
    except requests.exceptions.RequestException as err:
      raise AnsibleCTVLException(message="ErrorPath: cm_api >> " + err)