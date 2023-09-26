#!/usr/bin/python
# -*- coding: utf-8 -*-
#
# (c) 2023 Thales Group. All rights reserved.
# Author: Anurag Jain, Developer Advocate, Thales
#
# Licensed under the MIT License
#

"""This module adds custom exceptions for Thales CT-VL modules.

In order to use this module, include it as part of a custom
module as shown below.
  from ansible_collections.thalesgroup.ctvl.plugins.module_utils.exceptions import CTVLApiException
"""

from ansible.module_utils._text import to_native

class CTVLApiException(Exception):

    def __str__(self):
        if self.api_error_code and self.message:
            return "{0}: {1}".format(self.api_error_code, self.message)

        return super().__str__()

    def __init__(self, message, api_error_code):
        if not message and not api_error_code:
            super().__init__()
        elif not message:
            super().__init__(api_error_code)
        else:
            super().__init__(message)

        self.message = message
        self.api_error_code = api_error_code

class AnsibleCTVLException(Exception):

    def __str__(self):
        if self.message:
            return "{0}".format(self.message)

        return super().__str__()

    def __init__(self, message):
        if not message:
            super().__init__()
        else:
            super().__init__(message)

        self.message = message
        #super().__init__(self.message)