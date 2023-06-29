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
"""This module adds custom exceptions for Thales CipherTrust modules.

In order to use this module, include it as part of a custom
module as shown below.
  from ansible_collections.thalesgroup.ciphertrust.plugins.module_utils.exceptions import CMApiException
"""

from ansible.module_utils._text import to_native

class CMApiException(Exception):

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
        #super().__init__(self.api_error_code + ": " + self.message)

class AnsibleCMException(Exception):

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