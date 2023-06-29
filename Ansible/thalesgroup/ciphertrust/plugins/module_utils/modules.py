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
"""This module adds shared support for generic Thales CipherTrust modules.

In order to use this module, include it as part of a custom
module as shown below.
  from ansible_collections.thalesgroup.ciphertrust.plugins.module_utils.modules import ThalesCipherTrustModule
  module = ThalesCipherTrustModule(argument_spec=dictionary, supports_check_mode=boolean
                            mutually_exclusive=list1, required_together=list2)

The 'ThalesCipherTrustModule' module provides similar, but more restricted,
interfaces to the normal Ansible module.
"""

import os
import traceback

from ansible.module_utils.basic import AnsibleModule
from ansible.module_utils.basic import env_fallback
from ansible.module_utils.basic import missing_required_lib
from ansible.module_utils.common.dict_transformations import camel_dict_to_snake_dict
from ansible.module_utils._text import to_native

class ThalesCipherTrustModule:
    """An ansible module class for CipherTrust modules
    ThalesCipherTrustModule provides an a class for building modules which
    connect to Thales CipherTrust Manager.  The interface is currently more
    restricted than the basic module class with the aim that later the
    basic module class can be reduced.  If you find that any key
    feature is missing please create an issue on the GitHub repo for this collection.
    """

    default_settings = {
        "default_args": True,
        "auto_retry": True,
        "module_class": AnsibleModule
    }

    def __init__(self, **kwargs):
        local_settings = {}
        for key in ThalesCipherTrustModule.default_settings:
            try:
                local_settings[key] = kwargs.pop(key)
            except KeyError:
                local_settings[key] = ThalesCipherTrustModule.default_settings[key]

        self.settings = local_settings

        if local_settings["default_args"]:
            argument_spec_full = ciphertrust_argument_spec()
            try:
                argument_spec_full.update(kwargs["argument_spec"])
            except (TypeError, NameError):
                pass
            kwargs["argument_spec"] = argument_spec_full

        self._module = ThalesCipherTrustModule.default_settings["module_class"](**kwargs)
        self.check_mode = self._module.check_mode
        self._diff = self._module._diff
        self._name = self._module._name
        
    @property
    def params(self):
        return self._module.params

    def exit_json(self, *args, **kwargs):
        return self._module.exit_json(*args, **kwargs)

    def fail_json(self, *args, **kwargs):
        return self._module.fail_json(*args, **kwargs)

    def debug(self, *args, **kwargs):
        return self._module.debug(*args, **kwargs)

    def warn(self, *args, **kwargs):
        return self._module.warn(*args, **kwargs)

    def deprecate(self, *args, **kwargs):
        return self._module.deprecate(*args, **kwargs)

    def boolean(self, *args, **kwargs):
        return self._module.boolean(*args, **kwargs)

def _ciphertrust_common_argument_spec():
    """
    """
    return dict(
        localNode = dict(
            server_ip=dict(type='str', required=True),
            server_private_ip=dict(type='str', required=True),
            server_port=dict(type='int', required=True),
            user=dict(type='str', required=True),
            password=dict(type='str', required=True),
            verify=dict(type='bool', required=True),
        )
    )

def ciphertrust_argument_spec():
    """
    Returns a dictionary containing the argument_spec common to all CipherTrust Manager modules.
    """
    spec = _ciphertrust_common_argument_spec()
    return spec