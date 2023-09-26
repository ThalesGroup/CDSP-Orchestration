#!/usr/bin/python
# -*- coding: utf-8 -*-
#
# (c) 2023 Thales Group. All rights reserved.
# Author: Anurag Jain, Developer Advocate, Thales
#
# Licensed under the MIT License
#

"""This module adds shared support for generic Thales CT-VL modules.

In order to use this module, include it as part of a custom
module as shown below.
  from ansible_collections.thalesgroup.ctvl.plugins.module_utils.modules import ThalesCTVLModule
  module = ThalesCTVLModule(argument_spec=dictionary, supports_check_mode=boolean
                            mutually_exclusive=list1, required_together=list2)

The 'ThalesCTVLModule' module provides similar, but more restricted,
interfaces to the normal Ansible module.
"""

from ansible.module_utils.basic import AnsibleModule
from ansible.module_utils.basic import env_fallback
from ansible.module_utils.basic import missing_required_lib
from ansible.module_utils.common.dict_transformations import camel_dict_to_snake_dict
from ansible.module_utils._text import to_native

class ThalesCTVLModule:
    """An ansible module class for CT-VL modules
    ThalesCTVLModule provides an a class for building modules which
    connect to Thales CT-VL.  The interface is currently more
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
        for key in ThalesCTVLModule.default_settings:
            try:
                local_settings[key] = kwargs.pop(key)
            except KeyError:
                local_settings[key] = ThalesCTVLModule.default_settings[key]

        self.settings = local_settings

        if local_settings["default_args"]:
            argument_spec_full = ctvl_argument_spec()
            try:
                argument_spec_full.update(kwargs["argument_spec"])
            except (TypeError, NameError):
                pass
            kwargs["argument_spec"] = argument_spec_full

        self._module = ThalesCTVLModule.default_settings["module_class"](**kwargs)
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

def _ctvl_common_argument_spec():
    """
    """
    return dict(
        server = dict(
            url=dict(type='str', required=True),
            username=dict(type='str', required=True),
            password=dict(type='str', required=True),
            verify=dict(type='bool', required=True),
        )
    )

def ctvl_argument_spec():
    """
    Returns a dictionary containing the argument_spec common to all CT-VL modules.
    """
    spec = _ctvl_common_argument_spec()
    return spec