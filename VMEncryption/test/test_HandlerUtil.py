#!/usr/bin/env python
#
# *********************************************************
# Copyright (c) Microsoft. All rights reserved.
#
# Apache 2.0 License
#
# You may obtain a copy of the License at
# http:#www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
# implied. See the License for the specific language governing
# permissions and limitations under the License.
#
# *********************************************************

""" Unit tests for the HandlerUtil module """

import unittest
import os
import console_logger
import patch
from Utils import HandlerUtil

class TestHandlerUtil(unittest.TestCase):
    def setUp(self):
        self.logger = console_logger.ConsoleLogger()
        self.distro_patcher = patch.GetDistroPatcher(self.logger)
        self.hutil = HandlerUtil.HandlerUtility(self.logger.log, self.logger.error, "AzureDiskEncryptionForLinux")
        # invoke unit test from within main for setup (to avoid having to change dependencies)
        # then move cwd to parent to emulate calling convention of guest agent 
        if os.getcwd().endswith('main'):
            os.chdir(os.path.dirname(os.getcwd()))
        else:
            self.logger.log(os.getcwd())

    def test_parse_config(self):
        test = '{"runtimeSettings": [{"handlerSettings": {"protectedSettingsCertThumbprint": null, "publicSettings": {"VolumeType": "DATA", "KekVaultResourceId": "/subscriptions/759532d8-9991-4d04-878f-49f0f4804906/resourceGroups/ejrefactorrg/providers/Microsoft.KeyVault/vaults/adekjc7kv", "EncryptionOperation": "EnableEncryption", "KeyEncryptionAlgorithm": "RSA-OAEP", "KeyEncryptionKeyURL": "https://adekjc7kv.vault.azure.net/keys/adekjc7kek/805291e00028474a87e302ce507ed049", "KeyVaultURL": "https://adekjc7kv.vault.azure.net", "KeyVaultResourceId": "/subscriptions/759532d8-9991-4d04-878f-49f0f4804906/resourceGroups/ejrefactorrg/providers/Microsoft.KeyVault/vaults/adekjc7kv", "SequenceVersion": "c8608bb5-df18-43a7-9f0e-dbe09a57fd0b"}, "protectedSettings": null} }]}'
        self.assertIsNotNone(self.hutil._parse_config(test))

    def test_do_parse_context(self):
        self.assertIsNotNone(self.hutil.do_parse_context('Enable'))

    def test_try_parse_context(self):
        self.assertIsNotNone(self.hutil.try_parse_context())

    def test_get_last_nonquery_sequence_number(self):
        self.assertIsNotNone(self.hutil.do_parse_context('Enable'))
        self.assertEqual(self.hutil.get_last_nonquery_sequence_number(), 0)

    def test_is_valid_nonquery(self):
        self.assertTrue(self.hutil.is_valid_nonquery( os.path.realpath(os.path.curdir) + '/config/0.settings'))

    def test_get_last_nonquery_config_path(self):
        self.assertIsNotNone(self.hutil.do_parse_context('Enable'))
        self.assertIsNotNone(self.hutil.get_last_nonquery_config_path())

    def test_get_last_config(self):
        self.assertIsNotNone(self.hutil.do_parse_context('Enable'))
        self.assertIsNotNone(self.hutil.get_last_config(nonquery=False))

    def test_get_last_nonquery_config(self):
        self.assertIsNotNone(self.hutil.do_parse_context('Enable'))
        self.assertIsNotNone(self.hutil.get_last_config(nonquery=True))

    def test_get_handler_env(self):
        self.assertIsNotNone(self.hutil.get_handler_env())

    def test_archive_old_configs(self):
        self.assertIsNotNone(self.hutil.do_parse_context('Enable'))
        self.hutil.archive_old_configs()