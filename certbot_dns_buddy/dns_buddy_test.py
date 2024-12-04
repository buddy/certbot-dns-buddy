"""Tests for certbot_dns_buddy.dns_buddy."""

import unittest

import logging
from unittest import mock
import requests_mock

import sys
import io

from certbot.errors import PluginError
try:
    import certbot.compat.os as os
except ImportError:
    import os
from certbot.plugins import dns_test_common
from certbot.plugins.dns_test_common import DOMAIN
from certbot.tests import util as test_util
from certbot_dns_buddy.dns_buddy import _ApiClient

logger = logging.getLogger(__name__)
logger.setLevel(logging.DEBUG)

FAKE_TOKEN = "XXXX"
FAKE_BASE_URL = "https://foo.bar"

class AuthenticatorTest(test_util.TempDirTestCase, dns_test_common.BaseAuthenticatorTest):
    """Class to test the Authenticator."""
    def setUp(self):
        super(AuthenticatorTest, self).setUp()

        self.config = mock.MagicMock()

        os.environ["BUDDY_TOKEN"] = FAKE_TOKEN
        os.environ["BUDDY_BASE_URL"] = FAKE_BASE_URL

        from certbot_dns_buddy.dns_buddy import Authenticator
        self.auth = Authenticator(self.config, "buddy")
        self.mock_client = mock.MagicMock(default_propagation_seconds=15)
        self.auth._api_client = mock.MagicMock(return_value=self.mock_client)

        try:
            from certbot.display.util import notify
            notify_patch = mock.patch('certbot._internal.main.display_util.notify')
            self.mock_notify = notify_patch.start()
            self.addCleanup(notify_patch.stop)
            self.old_stdout = sys.stdout
            sys.stdout = io.StringIO()
        except ImportError:
            self.old_stdout = sys.stdout

    def tearDown(self):
        sys.stdout = self.old_stdout

    def test_perform(self):
        """Tests the perform function to see if client method is called"""
        self.auth.perform([self.achall])
        expected = [
            mock.call.add_txt_record(DOMAIN, "_acme-challenge." + DOMAIN, mock.ANY)
        ]
        self.assertEqual(expected, self.mock_client.mock_calls)

    def test_cleanup(self):
        """Tests cleanup method to see if client method is called"""
        self.auth._attempt_cleanup = True
        self.auth.cleanup([self.achall])
        expected = [
            mock.call.del_txt_record(DOMAIN, "_acme-challenge." + DOMAIN, mock.ANY)
        ]
        self.assertEqual(expected, self.mock_client.mock_calls)