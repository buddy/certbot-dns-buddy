import json
import logging
import requests
from certbot import errors
from certbot.plugins import dns_common

try:
    import certbot.compat.os as os
except ImportError:
    import os

logger = logging.getLogger(__name__)


class Authenticator(dns_common.DNSAuthenticator):
    """DNS Authenticator for Buddy

    This plugin enables usage of Buddy rest API to complete ``dns-01`` challenges."""

    description = "Automates dns-01 challenges using Buddy API"

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.token = ""
        self.base_url = ""
        self.workspace = ""
        self.credentials = None

    @classmethod
    def add_parser_arguments(cls, add, **kwargs):
        super(Authenticator, cls).add_parser_arguments(
            add, default_propagation_seconds=120
        )
        add("credentials", help="Buddy credentials INI file")

    def more_info(self):
        return self.description

    def _setup_credentials(self):
        token = os.getenv("BUDDY_TOKEN")
        base_url = os.getenv("BUDDY_BASE_URL")
        workspace = os.getenv("BUDDY_WORKSPACE")
        if token is None:
            self.credentials = self._configure_credentials(
                "credentials",
                "Buddy credentials INI file",
                {
                    "token": "Buddy API token",
                }
            )
            token = self.credentials.conf("token")
            workspace = self.credentials.conf("workspace")
            base_url = self.credentials.conf("base_url")
        if token is None:
            raise errors.PluginError("Buddy API token not defined")
        if workspace is None:
            raise errors.PluginError("Buddy workspace not defined")
        if base_url is None:
            base_url = "https://api.buddy.works"
        self.token = token
        self.base_url = base_url
        self.workspace = workspace

    def _perform(self, domain, validation_name, validation):
        try:
            self._api_client().add_txt_record(validation_name, validation)
        except ValueError as err:
            raise errors.PluginError("Cannot add txt record: {err}".format(err=err))

    def _cleanup(self, domain, validation_name, validation):
        try:
            self._api_client().del_txt_record(validation_name, validation)
        except ValueError as err:
            raise errors.PluginError("Cannot remove txt record: {err}".format(err=err))

    def _api_client(self):
        return _ApiClient(self.base_url, self.token, self.workspace)


class _ApiClient:
    def __init__(self, base_url, token, workspace):
        """Initialize class managing a domain within Buddy API

        :param str base_url: API base URL
        :param str token: API token
        :param str workspace: API workspace domain
        """
        self.base_url = base_url
        self.token = token
        self.workspace = workspace
        self.session = requests.Session()
        self.session.headers.update({
            "Accept": "application/json",
            "Content-Type": "application/json",
            "Authorization": "Bearer {token}".format(token=self.token)
        })

    def _request(self, method, url, payload):
        """Perform a POST request to Buddy API
        :param url: relative URL
        :param payload: request body"""
        url = self.base_url + url
        logger.debug("%s %s", method, url)
        with self.session.request(method, url, json=payload) as res:
            try:
                result = res.json()
            except json.decoder.JSONDecodeError:
                raise errors.PluginError("no JSON in API response")
            if res.status_code == requests.codes.ok:
                return result
            if result["errors"]:
                raise errors.PluginError(result["errors"][0]["message"])
            raise errors.PluginError("something went wrong")

    def _get_record_value(self, name):
        try:
            record = self._request("GET", "/workspaces/%s/domains/%s/records/TXT" % (self.workspace, name), None)
            return record["values"]
        except:
            return []

    def add_txt_record(self, name, value, ttl=60):
        """Add a TXT record to a domain
        :param str name: record key in zone
        :param str value: value of record
        :param int ttl: optional ttl of record"""
        values = self._get_record_value(name)
        values.append(value)
        self._request("PATCH", "/workspaces/%s/domains/%s/records/TXT" % (self.workspace, name), {
            "values": values,
            "ttl": ttl
        })

    def del_txt_record(self, name, value, ttl=60):
        """Delete a TXT record from a domain
        :param str name: record key in zone
        :param str value: value of record
        :param int ttl: optional ttl of record"""
        values = self._get_record_value(name)
        if value in values:
            values.remove(value)
        if len(values) == 0:
            self._request("DELETE", "/workspaces/%s/domains/%s/records/TXT" % (self.workspace, name), None)
        else:
            self._request("PATCH", "/workspaces/%s/domains/%s/records/TXT" % (self.workspace, name), {
                "values": values,
                "ttl": ttl
            })
