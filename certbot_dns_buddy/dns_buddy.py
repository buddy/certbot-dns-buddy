import json
import logging
import idna
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
        if token is None:
            self.credentials = self._configure_credentials(
                "credentials",
                "Buddy credentials INI file",
                {
                    "token": "Buddy API token",
                }
            )
            token = self.credentials.conf("token")
            base_url = self.credentials.conf("base_url")
        if token is None:
            raise errors.PluginError("Buddy API token not defined")
        if base_url is None:
            base_url = "https://api.buddy.works"
        self.token = token
        self.base_url = base_url

    def _perform(self, domain, validation_name, validation):
        decoded_domain = idna.decode(domain)
        try:
            self._api_client().add_txt_record(decoded_domain, validation_name, validation)
        except ValueError as err:
            raise errors.PluginError("Cannot add txt record: {err}".format(err=err))

    def _cleanup(self, domain, validation_name, validation):
        decoded_domain = idna.decode(domain)
        try:
            self._api_client().del_txt_record(decoded_domain, validation_name, validation)
        except ValueError as err:
            raise errors.PluginError("Cannot remove txt record: {err}".format(err=err))

    def _api_client(self):
        return _ApiClient(self.base_url, self.token)


class _ApiClient:
    def __init__(self, base_url, token):
        """Initialize class managing a domain within Buddy API

        :param str base_url: API base URL
        :param str token: API token
        """
        self.base_url = base_url
        self.token = token
        self.session = requests.Session()
        self.session.headers.update({
            "Accept": "application/json",
            "Content-Type": "application/json",
            "Authorization": "Bearer {token}".format(token=self.token)
        })

    def _post_request(self, url, payload):
        """Perform a POST request to Buddy API
        :param url: relative URL
        :param payload: request body"""
        url = self.base_url + url
        logger.debug("POST %s", url)
        with self.session.post(url, data=payload) as res:
            try:
                result = res.json()
            except json.decoder.JSONDecodeError:
                raise errors.PluginError("no JSON in API response")
            if res.status_code == requests.codes.ok:
                return result
            if result["errors"]:
                raise errors.PluginError(result["errors"][0]["message"])
            raise errors.PluginError("something went wrong")

    def add_txt_record(self, domain, name, value, ttl=300):
        """Add a TXT record to a domain
        :param str domain: name of domain to lookup
        :param str name: record key in zone
        :param str value: value of record
        :param int ttl: optional ttl of record"""
        # foo.bar _acme-challenge.foo.bar MIFwJwRzJuLEknEfCY2PQwhzE-yf1WIisPFjCWAlKEs
        logger.debug("add_txt_record %s %s %s", domain, name, value)

    def del_txt_record(self, domain, name, value):
        """Delete a TXT record from a domain
        :param str domain: name of domain to lookup
        :param str name: record key in zone
        :param str value: value of record"""
        logger.debug("del_txt_record %s %s %s", domain, name, value)
